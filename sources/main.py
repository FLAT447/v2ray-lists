from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
from github import GithubException
from github import Github, Auth
from datetime import datetime
import concurrent.futures
import urllib.parse
import threading
import socket
import zoneinfo
import requests
import urllib3
import base64
import html
import json
import re
import os
import time

# -------------------- КОНФИГУРАЦИЯ --------------------
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "FLAT447/v2ray-lists"

# Telegram настройки
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# Настройки пинга
PING_TIMEOUT = 2.0
PING_MAX_WORKERS = 50
ENABLE_PING_CHECK = True

# Настройки загрузки
DEFAULT_MAX_WORKERS = 16
EXTRA_URL_TIMEOUT = 6
EXTRA_URL_MAX_ATTEMPTS = 2

# Номера подписок, которые должны содержать только пингуемые сервера
PING_FILTERED_FILES = {1, 6, 22, 23, 24, 25, 26}

# Файлы для отправки лучших ключей
TOP_FILES = {1, 6, 23, 24, 25, 26}
TOP_COUNTS = {1: 3, 6: 3, 23: 3, 24: 3, 25: 3, 26: 5}

# -------------------- ЛОГИРОВАНИЕ --------------------
LOGS_BY_FILE: dict[int, list[str]] = defaultdict(list)
_LOG_LOCK = threading.Lock()
_UPDATED_FILES_LOCK = threading.Lock()
_GITHUBMIRROR_INDEX_RE = re.compile(r"githubmirror/(\d+)\.txt")
updated_files = set()

def _extract_index(msg: str) -> int:
    m = _GITHUBMIRROR_INDEX_RE.search(msg)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return 0

def log(message: str):
    idx = _extract_index(message)
    with _LOG_LOCK:
        LOGS_BY_FILE[idx].append(message)
    print(message)

zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

# -------------------- TELEGRAM --------------------
def send_telegram_message(message: str):
    """Отправляет сообщение в Telegram"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log("⚠️ Telegram не настроен: отсутствуют TELEGRAM_BOT_TOKEN или TELEGRAM_CHAT_ID")
        return False
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            log("📨 Сообщение отправлено в Telegram")
            return True
        else:
            log(f"⚠️ Ошибка отправки в Telegram: {response.status_code}")
            return False
    except Exception as e:
        log(f"⚠️ Ошибка отправки в Telegram: {e}")
        return False

def get_best_configs(file_path: str, count: int) -> list:
    """Возвращает N лучших конфигов из файла (с наименьшим пингом)"""
    if not os.path.exists(file_path):
        return []
    
    with open(file_path, "r", encoding="utf-8") as f:
        configs = [line.strip() for line in f.readlines() if line.strip()]
    
    if not configs:
        return []
    
    # Тестируем пинг для каждого конфига
    results = []
    
    def test_one(cfg):
        host_port = extract_host_and_port(cfg)
        if not host_port:
            return (cfg, float('inf'))
        host, port = host_port
        start_time = time.time()
        is_alive = ping_host(host, port, PING_TIMEOUT)
        ping_time = (time.time() - start_time) * 1000 if is_alive else float('inf')
        return (cfg, ping_time)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(test_one, cfg) for cfg in configs[:100]]  # Ограничиваем для скорости
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result[1] != float('inf'):
                results.append(result)
    
    # Сортируем по пингу и берем лучшие
    results.sort(key=lambda x: x[1])
    return [cfg for cfg, _ in results[:count]]

def format_config_for_telegram(config: str, index: int, ping_ms: float = None) -> str:
    """Форматирует конфиг для отправки в Telegram"""
    # Сокращаем длинные ссылки
    if len(config) > 100:
        # Для vmess/vless/trojan показываем только начало
        if config.startswith(("vmess://", "vless://", "trojan://")):
            prefix = config.split("://")[0]
            config_short = f"{prefix}://...{config[-50:]}"
        else:
            config_short = config[:100] + "..."
    else:
        config_short = config
    
    # Пытаемся извлечь хост и порт
    host_port = extract_host_and_port(config)
    location = ""
    if host_port:
        host, port = host_port
        location = f"📍 {host}:{port}"
    
    ping_text = f" | 🏓 {ping_ms:.0f}ms" if ping_ms else ""
    
    return f"<b>{index}</b>. <code>{config_short}</code>\n{location}{ping_text}"

# -------------------- GITHUB --------------------
if not GITHUB_TOKEN:
    log("❌ Ошибка: GitHub токен не найден!")
    exit(1)

try:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
    REPO = g.get_repo(REPO_NAME)
    log(f"✅ Подключение к GitHub: {REPO_NAME}")
except Exception as e:
    log(f"❌ Ошибка подключения: {e}")
    exit(1)

try:
    remaining, limit = g.rate_limiting
    log(f"ℹ️ GitHub API: {remaining}/{limit} запросов")
except Exception:
    pass

if not os.path.exists("githubmirror"):
    os.mkdir("githubmirror")

# -------------------- ИСТОЧНИКИ --------------------
URLS = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt", #1
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt", #2
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt", #3
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt", #4
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt", #5
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/hk/vless.txt", #6
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt", #7
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt", #8
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt", #9
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless", #10
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt", #11
    "https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt", #12
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt", #13
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes", #14
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/mixed_iran.txt", #15
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub", #16
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt", #17
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt", #18
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix", #19
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt", #20
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt", #21
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri", #22
    "https://raw.githubusercontent.com/WhitePrime/xraycheck/refs/heads/main/configs/ru", #23
    "https://github.com/Mr-Meshky/vify/raw/refs/heads/main/configs/vless.txt", #24
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt", #25
]

EXTRA_URLS_FOR_26 = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://whiteprime.github.io/xraycheck/configs/white-list_available",
    "https://wlrus.lol/confs/selected.txt",
    "https://ety.twinkvibe.gay/whitelist",
    "https://whiteprime.github.io/xraycheck/configs/white-list_available_st(top100)"
]

REMOTE_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]
LOCAL_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]
REMOTE_PATHS.append("githubmirror/26.txt")
LOCAL_PATHS.append("githubmirror/26.txt")

# -------------------- НАСТРОЙКИ --------------------
urllib3.disable_warnings()
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/143.0.0.0 Safari/537.36"

def _build_session(max_pool_size: int) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=max_pool_size, pool_maxsize=max_pool_size,
                          max_retries=Retry(total=1, backoff_factor=0.2,
                          status_forcelist=(429,500,502,503,504),
                          allowed_methods=("HEAD","GET","OPTIONS")))
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": CHROME_UA})
    return session

REQUESTS_SESSION = _build_session(DEFAULT_MAX_WORKERS)

def fetch_data(url: str, timeout: int = 10, max_attempts: int = 3, session=None, allow_http_downgrade=True) -> str:
    sess = session or REQUESTS_SESSION
    for attempt in range(1, max_attempts + 1):
        try:
            modified_url = url
            verify = True
            if attempt == 2:
                verify = False
            elif attempt == 3:
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme == "https" and allow_http_downgrade:
                    modified_url = parsed._replace(scheme="http").geturl()
                verify = False
            response = sess.get(modified_url, timeout=timeout, verify=verify)
            response.raise_for_status()
            return response.text
        except Exception as exc:
            if attempt < max_attempts:
                continue
            raise exc

def save_to_local_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    log(f"📁 Данные сохранены локально в {path}")

def extract_source_name(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        parts = parsed.path.split('/')
        if len(parts) > 2:
            return f"{parts[1]}/{parts[2]}"
        return parsed.netloc
    except:
        return "Источник"

# -------------------- ПИНГ --------------------
def extract_host_and_port(config: str):
    try:
        if config.startswith("vmess://"):
            try:
                payload = config[8:]
                rem = len(payload) % 4
                if rem:
                    payload += '=' * (4 - rem)
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                if decoded.startswith('{'):
                    j = json.loads(decoded)
                    host = j.get('add') or j.get('host') or j.get('ip')
                    port = j.get('port')
                    if host and port:
                        return host, int(port)
            except:
                pass
        elif config.startswith(("vless://", "trojan://")):
            match = re.search(r'@([\w\.-]+):(\d+)', config)
            if match:
                return match.group(1), int(match.group(2))
        elif config.startswith("ss://"):
            match = re.search(r'@([\w\.-]+):(\d+)', config)
            if match:
                return match.group(1), int(match.group(2))
        else:
            match = re.search(r'(?:@|//)([\w\.-]+):(\d{1,5})', config)
            if match:
                return match.group(1), int(match.group(2))
    except:
        pass
    return None

def ping_host(host: str, port: int, timeout: float = PING_TIMEOUT) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def check_config_availability(config: str) -> bool:
    if not ENABLE_PING_CHECK:
        return True
    host_port = extract_host_and_port(config)
    if not host_port:
        return True
    host, port = host_port
    return ping_host(host, port, PING_TIMEOUT)

def filter_by_ping(configs: list, file_num: int) -> list:
    """Фильтрует список конфигов по пингу"""
    if not ENABLE_PING_CHECK:
        return configs
    
    log(f"🔍 Проверка пинга для {len(configs)} конфигов (файл {file_num})...")
    working = []
    
    def check_one(cfg):
        return cfg if check_config_availability(cfg) else None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=PING_MAX_WORKERS) as executor:
        futures = [executor.submit(check_one, cfg) for cfg in configs]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                working.append(result)
    
    log(f"📊 Файл {file_num}: {len(working)}/{len(configs)} рабочих серверов")
    return working

# -------------------- ФИЛЬТРАЦИЯ INSECURE --------------------
INSECURE_PATTERN = re.compile(
    r'(?:[?&;]|3%[Bb])(allowinsecure|allow_insecure|insecure)=(?:1|true|yes)(?:[&;#]|$|(?=\s|$))',
    re.IGNORECASE
)

def filter_insecure_configs(local_path, data, log_enabled=True):
    result = []
    splitted = data.splitlines()

    for line in splitted:
        original_line = line
        processed = line.strip()
        processed = urllib.parse.unquote(html.unescape(processed))

        if INSECURE_PATTERN.search(processed):
            continue

        result.append(original_line)

    filtered_count = len(splitted) - len(result)
    
    if filtered_count > 0 and log_enabled:
        log(f"ℹ️ Отфильтровано {filtered_count} небезопасных конфигов для {local_path}")
    
    return "\n".join(result), filtered_count

# -------------------- ЗАГРУЗКА И СОХРАНЕНИЕ --------------------
def download_and_save(idx):
    url = URLS[idx]
    local_path = LOCAL_PATHS[idx]
    file_number = idx + 1
    
    try:
        data = fetch_data(url)
        data, _ = filter_insecure_configs(local_path, data, log_enabled=False)
        
        lines = [l.strip() for l in data.splitlines() if l.strip()]
        
        # Фильтруем по пингу только нужные файлы
        if file_number in PING_FILTERED_FILES:
            lines = filter_by_ping(lines, file_number)
        
        data = "\n".join(lines)
        
        if os.path.exists(local_path):
            with open(local_path, "r", encoding="utf-8") as f:
                if f.read() == data:
                    log(f"🔄 Изменений для {local_path} нет (локально). Пропуск загрузки в GitHub.")
                    return None
        
        save_to_local_file(local_path, data)
        return local_path, REMOTE_PATHS[idx], file_number, len(lines)
    except Exception as e:
        log(f"⚠️ Ошибка при скачивании {url}: {str(e)[:100]}")
        return None

def upload_to_github(local_path, remote_path):
    if not os.path.exists(local_path):
        log(f"❌ Файл {local_path} не найден.")
        return

    with open(local_path, "r", encoding="utf-8") as f:
        content = f.read()

    max_retries = 5

    for attempt in range(1, max_retries + 1):
        try:
            try:
                file_in_repo = REPO.get_contents(remote_path)
                current_sha = file_in_repo.sha
                
                # Безопасное получение содержимого
                try:
                    remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                except (AssertionError, AttributeError):
                    if hasattr(file_in_repo, 'content') and file_in_repo.content:
                        remote_content = base64.b64decode(file_in_repo.content).decode("utf-8", errors="replace")
                    else:
                        remote_content = None
                
                if remote_content == content:
                    log(f"🔄 Изменений для {remote_path} нет.")
                    return
                    
            except GithubException as e_get:
                if getattr(e_get, "status", None) == 404:
                    basename = os.path.basename(remote_path)
                    REPO.create_file(
                        path=remote_path,
                        message=f"🆕 Первый коммит {basename} по часовому поясу Европа/Москва: {offset}",
                        content=content,
                    )
                    log(f"🆕 Файл {remote_path} создан.")
                    file_index = int(remote_path.split('/')[1].split('.')[0])
                    with _UPDATED_FILES_LOCK:
                        updated_files.add(file_index)
                    return
                else:
                    log(f"⚠️ Ошибка при получении {remote_path}: {e_get.data.get('message', str(e_get))}")
                    return

            basename = os.path.basename(remote_path)
            REPO.update_file(
                path=remote_path,
                message=f"🚀 Обновление {basename} по часовому поясу Европа/Москва: {offset}",
                content=content,
                sha=current_sha,
            )
            log(f"🚀 Файл {remote_path} обновлён в репозитории.")
            file_index = int(remote_path.split('/')[1].split('.')[0])
            with _UPDATED_FILES_LOCK:
                updated_files.add(file_index)
            return
            
        except GithubException as e_upd:
            if getattr(e_upd, "status", None) == 409 and attempt < max_retries:
                wait_time = 0.5 * (2 ** (attempt - 1))
                log(f"⚠️ Конфликт SHA для {remote_path}, попытка {attempt}/{max_retries}, ждем {wait_time} сек")
                time.sleep(wait_time)
                continue
            else:
                log(f"❌ Не удалось обновить {remote_path}: {e_upd.data.get('message', str(e_upd))}")
                return

    log(f"❌ Не удалось обновить {remote_path} после {max_retries} попыток")

# -------------------- 26-Й ФАЙЛ (ПОЛНЫЙ СПИСОК SNI) --------------------
SNI_DOMAINS = [
    "00.img.avito.st", "01.img.avito.st", "02.img.avito.st", "03.img.avito.st",
    "04.img.avito.st", "05.img.avito.st", "06.img.avito.st", "07.img.avito.st",
    "08.img.avito.st", "09.img.avito.st", "10.img.avito.st", "1013a--ma--8935--cp199.stbid.ru",
    "11.img.avito.st", "12.img.avito.st", "13.img.avito.st", "14.img.avito.st",
    "15.img.avito.st", "16.img.avito.st", "17.img.avito.st", "18.img.avito.st",
    "19.img.avito.st", "1l-api.mail.ru", "1l-go.mail.ru", "1l-hit.mail.ru", "1l-s2s.mail.ru",
    "1l-view.mail.ru", "1l.mail.ru", "1link.mail.ru", "20.img.avito.st", "2018.mail.ru",
    "2019.mail.ru", "2020.mail.ru", "2021.mail.ru", "21.img.avito.st", "22.img.avito.st",
    "23.img.avito.st", "23feb.mail.ru", "24.img.avito.st", "25.img.avito.st",
    "26.img.avito.st", "27.img.avito.st", "28.img.avito.st", "29.img.avito.st", "2gis.com",
    "2gis.ru", "30.img.avito.st", "300.ya.ru", "31.img.avito.st", "32.img.avito.st",
    "33.img.avito.st", "34.img.avito.st", "3475482542.mc.yandex.ru", "35.img.avito.st",
    "36.img.avito.st", "37.img.avito.st", "38.img.avito.st", "39.img.avito.st",
   
