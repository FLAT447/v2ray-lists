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
# GitHub настройки
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "FLAT447/v2ray-lists"

# Настройки пинга
PING_TIMEOUT = 2.0
PING_MAX_WORKERS = 50
ENABLE_PING_CHECK = True

# Настройки загрузки
DEFAULT_MAX_WORKERS = 16
EXTRA_URL_TIMEOUT = 6
EXTRA_URL_MAX_ATTEMPTS = 2

# Номера подписок, которые должны содержать только пингуемые сервера
PING_FILTERED_FILES = {1, 6, 22, 23, 24, 25}

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

# Получение текущего времени
zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

# -------------------- GITHUB ИНИЦИАЛИЗАЦИЯ --------------------
if not GITHUB_TOKEN:
    log("❌ Ошибка: GitHub токен не найден!")
    log("Установите переменную окружения GITHUB_TOKEN")
    exit(1)

try:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
    REPO = g.get_repo(REPO_NAME)
    log(f"✅ Подключение к GitHub: {REPO_NAME}")
except Exception as e:
    log(f"❌ Ошибка подключения к GitHub: {e}")
    exit(1)

# Проверка лимитов GitHub API
try:
    remaining, limit = g.rate_limiting
    if remaining < 100:
        log(f"⚠️ Внимание: осталось {remaining}/{limit} запросов к GitHub API")
    else:
        log(f"ℹ️ Доступно запросов к GitHub API: {remaining}/{limit}")
except Exception as e:
    log(f"⚠️ Не удалось проверить лимиты GitHub API: {e}")

# Создание директории
if not os.path.exists("githubmirror"):
    os.mkdir("githubmirror")
    log("📁 Создана директория githubmirror")

# -------------------- ИСТОЧНИКИ --------------------
URLS = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt", #1
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt", #2
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt", #3
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt", #4
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt", #5
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/vless.txt", #6
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
    "https://raw.githubusercontent.com/WhitePrime/xraycheck/refs/heads/main/configs/available", #23
    "https://github.com/Mr-Meshky/vify/raw/refs/heads/main/configs/vless.txt", #24
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt", #25
]

# Источники для 26-го файла
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

# Добавляем 26-й файл
REMOTE_PATHS.append("githubmirror/26.txt")
LOCAL_PATHS.append("githubmirror/26.txt")

# -------------------- НАСТРОЙКИ ЗАГРУЗКИ --------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/143.0.0.0 Safari/537.36"
)

def _build_session(max_pool_size: int) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=max_pool_size,
        pool_maxsize=max_pool_size,
        max_retries=Retry(
            total=1,
            backoff_factor=0.2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("HEAD", "GET", "OPTIONS"),
        ),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": CHROME_UA})
    return session

REQUESTS_SESSION = _build_session(max_pool_size=DEFAULT_MAX_WORKERS)

def fetch_data(url: str, timeout: int = 10, max_attempts: int = 3, session: requests.Session | None = None, allow_http_downgrade: bool = True) -> str:
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

        except requests.exceptions.RequestException as exc:
            if attempt < max_attempts:
                continue
            raise exc

def save_to_local_file(path, content):
    with open(path, "w", encoding="utf-8") as file:
        file.write(content)
    log(f"📁 Данные сохранены локально в {path}")

def extract_source_name(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        path_parts = parsed.path.split('/')
        if len(path_parts) > 2:
            return f"{path_parts[1]}/{path_parts[2]}"
        return parsed.netloc
    except:
        return "Источник"

# -------------------- ФУНКЦИИ ПИНГА --------------------
def extract_host_and_port(config: str):
    """Извлекает хост и порт из конфига"""
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
        elif config.startswith(("vless://", "trojan://", "ss://")):
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
    """Проверяет доступность хоста через TCP соединение"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def check_config_availability(config: str) -> bool:
    """Проверяет доступность сервера из конфига"""
    if not ENABLE_PING_CHECK:
        return True
    
    host_port = extract_host_and_port(config)
    if not host_port:
        return True
    
    host, port = host_port
    return ping_host(host, port, PING_TIMEOUT)

# -------------------- ФИЛЬТРАЦИЯ --------------------
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

# -------------------- ОСНОВНЫЕ ФУНКЦИИ --------------------
def download_and_save(idx):
    """Скачивает и сохраняет файл с возможной фильтрацией по пингу"""
    url = URLS[idx]
    local_path = LOCAL_PATHS[idx]
    file_number = idx + 1
    
    try:
        data = fetch_data(url)
        data, _ = filter_insecure_configs(local_path, data, log_enabled=False)
        
        # Если этот файл должен содержать только пингуемые сервера
        if file_number in PING_FILTERED_FILES and ENABLE_PING_CHECK:
            log(f"🔍 Проверка пинга для файла {file_number}.txt...")
            
            lines = data.splitlines()
            working_configs = []
            
            def check_line(line):
                line = line.strip()
                if not line:
                    return None
                if check_config_availability(line):
                    return line
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=PING_MAX_WORKERS) as executor:
                futures = [executor.submit(check_line, line) for line in lines]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        working_configs.append(result)
            
            data = "\n".join(working_configs)
            log(f"📊 Файл {file_number}.txt: {len(working_configs)}/{len(lines)} рабочих серверов")
        
        if os.path.exists(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as f_old:
                    old_data = f_old.read()
                if old_data == data:
                    log(f"🔄 Изменений для {local_path} нет (локально).")
                    return None
            except Exception:
                pass
        
        save_to_local_file(local_path, data)
        return local_path, REMOTE_PATHS[idx]
        
    except Exception as e:
        log(f"⚠️ Ошибка при скачивании {url}: {str(e)[:200]}")
        return None

def upload_to_github(local_path, remote_path):
    if not os.path.exists(local_path):
        log(f"❌ Файл {local_path} не найден.")
        return

    with open(local_path, "r", encoding="utf-8") as file:
        content = file.read()

    max_retries = 5

    for attempt in range(1, max_retries + 1):
        try:
            try:
                file_in_repo = REPO.get_contents(remote_path)
                current_sha = file_in_repo.sha
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

            try:
                remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                if remote_content == content:
                    log(f"🔄 Изменений для {remote_path} нет.")
                    return
            except Exception:
                pass

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

def create_filtered_configs():
    """Создает 26-й файл с конфигами для SNI/CIDR белых списков"""
    sni_domains = [
        "00.img.avito.st", "01.img.avito.st", "02.img.avito.st", "03.img.avito.st",
        "04.img.avito.st", "05.img.avito.st", "06.img.avito.st", "07.img.avito.st",
        "08.img.avito.st", "09.img.avito.st", "10.img.avito.st"
    ]  # Сократил для примера, полный список будет длинным
    
    # Оптимизация списка доменов
    sorted_domains = sorted(sni_domains, key=len)
    optimized_domains = []
    for d in sorted_domains:
        is_redundant = False
        for existing in optimized_domains:
            if existing in d:
                is_redundant = True
                break
        if not is_redundant:
            optimized_domains.append(d)

    try:
        pattern_str = r"(?:" + "|".join(re.escape(d) for d in optimized_domains) + r")"
        sni_regex = re.compile(pattern_str)
    except Exception as e:
        log(f"❌ Ошибка компиляции Regex: {e}")
        return None

    def _process_file_filtering(file_idx):
        local_path = f"githubmirror/{file_idx}.txt"
        filtered_lines = []
        if not os.path.exists(local_path):
            return filtered_lines
        try:
            with open(local_path, "r", encoding="utf-8") as file:
                content = file.read()
            content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', content)
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if sni_regex.search(line):
                    filtered_lines.append(line)
        except Exception:
            pass
        return filtered_lines

    all_configs = []

    # Обработка файлов 1-25
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(_process_file_filtering, i) for i in range(1, 26)]
        for future in concurrent.futures.as_completed(futures):
            all_configs.extend(future.result())

    # Загрузка доп. источников
    def _load_extra_configs(url):
        configs = []
        try:
            data = fetch_data(url, timeout=EXTRA_URL_TIMEOUT, max_attempts=EXTRA_URL_MAX_ATTEMPTS, allow_http_downgrade=False)
            data, _ = filter_insecure_configs("githubmirror/26.txt", data, log_enabled=False)
            data = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', data)
            lines = data.splitlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    configs.append(line)
        except Exception as e:
            log(f"⚠️ Ошибка при загрузке {url}: {str(e)[:100]}")
        return configs
    
    extra_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(_load_extra_configs, url) for url in EXTRA_URLS_FOR_26]
        for future in concurrent.futures.as_completed(futures):
            extra_configs.extend(future.result())
    
    all_configs.extend(extra_configs)

    # Дедупликация
    seen_full = set()
    seen_hostport = set()
    unique_configs = []

    for cfg in all_configs:
        c = cfg.strip()
        if not c or c in seen_full:
            continue
        seen_full.add(c)
        hostport = extract_host_and_port(c)
        if hostport:
            key = f"{hostport[0].lower()}:{hostport[1]}"
            if key in seen_hostport:
                continue
            seen_hostport.add(key)
        unique_configs.append(c)

    local_path_26 = "githubmirror/26.txt"
    try:
        with open(local_path_26, "w", encoding="utf-8") as file:
            file.write("\n".join(unique_configs))
        log(f"📁 Создан файл {local_path_26} с {len(unique_configs)} конфигами")
    except Exception as e:
        log(f"⚠️ Ошибка при сохранении {local_path_26}: {e}")

    return local_path_26

def update_readme_table():
    """Обновляет таблицы в README.md"""
    try:
        try:
            readme_file = REPO.get_contents("README.md")
            old_content = readme_file.decoded_content.decode("utf-8")
        except GithubException as e:
            if e.status == 404:
                log("❌ README.md не найден в репозитории")
                return
            else:
                log(f"⚠️ Ошибка при получении README.md: {e}")
                return

        time_part, date_part = offset.split(" | ")
        
        table_header = "| № | Файл | Источник | Время | Дата |\n|--|--|--|--|--|"
        table_rows = []
        
        for i, (remote_path, url) in enumerate(zip(REMOTE_PATHS, URLS + [""]), 1):
            filename = f"{i}.txt"
            raw_file_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/githubmirror/{i}.txt"
            
            if i <= 25:
                source_name = extract_source_name(url)
                source_column = f"[{source_name}]({url})"
            else:
                source_name = "Обход SNI/CIDR белых списков"
                source_column = f"[{source_name}]({raw_file_url})"
            
            if i in updated_files:
                update_time = time_part
                update_date = date_part
            else:
                pattern = rf"\|\s*{i}\s*\|\s*\[`{filename}`\].*?\|.*?\|\s*(.*?)\s*\|\s*(.*?)\s*\|"
                match = re.search(pattern, old_content)
                if match:
                    update_time = match.group(1).strip() if match.group(1).strip() else "Никогда"
                    update_date = match.group(2).strip() if match.group(2).strip() else "Никогда"
                else:
                    update_time = "Никогда"
                    update_date = "Никогда"
            
            table_rows.append(f"| {i} | [`{filename}`]({raw_file_url}) | {source_column} | {update_time} | {update_date} |")

        new_table = table_header + "\n" + "\n".join(table_rows)

        table_pattern = r"\| № \| Файл \| Источник \| Время \| Дата \|[\s\S]*?\|--\|--\|--\|--\|--\|[\s\S]*?(\n\n## |$)"
        new_content = re.sub(table_pattern, new_table + r"\1", old_content)

        if new_content != old_content:
            REPO.update_file(
                path="README.md",
                message=f"📝 Обновление таблицы в README.md: {offset}",
                content=new_content,
                sha=readme_file.sha
            )
            log("📝 Таблица в README.md обновлена")
        else:
            log("📝 Таблица в README.md не требует изменений")

    except Exception as e:
        log(f"⚠️ Ошибка при обновлении README.md: {e}")

# -------------------- MAIN --------------------
def main(dry_run: bool = False):
    log("🚀 Начало обновления конфигураций")
    log(f"📅 Время запуска: {offset}")
    log(f"🔍 Проверка пинга: {'включена' if ENABLE_PING_CHECK else 'выключена'}")
    log(f"📁 Файлы с фильтрацией по пингу: {sorted(PING_FILTERED_FILES)}")
    
    max_workers_download = min(DEFAULT_MAX_WORKERS, max(1, len(URLS)))
    max_workers_upload = max(2, min(6, len(URLS)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_download) as download_pool, \
         concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_upload) as upload_pool:

        download_futures = [download_pool.submit(download_and_save, i) for i in range(len(URLS))]
        upload_futures: list[concurrent.futures.Future] = []

        for future in concurrent.futures.as_completed(download_futures):
            result = future.result()
            if result:
                local_path, remote_path = result
                if dry_run:
                    log(f"ℹ️ Dry-run: пропускаем загрузку {remote_path}")
                else:
                    upload_futures.append(upload_pool.submit(upload_to_github, local_path, remote_path))

        for uf in concurrent.futures.as_completed(upload_futures):
            _ = uf.result()

    # Создаем 26-й файл
    local_path_26 = create_filtered_configs()
    
    # Загружаем 26-й файл
    if not dry_run and local_path_26:
        upload_to_github(local_path_26, "githubmirror/26.txt")

    # Обновляем README
    if not dry_run:
        update_readme_table()

    # Вывод логов
    ordered_keys = sorted(k for k in LOGS_BY_FILE.keys() if k != 0)
    output_lines: list[str] = []

    for k in ordered_keys:
        output_lines.append(f"----- {k}.txt -----")
        output_lines.extend(LOGS_BY_FILE[k])

    if LOGS_BY_FILE.get(0):
        output_lines.append("----- Общие сообщения -----")
        output_lines.extend(LOGS_BY_FILE[0])

    print("\n" + "="*50)
    print("\n".join(output_lines))
    print("="*50)
    log("✅ Обновление завершено")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Скачивание конфигов и загрузка в GitHub")
    parser.add_argument("--dry-run", action="store_true", help="Только скачивать и сохранять локально")
    args = parser.parse_args()
    main(dry_run=args.dry_run)
