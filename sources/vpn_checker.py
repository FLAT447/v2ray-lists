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
import ipaddress
import re
import os
import time

# -------------------- КОНФИГУРАЦИЯ --------------------
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "FLAT447/v2ray-lists"

# Telegram настройки
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TELEGRAM_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID")

# Настройки пинга
PING_TIMEOUT = 1.5
PING_MAX_WORKERS = 200
ENABLE_PING_CHECK = True

# Настройки загрузки
DEFAULT_MAX_WORKERS = 16
EXTRA_URL_TIMEOUT = 6
EXTRA_URL_MAX_ATTEMPTS = 2

# Номера подписок, которые должны содержать только пингуемые сервера
PING_FILTERED_FILES = {1, 6, 22, 23, 24, 25, 26}

# Шаблон заголовка для каждого файла
HEADER_TEMPLATE = """#announce: 🔰 Нажми на спидометр или молнию, чтобы проверить соединение. Меньше ms - лучше | n/a - не работает. Если ВПН плохо работает, то нажмите на 🔄️.
#profile-web-page-url: https://flat447.github.io/v2ray-lists-site
#profile-title: V2Ray Lists {num}
#support-url: https://t.me/flat447
#profile-update-interval: 1
"""

# Файл статистики
STATS_JSON_PATH = "stats.json"

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
def send_telegram_message(message: str, send_to_channel: bool = True) -> bool:
    """Синхронная отправка сообщения через Telegram Bot API"""
    if not TELEGRAM_BOT_TOKEN:
        log("⚠️ Telegram не настроен: отсутствует TELEGRAM_BOT_TOKEN")
        return False

    success = False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "text": message,
        "disable_web_page_preview": True,
        "parse_mode": "HTML"
    }

    if TELEGRAM_CHAT_ID:
        try:
            payload["chat_id"] = TELEGRAM_CHAT_ID
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                log("📨 Сообщение отправлено в Telegram (чат)")
                success = True
            else:
                log(f"⚠️ Ошибка отправки в чат: {resp.status_code} {resp.text}")
        except Exception as e:
            log(f"⚠️ Исключение при отправке в чат: {e}")

    if send_to_channel and TELEGRAM_CHANNEL_ID:
        try:
            payload["chat_id"] = TELEGRAM_CHANNEL_ID
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                log("📨 Сообщение отправлено в Telegram (канал)")
                success = True
            else:
                log(f"⚠️ Ошибка отправки в канал: {resp.status_code} {resp.text}")
        except Exception as e:
            log(f"⚠️ Исключение при отправке в канал: {e}")

    return success

def send_update_notification():
    """Отправляет уведомление об обновлении подписок с указанием количества конфигов"""
    if not updated_files:
        return

    message_parts = []
    message_parts.append(f"🔄 <b>V2Ray подписки обновлены!</b>")
    message_parts.append(f"📅 Время: {offset}")

    updated_list = sorted(updated_files)
    total_configs = 0
    file_info = []

    for file_num in updated_list:
        local_path = f"githubmirror/{file_num}.txt"
        config_count = 0
        if os.path.exists(local_path):
            with open(local_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        config_count += 1
            total_configs += config_count
            file_info.append((file_num, config_count))
        else:
            file_info.append((file_num, 0))

    message_parts.append(f"📁 Обновлены файлы: {', '.join([f'{num}.txt' for num in updated_list])}")
    message_parts.append(f"📊 Всего конфигураций: {total_configs}")
    message_parts.append("")
    message_parts.append(f"📦 <a href='https://github.com/{REPO_NAME}'>Репозиторий проекта</a>")
    message_parts.append("⚡️ <a href='https://flat447.github.io/v2ray-lists-site'>Сайт проекта</a>")

    full_message = "\n".join(message_parts)

    if len(full_message) > 4096:
        for i in range(0, len(full_message), 4000):
            send_telegram_message(full_message[i:i+4000], True)
    else:
        send_telegram_message(full_message, True)

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
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/wifi", #6
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
    "https://github.com/rtwo2/FastNodes/raw/refs/heads/main/sub/protocols/hysteria2.txt", #18
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/tuic.txt", #19
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt", #20
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt", #21
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri", #22
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt", #23
    "https://github.com/Mr-Meshky/vify/raw/refs/heads/main/configs/vless.txt", #24
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt", #25
]

EXTRA_URLS_FOR_26 = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/30.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/wl.txt",
    "https://ety.twinkvibe.gay/whitelist",
    "https://white-lists.vercel.app/api/filter?code=RU",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/31.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/whitelist_full"
]

SNI_SOURCES = [
    "https://github.com/hxehex/russia-mobile-internet-whitelist/raw/refs/heads/main/whitelist.txt"
]
IP_SOURCES = [
    "https://github.com/hxehex/russia-mobile-internet-whitelist/raw/refs/heads/main/cidrwhitelist.txt"
]

REMOTE_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]
LOCAL_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]
REMOTE_PATHS.append("githubmirror/26.txt")
LOCAL_PATHS.append("githubmirror/26.txt")

# -------------------- НАСТРОЙКИ --------------------
urllib3.disable_warnings()
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/143.0.0.0 Safari/537.36"
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')

def decode_if_base64(data: str) -> str:
    """
    Проверяет, является ли строка целиком закодированной в Base64.
    Если да — декодирует её, иначе возвращает исходные данные.
    """
    stripped = data.strip()
    if '\n' not in stripped and BASE64_PATTERN.match(stripped):
        try:
            missing_padding = len(stripped) % 4
            if missing_padding:
                stripped += '=' * (4 - missing_padding)
            decoded_bytes = base64.b64decode(stripped)
            decoded_str = decoded_bytes.decode('utf-8', errors='replace')
            if any(proto in decoded_str for proto in ('vmess://', 'vless://', 'trojan://', 'ss://', 'tuic://')):
                log(f"🔓 Обнаружена и декодирована Base64 подписка (длина {len(decoded_str)} символов)")
                return decoded_str
        except Exception as e:
            log(f"⚠️ Ошибка при декодировании Base64: {e}")
    return data

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

def clean_existing_headers(content: str) -> str:
    """Удаляет существующие метаданные подписок (строки вида #key: value)"""
    lines = content.splitlines()
    cleaned = []
    metadata_prefixes = (
        "#profile-title:", "#profile-update-interval:", "#profile-web-page-url:",
        "#support-url:", "#announce:", "#update-url:", "#subscribe-url:"
    )
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") and any(stripped.startswith(p) for p in metadata_prefixes):
            continue
        cleaned.append(line)
    return "\n".join(cleaned)

def add_file_header(content: str, file_num: int) -> str:
    """Добавляет заголовочные комментарии в начало файла с подстановкой номера."""
    header = HEADER_TEMPLATE.format(num=file_num)
    return header + "\n" + content

def save_to_local_file(path, content, file_num):
    """Сохраняет контент с добавленным заголовком в локальный файл."""
    content_with_header = add_file_header(content, file_num)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content_with_header)
    log(f"📁 Данные сохранены локально в {path} (добавлен заголовок #{file_num})")

def extract_source_name(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        parts = parsed.path.split('/')
        if len(parts) > 2:
            return f"{parts[1]}/{parts[2]}"
        return parsed.netloc
    except:
        return "Источник"

# -------------------- ПИНГ И ПАРСИНГ --------------------
def extract_server_info(config: str):
    """
    Возвращает кортеж (host, port, user_id).
    Поддерживает VMess, VLESS, Trojan, SS, TUIC, Hysteria/Hysteria2.
    """
    try:
        if config.startswith("vmess://"):
            payload = config[8:]
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded.startswith('{'):
                j = json.loads(decoded)
                host = j.get('add') or j.get('host') or j.get('ip')
                port = j.get('port')
                user_id = j.get('id')
                if host and port:
                    return str(host), int(port), str(user_id) if user_id else None
        else:
            parsed = urllib.parse.urlparse(config)
            host = parsed.hostname
            port = parsed.port
            user_id = parsed.username
            if host and port:
                return str(host), int(port), str(user_id) if user_id else None
    except:
        pass
    return None, None, None

def ping_host(host: str, port: int, timeout: float = PING_TIMEOUT) -> bool:
    if host.lower() in {'127.0.0.1', '0.0.0.0', 'localhost', '::1', ''}:
        return False
    try:
        resolved_ip = socket.gethostbyname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((resolved_ip, port))
        sock.close()
        return result == 0
    except socket.gaierror:
        return False
    except:
        return False

def check_config_availability(config: str) -> bool:
    if not ENABLE_PING_CHECK:
        return True
    host, port, _ = extract_server_info(config)
    if not host or not port:
        return True
    return ping_host(host, port, PING_TIMEOUT)

def filter_by_ping(configs: list, file_num: int) -> list:
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

def remove_duplicates(configs: list) -> list:
    seen_full = set()
    seen_endpoints = set()
    unique = []
    for cfg in configs:
        if cfg in seen_full:
            continue
        host, port, user_id = extract_server_info(cfg)
        if not host or not port:
            seen_full.add(cfg)
            unique.append(cfg)
            continue
        if host.lower() in {'127.0.0.1', '0.0.0.0', 'localhost', '::1'}:
            continue
        endpoint_key = f"{host.lower()}:{port}"
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        seen_full.add(cfg)
        unique.append(cfg)
    return unique

# -------------------- ЗАГРУЗКА И СОХРАНЕНИЕ --------------------
def download_and_save(idx):
    url = URLS[idx]
    local_path = LOCAL_PATHS[idx]
    file_number = idx + 1
    try:
        data = fetch_data(url)
        data = decode_if_base64(data)
        data = clean_existing_headers(data)
        data, _ = filter_insecure_configs(local_path, data, log_enabled=False)
        lines = [l.strip() for l in data.splitlines() if l.strip()]
        lines = remove_duplicates(lines)
        if file_number in PING_FILTERED_FILES:
            lines = filter_by_ping(lines, file_number)
        data = "\n".join(lines)
        content_with_header = add_file_header(data, file_number)
        if os.path.exists(local_path):
            with open(local_path, "r", encoding="utf-8") as f:
                if f.read() == content_with_header:
                    log(f"🔄 Изменений для {local_path} нет (локально). Пропуск загрузки в GitHub.")
                    return None
        save_to_local_file(local_path, data, file_number)
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

# -------------------- 26-Й ФАЙЛ (ПОЛНЫЙ СПИСОК SNI + CIDR - ЗАГРУЗКА ИЗ УДАЛЁННЫХ ИСТОЧНИКОВ) --------------------
def fetch_remote_list(url: str) -> set:
    """
    Загружает список строк из удалённого URL.
    Поддерживает JSON-массив/объект с полем 'domains' и plain text.
    Возвращает множество очищенных строк.
    """
    try:
        resp = fetch_data(url, timeout=EXTRA_URL_TIMEOUT, max_attempts=EXTRA_URL_MAX_ATTEMPTS)
        resp = resp.strip()
        try:
            data = json.loads(resp)
            if isinstance(data, list):
                return {str(item).strip() for item in data if item}
            elif isinstance(data, dict):
                for key in ('domains', 'domain', 'sni', 'hosts', 'ips', 'cidr'):
                    if key in data:
                        return {str(item).strip() for item in data[key] if item}
                return set(str(v).strip() for v in data.values() if v)
        except (json.JSONDecodeError, ValueError):
            pass
        lines = set()
        for line in resp.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                if '#' in line:
                    line = line.split('#', 1)[0].strip()
                if line:
                    lines.add(line)
        return lines
    except Exception as e:
        log(f"⚠️ Не удалось загрузить список из {url}: {e}")
        return set()

def create_filtered_configs():
    """Создаёт 26-й файл с конфигами, разрешёнными по SNI-доменам и IP-подсетям"""
    log("🔄 Загрузка белых списков SNI...")
    sni_set = set()
    for url in SNI_SOURCES:
        sni_set.update(fetch_remote_list(url))
    log(f"📋 Загружено {len(sni_set)} уникальных SNI-доменов")

    log("🔄 Загрузка белых списков IP...")
    ip_networks = []
    for url in IP_SOURCES:
        for entry in fetch_remote_list(url):
            try:
                net = ipaddress.ip_network(entry, strict=False)
                ip_networks.append(net)
            except ValueError:
                log(f"⚠️ Некорректная запись IP-подсети: {entry}")
    log(f"📋 Загружено {len(ip_networks)} IP-подсетей")

    def is_host_allowed(host: str) -> bool:
        if not host:
            return False
        host = host.strip().lower()
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                return False
            for net in ip_networks:
                if ip in net:
                    return True
            return False
        except ValueError:
            pass
        for sni in sni_set:
            sni = sni.lower()
            if host == sni or host.endswith('.' + sni):
                return True
        return False

    def extract_from_file(file_idx):
        path = f"githubmirror/{file_idx}.txt"
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', content)
            configs = []
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                host, _, _ = extract_server_info(stripped)
                if is_host_allowed(host):
                    configs.append(stripped)
            return configs
        except Exception as e:
            log(f"⚠️ Ошибка обработки {path}: {e}")
            return []

    all_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_MAX_WORKERS) as executor:
        futures = [executor.submit(extract_from_file, i) for i in range(1, 26)]
        for future in concurrent.futures.as_completed(futures):
            all_configs.extend(future.result())

    def load_extra(url):
        try:
            data = fetch_data(url, timeout=EXTRA_URL_TIMEOUT, max_attempts=EXTRA_URL_MAX_ATTEMPTS, allow_http_downgrade=False)
            data = clean_existing_headers(data)
            data, _ = filter_insecure_configs("githubmirror/26.txt", data, log_enabled=False)
            data = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', data)
            result = []
            for line in data.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                host, _, _ = extract_server_info(stripped)
                if is_host_allowed(host):
                    result.append(stripped)
            return result
        except Exception as e:
            log(f"⚠️ Ошибка загрузки доп. источника {url}: {e}")
            return []

    extra = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(load_extra, url) for url in EXTRA_URLS_FOR_26]
        for future in concurrent.futures.as_completed(futures):
            extra.extend(future.result())

    all_configs.extend(extra)

    unique = remove_duplicates(all_configs)
    unique = filter_by_ping(unique, 26)

    path = "githubmirror/26.txt"
    content_with_header = add_file_header("\n".join(unique), 26)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content_with_header)
    log(f"📁 Создан файл {path} с {len(unique)} конфигами (добавлен заголовок #26)")
    return path, len(unique)

# -------------------- README --------------------
def update_readme_table():
    try:
        readme = REPO.get_contents("README.md")
        old = readme.decoded_content.decode("utf-8")
        time_part, date_part = offset.split(" | ")
        rows = []
        for i in range(1, 27):
            filename = f"{i}.txt"
            raw_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/githubmirror/{i}.txt"
            if i <= 25:
                source = f"[{extract_source_name(URLS[i-1])}]({URLS[i-1]})"
            else:
                source = f"[Обход SNI/CIDR белых списков]({raw_url})"
            if i in updated_files:
                rows.append(f"| {i} | [`{filename}`]({raw_url}) | {source} | {time_part} | {date_part} |")
            else:
                match = re.search(rf"\|\s*{i}\s*\|.*?\|\s*(.*?)\s*\|\s*(.*?)\s*\|", old)
                if match:
                    rows.append(f"| {i} | [`{filename}`]({raw_url}) | {source} | {match.group(1)} | {match.group(2)} |")
                else:
                    rows.append(f"| {i} | [`{filename}`]({raw_url}) | {source} | Никогда | Никогда |")
        new_table = "| № | Файл | Источник | Время | Дата |\n|--|--|--|--|--|\n" + "\n".join(rows)
        new_content = re.sub(r"\| № \| Файл \| Источник \| Время \| Дата \|[\s\S]*?\|--\|--\|--\|--\|--\|[\s\S]*?(\n\n## |$)", new_table + r"\1", old)
        if new_content != old:
            REPO.update_file("README.md", f"📝 Обновление таблицы в README.md по часовому поясу Европа/Москва: {offset}", new_content, readme.sha)
            log("📝 Таблица в README.md обновлена")
    except Exception as e:
        log(f"⚠️ Ошибка README: {e}")

def update_stats_json(updated_info: dict):
    if not updated_info:
        log("ℹ️ Нет обновлённых файлов для записи в stats.json")
        return
    try:
        try:
            stats_file = REPO.get_contents(STATS_JSON_PATH)
            current_sha = stats_file.sha
            content = stats_file.decoded_content.decode("utf-8")
            stats = json.loads(content)
        except GithubException as e:
            if getattr(e, "status", None) == 404:
                stats = {"last_global_update": "", "files": {}}
                current_sha = None
            else:
                raise
        stats["last_global_update"] = offset
        if "files" not in stats:
            stats["files"] = {}
        for file_num, count in updated_info.items():
            stats["files"][str(file_num)] = {
                "count": count,
                "updated": offset
            }
        new_content = json.dumps(stats, indent=2, ensure_ascii=False)
        if current_sha is None:
            REPO.create_file(
                path=STATS_JSON_PATH,
                message=f"📊 Создание stats.json с данными обновления",
                content=new_content,
            )
            log(f"🆕 Файл {STATS_JSON_PATH} создан в репозитории")
        else:
            if new_content != content:
                REPO.update_file(
                    path=STATS_JSON_PATH,
                    message=f"📊 Обновление статистики по состоянию на {offset}",
                    content=new_content,
                    sha=current_sha,
                )
                log(f"📊 Статистика в {STATS_JSON_PATH} обновлена")
            else:
                log(f"ℹ️ Статистика в {STATS_JSON_PATH} не изменилась")
    except Exception as e:
        log(f"⚠️ Ошибка при обновлении {STATS_JSON_PATH}: {e}")

# -------------------- MAIN --------------------
def main(dry_run: bool = False):
    log("🚀 Начало обновления конфигураций")
    log(f"📅 Время запуска: {offset}")
    log(f"🔍 Проверка пинга: {'включена' if ENABLE_PING_CHECK else 'выключена'}")
    log(f"📁 Файлы с фильтрацией по пингу: {sorted(PING_FILTERED_FILES)}")

    download_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_MAX_WORKERS) as download_pool, \
         concurrent.futures.ThreadPoolExecutor(max_workers=6) as upload_pool:
        futures = [download_pool.submit(download_and_save, i) for i in range(len(URLS))]
        uploads = []
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res and not dry_run:
                download_results.append(res)
                uploads.append(upload_pool.submit(upload_to_github, res[0], res[1]))
        for u in concurrent.futures.as_completed(uploads):
            try:
                u.result()
            except Exception as e:
                log(f"⚠️ Ошибка при загрузке: {e}")

    path_26, count_26 = create_filtered_configs()
    if not dry_run and path_26:
        upload_to_github(path_26, "githubmirror/26.txt")
        download_results.append((path_26, "githubmirror/26.txt", 26, count_26))

    if not dry_run:
        update_readme_table()

    updated_stats_info = {}
    for res in download_results:
        file_num = res[2]
        count = res[3]
        updated_stats_info[file_num] = count
    if not dry_run and updated_stats_info:
        update_stats_json(updated_stats_info)

    if updated_files and not dry_run:
        send_update_notification()

    for k in sorted(LOGS_BY_FILE.keys()):
        if k == 0:
            print("\n----- Общие сообщения -----")
        else:
            print(f"\n----- {k}.txt -----")
        for msg in LOGS_BY_FILE[k]:
            print(msg)

    log("✅ Обновление завершено")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    main(dry_run=args.dry_run)
