from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
from github import GithubException, Github, Auth, InputGitTreeElement
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
import hashlib
import zipfile
import csv
import ipaddress

# -------------------- КОНФИГУРАЦИЯ --------------------
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "FLAT447/v2ray-lists"

# Telegram настройки
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TELEGRAM_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID")

# Настройки пинга
PING_TIMEOUT = 2.0          # было 1.5 → как в старом main.py
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
downloaded_configs: dict[int, list[str]] = {}
downloaded_configs_lock = threading.Lock()

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
    if not updated_files:
        return

    message_parts = []
    message_parts.append(f"🔄 <b>V2Ray подписки обновлены!</b>")
    message_parts.append(f"📅 Время: {offset}")

    updated_list = sorted(updated_files)
    total_configs = 0
    file_info = []

    for file_num in updated_list:
        with downloaded_configs_lock:
            configs = downloaded_configs.get(file_num, [])
        count = len(configs)
        total_configs += count
        file_info.append((file_num, count))

    message_parts.append(f"📁 Обновлены файлы: {', '.join([f'{num}.txt' for num in updated_list])}")
    message_parts.append(f"📊 Всего конфигураций: {total_configs}")
    message_parts.append("")

    message_parts.append("🔗 <b>Ссылки для импорта в клиент (RAW):</b>")
    for file_num, count in file_info:
        raw_url = f"https://raw.githubusercontent.com/{REPO_NAME}/refs/heads/main/githubmirror/{file_num}.txt"
        message_parts.append(f"• <a href='{raw_url}'>{file_num}.txt</a> ({count} конфиг.)")
        message_parts.append(f"  <code>{raw_url}</code>")

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
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/wifi",
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",  # <- 10-й файл
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
    "https://github.com/rtwo2/FastNodes/raw/refs/heads/main/sub/protocols/hysteria2.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/tuic.txt",
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://github.com/Mr-Meshky/vify/raw/refs/heads/main/configs/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
]

EXTRA_URLS_FOR_26 = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/30.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
    "https://ety.twinkvibe.gay/whitelist",
    "https://white-lists.vercel.app/api/filter?code=RU",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/31.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/whitelist_full"
]

# -------------------- НАСТРОЙКИ СЕТИ --------------------
urllib3.disable_warnings()
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/143.0.0.0 Safari/537.36"
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')

def decode_if_base64(data: str) -> str:
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
    header = HEADER_TEMPLATE.format(num=file_num)
    return header + "\n" + content

def save_to_local_file(path, content, file_num):
    content_with_header = add_file_header(content, file_num)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content_with_header)
    log(f"📁 Данные сохранены локально в {path} (добавлен заголовок #{file_num})")

# -------------------- ПИНГ (с кэшированием) --------------------
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

_ping_cache: dict[tuple[str, int], bool] = {}
_ping_cache_lock = threading.Lock()

def ping_host(host: str, port: int, timeout: float = PING_TIMEOUT) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def ping_host_cached(host: str, port: int, timeout: float = PING_TIMEOUT) -> bool:
    key = (host, port)
    with _ping_cache_lock:
        if key in _ping_cache:
            return _ping_cache[key]
    result = ping_host(host, port, timeout)
    with _ping_cache_lock:
        _ping_cache[key] = result
    return result

def check_config_availability(config: str) -> bool:
    if not ENABLE_PING_CHECK:
        return True
    hp = extract_host_and_port(config)
    if not hp:
        return True
    return ping_host_cached(hp[0], hp[1], PING_TIMEOUT)

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

# -------------------- ФИЛЬТРАЦИЯ INSECURE --------------------
INSECURE_PATTERN = re.compile(
    r'(?:[?&;]|3%[Bb])(allowinsecure|allow_insecure|insecure)=(?:1|true|yes)(?:[&;#]|$|(?=\s|$))',
    re.IGNORECASE
)

def filter_insecure_configs(data: str, log_enabled=True):
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
        log(f"ℹ️ Отфильтровано {filtered_count} небезопасных конфигов")
    return "\n".join(result), filtered_count

# -------------------- ЗАГРУЗКА И КЭШИРОВАНИЕ --------------------
def download_and_cache(idx):
    url = URLS[idx]
    file_number = idx + 1
    try:
        data = fetch_data(url)
        data = decode_if_base64(data)
        data = clean_existing_headers(data)
        data, _ = filter_insecure_configs(data, log_enabled=False)

        lines = [l.strip() for l in data.splitlines() if l.strip()]

        if file_number in PING_FILTERED_FILES:
            lines = filter_by_ping(lines, file_number)

        with downloaded_configs_lock:
            downloaded_configs[file_number] = lines

        # Сохраняем файл локально (кроме 10, который будет пересоздан отдельно)
        if file_number != 10:
            path = f"githubmirror/{file_number}.txt"
            save_to_local_file(path, "\n".join(lines), file_number)

        return file_number, lines
    except Exception as e:
        log(f"⚠️ Ошибка при скачивании {url}: {str(e)[:100]}")
        return None

# -------------------- ЗАГРУЗКА ДОП. ИСТОЧНИКОВ --------------------
def fetch_extra_sources(urls: list[str]) -> list[str]:
    all_lines = []
    def load(url):
        try:
            data = fetch_data(url, timeout=EXTRA_URL_TIMEOUT, max_attempts=EXTRA_URL_MAX_ATTEMPTS,
                              allow_http_downgrade=False)
            data = clean_existing_headers(data)
            data, _ = filter_insecure_configs(data, log_enabled=False)
            return data.splitlines()
        except:
            return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(load, url) for url in urls]
        for future in concurrent.futures.as_completed(futures):
            all_lines.extend(future.result())
    return [l.strip() for l in all_lines if l.strip() and not l.startswith('#')]

# -------------------- GeoIP: автономная загрузка IP2Location --------------------
_geoip_ranges: list[tuple[int, int, str]] = []
_geoip_loaded = False
_geoip_lock = threading.Lock()

def _download_ip2location_db():
    """Скачивает и распаковывает IP2Location LITE DB1 (Country)."""
    log("📥 Скачивание IP2Location LITE DB1 (Country)...")
    zip_path = "IP2LOCATION-LITE-DB1.CSV.ZIP"
    
    # Скачиваем ZIP
    resp = requests.get(GEOIP_ZIP_URL, timeout=60, stream=True)
    resp.raise_for_status()
    total_size = int(resp.headers.get('content-length', 0))
    downloaded = 0
    with open(zip_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
            downloaded += len(chunk)
            if total_size:
                log(f"   Загружено: {downloaded * 100 / total_size:.0f}%")
    
    # Распаковываем
    log("📦 Распаковка...")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        csv_name = None
        for name in zf.namelist():
            if name.endswith('.CSV'):
                csv_name = name
                break
        if not csv_name:
            raise RuntimeError("CSV файл не найден в ZIP архиве")
        zf.extract(csv_name, ".")
        if csv_name != GEOIP_CSV_PATH:
            if os.path.exists(GEOIP_CSV_PATH):
                os.remove(GEOIP_CSV_PATH)
            os.rename(csv_name, GEOIP_CSV_PATH)
    
    os.remove(zip_path)
    log("✅ IP2Location база загружена")

def _load_geoip_db():
    """Загружает CSV базу в память как список диапазонов."""
    global _geoip_ranges, _geoip_loaded
    
    with _geoip_lock:
        if _geoip_loaded:
            return
        
        if not os.path.exists(GEOIP_CSV_PATH):
            _download_ip2location_db()
        
        log("🔍 Загрузка GeoIP базы в память...")
        ranges = []
        with open(GEOIP_CSV_PATH, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 3 and row[0].isdigit() and row[1].isdigit():
                    try:
                        start_ip = int(row[0])
                        end_ip = int(row[1])
                        country = row[2].strip().upper()
                        ranges.append((start_ip, end_ip, country))
                    except ValueError:
                        continue
        
        # Сортируем по начальному IP для бинарного поиска
        ranges.sort(key=lambda x: x[0])
        _geoip_ranges = ranges
        _geoip_loaded = True
        log(f"✅ Загружено {len(ranges)} диапазонов IP")

def _get_country_code(ip_str: str) -> str | None:
    """Определяет страну по IP используя загруженную базу."""
    _load_geoip_db()
    
    if not _geoip_ranges:
        return None
    
    try:
        ip = ipaddress.ip_address(ip_str)
        ip_int = int(ip)
        
        # Бинарный поиск
        lo, hi = 0, len(_geoip_ranges) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end, country = _geoip_ranges[mid]
            if ip_int < start:
                hi = mid - 1
            elif ip_int > end:
                lo = mid + 1
            else:
                return country
        return None
    except Exception:
        return None

def _resolve_host_to_ip(host: str) -> str | None:
    ipv4_re = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
    if ipv4_re.match(host):
        return host
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def _is_cascade_config(config: str) -> bool:
    hp = extract_host_and_port(config)
    if not hp:
        return False
    host, _ = hp
    ip = _resolve_host_to_ip(host)
    if not ip:
        return False
    country = _get_country_code(ip)
    return country == "RU"

# -------------------- СБОРКА ФАЙЛА 26 --------------------
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
    "40.img.avito.st", "41.img.avito.st", "42.img.avito.st", "43.img.avito.st",
    "44.img.avito.st", "45.img.avito.st", "46.img.avito.st", "47.img.avito.st",
    "48.img.avito.st", "49.img.avito.st", "50.img.avito.st", "51.img.avito.st",
    "52.img.avito.st", "53.img.avito.st", "54.img.avito.st", "55.img.avito.st",
    "56.img.avito.st", "57.img.avito.st", "58.img.avito.st", "59.img.avito.st",
    "60.img.avito.st", "61.img.avito.st", "62.img.avito.st", "63.img.avito.st",
    "64.img.avito.st", "65.img.avito.st", "66.img.avito.st", "67.img.avito.st",
    "68.img.avito.st", "69.img.avito.st", "70.img.avito.st", "71.img.avito.st",
    "72.img.avito.st", "73.img.avito.st", "74.img.avito.st", "742231.ms.ok.ru",
    "75.img.avito.st", "76.img.avito.st", "77.img.avito.st", "78.img.avito.st",
    "79.img.avito.st", "80.img.avito.st", "81.img.avito.st", "82.img.avito.st",
    "83.img.avito.st", "84.img.avito.st", "85.img.avito.st", "86.img.avito.st",
    "87.img.avito.st", "88.img.avito.st", "89.img.avito.st", "8mar.mail.ru", "8march.mail.ru",
    "90.img.avito.st", "91.img.avito.st", "92.img.avito.st", "93.img.avito.st",
    "94.img.avito.st", "95.img.avito.st", "96.img.avito.st", "97.img.avito.st",
    "98.img.avito.st", "99.img.avito.st", "9may.mail.ru", "a.auth-nsdi.ru", "a.res-nsdi.ru",
    "a.wb.ru", "aa.mail.ru", "ad.adriver.ru", "ad.mail.ru", "adm.digital.gov.ru",
    "adm.mp.rzd.ru", "admin.cs7777.vk.ru", "admin.tau.vk.ru", "ads.vk.ru", "adv.ozon.ru",
    "afisha.mail.ru", "agent.mail.ru", "akashi.vk-portal.net", "alfabank.ru",
    "alfabank.servicecdn.ru", "alfabank.st", "alpha3.minigames.mail.ru",
    "alpha4.minigames.mail.ru", "amigo.mail.ru", "ams2-cdn.2gis.com", "an.yandex.ru",
    "analytics.predict.mail.ru", "analytics.vk.ru", "answer.mail.ru", "answers.mail.ru",
    "api-maps.yandex.ru", "api.2gis.ru", "api.a.mts.ru", "api.apteka.ru", "api.avito.ru",
    "api.browser.yandex.com", "api.browser.yandex.ru", "api.cs7777.vk.ru",
    "api.events.plus.yandex.net", "api.expf.ru", "api.max.ru", "api.mindbox.ru", "api.ok.ru",
    "api.photo.2gis.com", "api.plus.kinopoisk.ru", "api.predict.mail.ru",
    "api.reviews.2gis.com", "api.s3.yandex.net", "api.tau.vk.ru", "api.uxfeedback.yandex.net",
    "api.vk.ru", "api2.ivi.ru", "apps.research.mail.ru", "authdl.mail.ru", "auto.mail.ru",
    "auto.ru", "autodiscover.corp.mail.ru", "autodiscover.ord.ozon.ru", "av.mail.ru",
    "avatars.mds.yandex.com", "avatars.mds.yandex.net", "avito.ru", "avito.st", "aw.mail.ru",
    "away.cs7777.vk.ru", "away.tau.vk.ru", "azt.mail.ru", "b.auth-nsdi.ru", "b.res-nsdi.ru",
    "bank.ozon.ru", "banners-website.wildberries.ru", "bb.mail.ru", "bd.mail.ru",
    "beeline.api.flocktory.com", "beko.dom.mail.ru", "bender.mail.ru", "beta.mail.ru",
    "bfds.sberbank.ru", "bitva.mail.ru", "biz.mail.ru", "blackfriday.mail.ru", "blog.mail.ru",
    "bot.gosuslugi.ru", "botapi.max.ru", "bratva-mr.mail.ru", "bro-bg-store.s3.yandex.com",
    "bro-bg-store.s3.yandex.net", "bro-bg-store.s3.yandex.ru", "brontp-pre.yandex.ru",
    "browser.mail.ru", "browser.yandex.com", "browser.yandex.ru", "business.vk.ru",
    "c.dns-shop.ru", "c.rdrom.ru", "calendar.mail.ru", "capsula.mail.ru", "cargo.rzd.ru",
    "cars.mail.ru", "catalog.api.2gis.com", "cdn.connect.mail.ru", "cdn.gpb.ru",
    "cdn.lemanapro.ru", "cdn.newyear.mail.ru", "cdn.rosbank.ru", "cdn.s3.yandex.net",
    "cdn.tbank.ru", "cdn.uxfeedback.ru", "cdn.yandex.ru", "cdn1.tu-tu.ru", "cdnn21.img.ria.ru",
    "cdnrhkgfkkpupuotntfj.svc.cdn.yandex.net", "cf.mail.ru", "chat-ct.pochta.ru",
    "chat-prod.wildberries.ru", "chat3.vtb.ru", "cloud.cdn.yandex.com", "cloud.cdn.yandex.net",
    "cloud.cdn.yandex.ru", "cloud.mail.ru", "cloud.vk.com", "cloud.vk.ru",
    "cloudcdn-ams19.cdn.yandex.net", "cloudcdn-m9-10.cdn.yandex.net",
    "cloudcdn-m9-12.cdn.yandex.net", "cloudcdn-m9-13.cdn.yandex.net",
    "cloudcdn-m9-14.cdn.yandex.net", "cloudcdn-m9-15.cdn.yandex.net",
    "cloudcdn-m9-2.cdn.yandex.net", "cloudcdn-m9-3.cdn.yandex.net",
    "cloudcdn-m9-4.cdn.yandex.net", "cloudcdn-m9-5.cdn.yandex.net",
    "cloudcdn-m9-6.cdn.yandex.net", "cloudcdn-m9-7.cdn.yandex.net",
    "cloudcdn-m9-9.cdn.yandex.net", "cm.a.mts.ru", "cms-res-web.online.sberbank.ru",
    "cobma.mail.ru", "cobmo.mail.ru", "cobrowsing.tbank.ru", "code.mail.ru",
    "codefest.mail.ru", "cog.mail.ru", "collections.yandex.com", "collections.yandex.ru",
    "comba.mail.ru", "combu.mail.ru", "commba.mail.ru", "company.rzd.ru", "compute.mail.ru",
    "connect.cs7777.vk.ru", "contacts.rzd.ru", "contract.gosuslugi.ru", "corp.mail.ru",
    "counter.yadro.ru", "cpa.hh.ru", "cpg.money.mail.ru", "crazypanda.mail.ru",
    "crowdtest.payment-widget-smarttv.plus.tst.kinopoisk.ru",
    "crowdtest.payment-widget.plus.tst.kinopoisk.ru", "cs.avito.ru", "cs7777.vk.ru",
    "csp.yandex.net", "ctlog.mail.ru", "ctlog2023.mail.ru", "ctlog2024.mail.ru", "cto.mail.ru",
    "cups.mail.ru", "d-assets.2gis.ru", "d5de4k0ri8jba7ucdbt6.apigw.yandexcloud.net",
    "da-preprod.biz.mail.ru", "da.biz.mail.ru", "data.amigo.mail.ru", "dating.ok.ru",
    "deti.mail.ru", "dev.cs7777.vk.ru", "dev.max.ru", "dev.tau.vk.ru", "dev1.mail.ru",
    "dev2.mail.ru", "dev3.mail.ru", "digital.gov.ru", "disk.2gis.com", "disk.rzd.ru",
    "dk.mail.ru", "dl.mail.ru", "dl.marusia.mail.ru", "dmp.dmpkit.lemanapro.ru", "dn.mail.ru",
    "dnd.wb.ru", "dobro.mail.ru", "doc.mail.ru", "dom.mail.ru", "download.max.ru",
    "dr.yandex.net", "dr2.yandex.net", "dragonpals.mail.ru", "ds.mail.ru", "duck.mail.ru",
    "duma.gov.ru", "dzen.ru", "e.mail.ru", "education.mail.ru", "egress.yandex.net",
    "eh.vk.com", "ekmp-a-51.rzd.ru", "enterprise.api-maps.yandex.ru", "epp.genproc.gov.ru",
    "esa-res.online.sberbank.ru", "esc.predict.mail.ru", "esia.gosuslugi.ru", "et.mail.ru",
    "expert.vk.ru", "external-api.mediabilling.kinopoisk.ru", "external-api.plus.kinopoisk.ru",
    "eye.targetads.io", "favicon.yandex.com", "favicon.yandex.net", "favicon.yandex.ru",
    "favorites.api.2gis.com", "fb-cdn.premier.one", "fe.mail.ru", "filekeeper-vod.2gis.com",
    "finance.mail.ru", "finance.wb.ru", "five.predict.mail.ru", "foto.mail.ru",
    "frontend.vh.yandex.ru", "fw.wb.ru", "games-bamboo.mail.ru", "games-fisheye.mail.ru",
    "games.mail.ru", "gazeta.ru", "genesis.mail.ru", "geo-apart.predict.mail.ru",
    "get4click.ru", "gibdd.mail.ru", "go.mail.ru", "golos.mail.ru", "gosuslugi.ru",
    "gosweb.gosuslugi.ru", "government.ru", "goya.rutube.ru", "gpb.finance.mail.ru",
    "graphql-web.kinopoisk.ru", "graphql.kinopoisk.ru", "gu-st.ru", "guns.mail.ru",
    "hb-bidder.skcrtxr.com", "hd.kinopoisk.ru", "health.mail.ru", "help.max.ru",
    "help.mcs.mail.ru", "hh.ru", "hhcdn.ru", "hi-tech.mail.ru", "horo.mail.ru", "hrc.tbank.ru",
    "hs.mail.ru", "http-check-headers.yandex.ru", "i.hh.ru", "i.max.ru", "i.rdrom.ru",
    "i0.photo.2gis.com", "i1.photo.2gis.com", "i2.photo.2gis.com", "i3.photo.2gis.com",
    "i4.photo.2gis.com", "i5.photo.2gis.com", "i6.photo.2gis.com", "i7.photo.2gis.com",
    "i8.photo.2gis.com", "i9.photo.2gis.com", "id.cs7777.vk.ru", "id.sber.ru", "id.tau.vk.ru",
    "id.tbank.ru", "id.vk.ru", "identitystatic.mts.ru", "images.apteka.ru",
    "imgproxy.cdn-tinkoff.ru", "imperia.mail.ru", "informer.yandex.ru", "infra.mail.ru",
    "internet.mail.ru", "invest.ozon.ru", "io.ozone.ru", "ir.ozone.ru", "it.mail.ru",
    "izbirkom.ru", "jam.api.2gis.com", "jd.mail.ru", "jitsi.wb.ru", "journey.mail.ru",
    "jsons.injector.3ebra.net", "juggermobile.mail.ru", "junior.mail.ru", "keys.api.2gis.com",
    "kicker.mail.ru", "kiks.yandex.com", "kiks.yandex.ru", "kingdomrift.mail.ru",
    "kino.mail.ru", "knights.mail.ru", "kobma.mail.ru", "kobmo.mail.ru", "komba.mail.ru",
    "kombo.mail.ru", "kombu.mail.ru", "kommba.mail.ru", "konflikt.mail.ru", "kp.ru",
    "kremlin.ru", "kz.mcs.mail.ru", "la.mail.ru", "lady.mail.ru", "landing.mail.ru",
    "le.tbank.ru", "learning.ozon.ru", "legal.max.ru", "legenda.mail.ru",
    "legendofheroes.mail.ru", "lemanapro.ru", "lenta.ru", "link.max.ru", "link.mp.rzd.ru",
    "live.ok.ru", "lk.gosuslugi.ru", "loa.mail.ru", "log.strm.yandex.ru", "login.cs7777.vk.ru",
    "login.mts.ru", "login.tau.vk.ru", "login.vk.com", "login.vk.ru", "lotro.mail.ru",
    "love.mail.ru", "m.47news.ru", "m.avito.ru", "m.cs7777.vk.ru", "m.ok.ru", "m.tau.vk.ru",
    "m.vk.ru", "m.vkvideo.cs7777.vk.ru", "ma.kinopoisk.ru", "magnit-ru.injector.3ebra.net",
    "mail.yandex.com", "mail.yandex.ru", "mailer.mail.ru", "mailexpress.mail.ru",
    "man.mail.ru", "map.gosuslugi.ru", "mapgl.2gis.com", "mapi.learning.ozon.ru",
    "maps.mail.ru", "market.rzd.ru", "marusia.mail.ru", "max.ru", "mc.yandex.com",
    "mc.yandex.ru", "mcs.mail.ru", "mddc.tinkoff.ru", "me.cs7777.vk.ru", "media-golos.mail.ru",
    "media.mail.ru", "mediafeeds.yandex.com", "mediafeeds.yandex.ru", "mediapro.mail.ru",
    "merch-cpg.money.mail.ru", "metrics.alfabank.ru", "microapps.kinopoisk.ru",
    "miniapp.internal.myteam.mail.ru", "minigames.mail.ru", "mkb.ru", "mking.mail.ru",
    "mobfarm.mail.ru", "money.mail.ru", "moscow.megafon.ru", "moskva.beeline.ru",
    "moskva.taximaxim.ru", "mosqa.mail.ru", "mowar.mail.ru", "mozilla.mail.ru", "mp.rzd.ru",
    "ms.cs7777.vk.ru", "msk.t2.ru", "mtscdn.ru", "multitest.ok.ru", "music.vk.ru",
    "my.mail.ru", "my.rzd.ru", "myteam.mail.ru", "nebogame.mail.ru", "net.mail.ru",
    "neuro.translate.yandex.ru", "new.mail.ru", "news.mail.ru", "newyear.mail.ru",
    "newyear2018.mail.ru", "nonstandard.sales.mail.ru", "notes.mail.ru",
    "novorossiya.gosuslugi.ru", "nspk.ru", "oauth.cs7777.vk.ru", "oauth.tau.vk.ru",
    "oauth2.cs7777.vk.ru", "octavius.mail.ru", "ok.ru", "oneclick-payment.kinopoisk.ru",
    "online.sberbank.ru", "operator.mail.ru", "ord.ozon.ru", "ord.vk.ru", "otvet.mail.ru",
    "otveti.mail.ru", "otvety.mail.ru", "owa.ozon.ru", "ozon.ru", "ozone.ru", "panzar.mail.ru",
    "park.mail.ru", "partners.gosuslugi.ru", "partners.lemanapro.ru", "passport.pochta.ru",
    "pay.mail.ru", "pay.ozon.ru", "payment-widget-smarttv.plus.kinopoisk.ru",
    "payment-widget.kinopoisk.ru", "payment-widget.plus.kinopoisk.ru", "pernatsk.mail.ru",
    "personalization-web-stable.mindbox.ru", "pets.mail.ru", "pic.rutubelist.ru", "pikabu.ru",
    "pl-res.online.sberbank.ru", "pms.mail.ru", "pochta.ru", "pochtabank.mail.ru",
    "pogoda.mail.ru", "pokerist.mail.ru", "polis.mail.ru", "pos.gosuslugi.ru", "pp.mail.ru",
    "pptest.userapi.com", "predict.mail.ru", "preview.rutube.ru", "primeworld.mail.ru",
    "privacy-cs.mail.ru", "prodvizhenie.rzd.ru", "ptd.predict.mail.ru", "pubg.mail.ru",
    "public-api.reviews.2gis.com", "public.infra.mail.ru", "pulse.mail.ru", "pulse.mp.rzd.ru",
    "push.vk.ru", "pw.mail.ru", "px.adhigh.net", "quantum.mail.ru", "queuev4.vk.com",
    "quiz.kinopoisk.ru", "r.vk.ru", "r0.mradx.net", "rambler.ru", "rap.skcrtxr.com",
    "rate.mail.ru", "rbc.ru", "rebus.calls.mail.ru", "rebus.octavius.mail.ru",
    "receive-sentry.lmru.tech", "reseach.mail.ru", "restapi.dns-shop.ru", "rev.mail.ru",
    "riot.mail.ru", "rl.mail.ru", "rm.mail.ru", "rs.mail.ru", "rt.api.operator.mail.ru",
    "rutube.ru", "rzd.ru", "s.rbk.ru", "s.vtb.ru", "s0.bss.2gis.com", "s1.bss.2gis.com",
    "s11.auto.drom.ru", "s3.babel.mail.ru", "s3.mail.ru", "s3.media-mobs.mail.ru", "s3.t2.ru",
    "s3.yandex.net", "sales.mail.ru", "sangels.mail.ru", "sba.yandex.com", "sba.yandex.net",
    "sba.yandex.ru", "sberbank.ru", "scitylana.apteka.ru", "sdk.money.mail.ru",
    "secure-cloud.rzd.ru", "secure.rzd.ru", "securepay.ozon.ru", "security.mail.ru",
    "seller.ozon.ru", "sentry.hh.ru", "service.amigo.mail.ru", "servicepipe.ru",
    "serving.a.mts.ru", "sfd.gosuslugi.ru", "shadowbound.mail.ru", "sntr.avito.ru",
    "socdwar.mail.ru", "sochi-park.predict.mail.ru", "souz.mail.ru", "speller.yandex.net",
    "sphere.mail.ru", "splitter.wb.ru", "sport.mail.ru", "sso-app4.vtb.ru", "sso-app5.vtb.ru",
    "sso.auto.ru", "sso.dzen.ru", "sso.kinopoisk.ru", "ssp.rutube.ru", "st-gismeteo.st",
    "st-im.kinopoisk.ru", "st-ok.cdn-vk.ru", "st.avito.ru", "st.gismeteo.st",
    "st.kinopoisk.ru", "st.max.ru", "st.okcdn.ru", "st.ozone.ru",
    "staging-analytics.predict.mail.ru", "staging-esc.predict.mail.ru",
    "staging-sochi-park.predict.mail.ru", "stand.aoc.mail.ru", "stand.bb.mail.ru",
    "stand.cb.mail.ru", "stand.la.mail.ru", "stand.pw.mail.ru", "startrek.mail.ru",
    "stat-api.gismeteo.net", "statad.ru", "static-mon.yandex.net", "static.apteka.ru",
    "static.beeline.ru", "static.dl.mail.ru", "static.lemanapro.ru", "static.operator.mail.ru",
    "static.rutube.ru", "stats.avito.ru", "stats.vk-portal.net", "status.mcs.mail.ru",
    "storage.ape.yandex.net", "storage.yandexcloud.net", "stormriders.mail.ru",
    "stream.mail.ru", "street-combats.mail.ru", "strm-rad-23.strm.yandex.net",
    "strm-spbmiran-07.strm.yandex.net", "strm-spbmiran-08.strm.yandex.net", "strm.yandex.net",
    "strm.yandex.ru", "styles.api.2gis.com", "suggest.dzen.ru", "suggest.sso.dzen.ru",
    "sun6-20.userapi.com", "sun6-21.userapi.com", "sun6-22.userapi.com",
    "sun9-101.userapi.com", "sun9-38.userapi.com", "support.biz.mail.ru",
    "support.mcs.mail.ru", "support.tech.mail.ru", "surveys.yandex.ru",
    "sync.browser.yandex.net", "sync.rambler.ru", "tag.a.mts.ru", "tamtam.ok.ru",
    "target.smi2.net", "target.vk.ru", "team.mail.ru", "team.rzd.ru", "tech.mail.ru",
    "tech.vk.ru", "tera.mail.ru", "ticket.rzd.ru", "tickets.widget.kinopoisk.ru",
    "tidaltrek.mail.ru", "tile0.maps.2gis.com", "tile1.maps.2gis.com", "tile2.maps.2gis.com",
    "tile3.maps.2gis.com", "tile4.maps.2gis.com", "tiles.maps.mail.ru", "tmgame.mail.ru",
    "tmsg.tbank.ru", "tns-counter.ru", "todo.mail.ru", "top-fwz1.mail.ru",
    "touch.kinopoisk.ru", "townwars.mail.ru", "travel.rzd.ru", "travel.yandex.ru",
    "travel.yastatic.net", "trk.mail.ru", "ttbh.mail.ru", "tutu.ru", "tv.mail.ru",
    "typewriter.mail.ru", "u.corp.mail.ru", "ufo.mail.ru", "ui.cs7777.vk.ru", "ui.tau.vk.ru",
    "user-geo-data.wildberries.ru", "uslugi.yandex.ru", "uxfeedback-cdn.s3.yandex.net",
    "uxfeedback.yandex.ru", "vk-portal.net", "vk.com", "vk.mail.ru", "vkdoc.mail.ru",
    "vkvideo.cs7777.vk.ru", "voina.mail.ru", "voter.gosuslugi.ru", "vt-1.ozone.ru",
    "wap.yandex.com", "wap.yandex.ru", "warface.mail.ru", "warheaven.mail.ru",
    "wartune.mail.ru", "wb.ru", "wcm.weborama-tech.ru", "web-static.mindbox.ru", "web.max.ru",
    "webagent.mail.ru", "weblink.predict.mail.ru", "webstore.mail.ru", "welcome.mail.ru",
    "welcome.rzd.ru", "wf.mail.ru", "wh-cpg.money.mail.ru", "whatsnew.mail.ru",
    "widgets.cbonds.ru", "widgets.kinopoisk.ru", "wok.mail.ru", "wos.mail.ru",
    "ws-api.oneme.ru", "ws.seller.ozon.ru", "www.avito.ru", "www.avito.st", "www.biz.mail.ru",
    "www.cikrf.ru", "www.drive2.ru", "www.drom.ru", "www.farpost.ru", "www.gazprombank.ru",
    "www.gosuslugi.ru", "www.ivi.ru", "www.kinopoisk.ru", "www.kp.ru", "www.magnit.com",
    "www.mail.ru", "www.mcs.mail.ru", "www.open.ru", "www.ozon.ru", "www.pochta.ru",
    "www.psbank.ru", "www.pubg.mail.ru", "www.raiffeisen.ru", "www.rbc.ru", "www.rzd.ru",
    "www.sberbank.ru", "www.t2.ru", "www.tbank.ru", "www.tutu.ru", "www.unicreditbank.ru",
    "www.vtb.ru", "www.wf.mail.ru", "www.wildberries.ru", "www.x5.ru", "xapi.ozon.ru",
    "xn--80ajghhoc2aj1c8b.xn--p1ai", "ya.ru", "yabro-wbplugin.edadeal.yandex.ru",
    "yabs.yandex.ru", "yandex.com", "yandex.net", "yandex.ru", "yastatic.net", "yummy.drom.ru",
    "zen-yabro-morda.mediascope.mc.yandex.ru", "zen.yandex.com", "zen.yandex.net",
    "zen.yandex.ru", "честныйзнак.рф"
]


def create_filtered_configs(extra_lines: list[str]):
    all_configs = []
    with downloaded_configs_lock:
        for fnum, lines in downloaded_configs.items():
            if fnum == 10:
                continue
            all_configs.extend(lines)

    all_configs.extend(extra_lines)

    # SNI фильтр
    sorted_domains = sorted(SNI_DOMAINS, key=len)
    sni_regex = re.compile("|".join(re.escape(d) for d in sorted_domains))
    filtered = [cfg for cfg in all_configs if sni_regex.search(cfg)]

    # Дедупликация
    seen_full = set()
    seen_hp = set()
    unique = []
    for cfg in filtered:
        if cfg in seen_full:
            continue
        seen_full.add(cfg)
        hp = extract_host_and_port(cfg)
        if hp:
            key = f"{hp[0].lower()}:{hp[1]}"
            if key in seen_hp:
                continue
            seen_hp.add(key)
        unique.append(cfg)

    unique = filter_by_ping(unique, 26)

    with downloaded_configs_lock:
        downloaded_configs[26] = unique

    path = "githubmirror/26.txt"
    save_to_local_file(path, "\n".join(unique), 26)
    log(f"📁 Создан файл {path} с {len(unique)} конфигами (#26)")
    return len(unique)

# -------------------- СБОРКА ФАЙЛА 10 --------------------
def create_cascade_configs(extra_lines: list[str]):
    log("🌐 [10] Начало сборки каскадных конфигов...")

    all_configs = []
    with downloaded_configs_lock:
        for fnum, lines in downloaded_configs.items():
            if fnum == 10:
                continue
            all_configs.extend(lines)
    all_configs.extend(extra_lines)

    # Дедупликация
    seen_full = set()
    seen_hp = set()
    unique = []
    for cfg in all_configs:
        if cfg in seen_full:
            continue
        seen_full.add(cfg)
        hp = extract_host_and_port(cfg)
        if hp:
            key = f"{hp[0].lower()}:{hp[1]}"
            if key in seen_hp:
                continue
            seen_hp.add(key)
        unique.append(cfg)

    log(f"📦 [10] После дедупликации: {len(unique)}")
    unique = filter_by_ping(unique, 10)

    log(f"🌍 [10] Проверка геолокации для {len(unique)} конфигов...")
    cascade = [cfg for cfg in unique if _is_cascade_config(cfg)]

    log(f"✅ [10] Каскадных конфигов (RU IP): {len(cascade)}")

    path = "githubmirror/10.txt"
    save_to_local_file(path, "\n".join(cascade), 10)
    with downloaded_configs_lock:
        downloaded_configs[10] = cascade

    return len(cascade)

# -------------------- ЕДИНЫЙ GIT-КОММИТ --------------------
def commit_all_changes(file_paths: dict[str, str], stats_json_content: str = None):
    if not file_paths and stats_json_content is None:
        log("⚠️ Нет изменений для коммита")
        return

    try:
        ref = REPO.get_git_ref("heads/main")
        current_commit = REPO.get_git_commit(ref.object.sha)

        # Собираем все обновления в порядке обработки
        updates = []
        for path, content in file_paths.items():
            updates.append((path, content))
        if stats_json_content is not None:
            updates.append((STATS_JSON_PATH, stats_json_content))

        if not updates:
            return

        for path, content in updates:
            # Берём текущее дерево
            base_tree = current_commit.tree

            # Создаём блоб для файла
            blob = REPO.create_git_blob(content, "utf-8")
            element = InputGitTreeElement(
                path=path, mode="100644", type="blob", sha=blob.sha
            )

            # Создаём новое дерево, заменяя/добавляя файл
            new_tree = REPO.create_git_tree([element], base_tree)

            # Формируем сообщение коммита с именем файла
            basename = os.path.basename(path)
            commit_message = f"🚀 Обновление {basename} по часовому поясу Европа/Москва: {offset}"

            # Создаём коммит на основе текущего родителя
            new_commit = REPO.create_git_commit(commit_message, new_tree, [current_commit])
            log(f"✅ Коммит {new_commit.sha}: {commit_message}")

            # Переходим к только что созданному коммиту как к родителю для следующего файла
            current_commit = new_commit

        # Обновляем ветку main на последний коммит в цепочке
        ref.edit(sha=current_commit.sha)
        log(f"✅ Ветка main обновлена на {current_commit.sha}")

    except Exception as e:
        log(f"❌ Ошибка создания коммитов: {e}")

# -------------------- СТАТИСТИКА --------------------
def build_stats_json(file_counts: dict[int, int]) -> str:
    try:
        try:
            contents = REPO.get_contents(STATS_JSON_PATH)
            stats = json.loads(contents.decoded_content)
        except GithubException as e:
            if getattr(e, "status", None) == 404:
                stats = {"last_global_update": "", "files": {}}
            else:
                raise

        stats["last_global_update"] = offset
        if "files" not in stats:
            stats["files"] = {}
        for fnum, count in file_counts.items():
            stats["files"][str(fnum)] = {"count": count, "updated": offset}

        return json.dumps(stats, indent=2, ensure_ascii=False)
    except Exception as e:
        log(f"⚠️ Ошибка при формировании stats.json: {e}")
        return None

# -------------------- MAIN --------------------
def main(dry_run: bool = False):
    log("🚀 Начало обновления конфигураций")
    log(f"📅 Время запуска: {offset}")
    log(f"🔍 Проверка пинга: {'включена' if ENABLE_PING_CHECK else 'выключена'}")
    log(f"📁 Файлы с фильтрацией по пингу: {sorted(PING_FILTERED_FILES)}")

    # 1. Загрузка дополнительных источников
    log("📥 Загрузка дополнительных источников...")
    extra_lines = fetch_extra_sources(EXTRA_URLS_FOR_26)
    log(f"📥 Дополнительных конфигов загружено: {len(extra_lines)}")

    # 2. Параллельная загрузка основных файлов
    with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_MAX_WORKERS) as pool:
        futures = []
        for i in range(len(URLS)):
            # Убираем пропуск 10-го URL (индекс 9), чтобы его конфиги попали в 26.txt
            # if i == 9:
            #     continue
            futures.append(pool.submit(download_and_cache, i))

        file_counts = {}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res is not None:
                fnum, lines = res
                file_counts[fnum] = len(lines)
                with _UPDATED_FILES_LOCK:
                    updated_files.add(fnum)

    # 3. Создание 26-го файла
    log("📁 Сборка файла 26...")
    count_26 = create_filtered_configs(extra_lines)
    file_counts[26] = count_26
    updated_files.add(26)

    # 4. Создание 10-го файла (каскадный, перезапишет downloaded_configs[10])
    log("📁 Сборка файла 10 (каскадные конфиги)...")
    count_10 = create_cascade_configs(extra_lines)
    file_counts[10] = count_10
    updated_files.add(10)

    # 5. Подготовка данных для коммита
    commit_data = {}
    for fnum in sorted(updated_files):
        local_path = f"githubmirror/{fnum}.txt"
        if os.path.exists(local_path):
            with open(local_path, "r", encoding="utf-8") as f:
                content = f.read()
            remote_path = f"githubmirror/{fnum}.txt"
            commit_data[remote_path] = content
        else:
            log(f"⚠️ Файл {local_path} не найден, пропускаем")

    # 6. stats.json
    stats_content = build_stats_json(file_counts) if file_counts and not dry_run else None

    # 7. Коммит
    if not dry_run:
        if commit_data:
            commit_all_changes(commit_data, stats_content)
        elif stats_content:
            commit_all_changes({}, stats_content)
        else:
            log("ℹ️ Нет новых данных для коммита")

        if updated_files:
            send_update_notification()

    # Вывод логов
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
