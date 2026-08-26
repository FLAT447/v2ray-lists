# =============================================================================
# core.py - настройки, утилиты, парсеры ссылок и конвертация в Clash
# =============================================================================
import base64
import json
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional, Dict, Set

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

USER_AGENT = "Mozilla/5.0 (compatible; vpn-parser/1.0)"
__version__ = "1.0.0"

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"
LISTS_FILE = BASE_DIR / "lists.json"

DEFAULT_CONFIG = {
    "output_dir": "output",
    "sources_dir": "sources",
    "max_configs": 0,
    "health_check": True,
    "health_check_timeout": 4,
    "health_check_workers": 200,
    "latency_threshold": 2000,
    "full_drop_slow": False,
    "dedup": True,
    "include_protocols": ["vless", "trojan", "hysteria2", "ss"],
    "import_rkp": False,
    "rkp_whitelist": "../#RKP_Parser5.0.1/#RKP_Parser5.0.1/configs/generic/whitelist.txt",
    "rkp_blacklist": "../#RKP_Parser5.0.1/#RKP_Parser5.0.1/configs/generic/blacklist.txt",
    "rule_list_cache_dir": "rules_cache",
    "git": {
        "enabled": False,
        "repo_url": "https://gitverse.ru/FLAT447/my-repo",
        "branch": "main",
        "local_dir": "mirror",
        "self_host_rules": True,
        "raw_base": "https://gitverse.ru/FLAT447/my-repo/raw/main",
    },
}

DEFAULT_LISTS = {
    "domestic_full": "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Russia/inside-raw.lst",
    "domestic_lite": "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt",
    "blocked_full": "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/refs/heads/main/domains_all.lst",
    "blocked_lite": "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst",
}

cfg: dict = dict(DEFAULT_CONFIG)
lists: dict = dict(DEFAULT_LISTS)


def load_dotenv():
    """Считывает переменные из .env в os.environ (если их ещё нет)."""
    p = BASE_DIR / ".env"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def load_configs():
    global cfg, lists
    load_dotenv()
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except Exception as e:
            print(f"[!] Ошибка чтения {CONFIG_FILE}: {e}")
    if LISTS_FILE.exists():
        try:
            lists.update(json.loads(LISTS_FILE.read_text(encoding="utf-8")))
        except Exception as e:
            print(f"[!] Ошибка чтения {LISTS_FILE}: {e}")


# --- Регулярки ---
VLESS_REGEX = re.compile(r"vless://[^\s\"'<>#]+", re.IGNORECASE)
TROJAN_REGEX = re.compile(r"trojan://[^\s\"'<>#]+", re.IGNORECASE)
HY2_REGEX = re.compile(r"(?:hysteria2|hy2)://[^\s\"'<>#]+", re.IGNORECASE)
SS_REGEX = re.compile(r"ss://[^\s\"'<>#]+", re.IGNORECASE)
MTPROTO_REGEX = re.compile(r"mtproto://[^\s\"'<>#]+", re.IGNORECASE)
TG_PROXY_REGEX = re.compile(r"https?://t\.me/proxy\?[^\s\"'<>#]+", re.IGNORECASE)
BASE64_LINE_REGEX = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


# --- Утилиты ---
def now_str() -> str:
    t = time.localtime()
    return f"{t.tm_hour:02d}:{t.tm_min:02d} | {t.tm_mday:02d}.{t.tm_mon:02d}.{t.tm_year}"


def safe_print(*a):
    try:
        print(*a)
    except UnicodeEncodeError:
        print(*[str(x).encode("ascii", "ignore").decode() for x in a])


def http_get(url: str, timeout: int = 20, binary: bool = False):
    headers = {"User-Agent": USER_AGENT}
    if "github" in url and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            return data if binary else data.decode("utf-8", errors="ignore")
    except Exception:
        if HAVE_REQUESTS:
            try:
                r = requests.get(url, timeout=timeout, headers=headers)
                return r.content if binary else r.text
            except Exception:
                return None
        return None


def try_b64_decode(blob: str) -> Optional[str]:
    blob = blob.strip()
    if len(blob) < 16:
        return None
    if not re.match(r"^[A-Za-z0-9+/=]+$", blob):
        return None
    try:
        pad = "=" * (-len(blob) % 4)
        dec = base64.b64decode(blob + pad, validate=True)
        return dec.decode("utf-8", errors="ignore")
    except Exception:
        return None


def normalize_config(url: str) -> str:
    try:
        url = url.strip()
        if "#" in url:
            url = url.split("#", 1)[0]
        if "?" in url:
            base, query = url.split("?", 1)
            params = {}
            for p in query.split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    params[k] = v
                else:
                    params[p] = ""
            url = base + "?" + "&".join(f"{k}={v}" for k, v in sorted(params.items()))
        return url
    except Exception:
        return url.strip()


def extract_links(text: str, depth: int = 0) -> Set[str]:
    found: Set[str] = set()
    if not text:
        return found
    # t.me/proxy оставляем как есть (именно этот формат читает Telegram)
    for pat in (VLESS_REGEX, TROJAN_REGEX, HY2_REGEX, SS_REGEX, MTPROTO_REGEX, TG_PROXY_REGEX):
        for m in pat.findall(text):
            found.add(m.strip())
    if depth < 3:
        for blob in BASE64_LINE_REGEX.findall(text):
            dec = try_b64_decode(blob)
            if dec and ("://" in dec or "vmess" in dec):
                found |= extract_links(dec, depth + 1)
    return found


# =============================================================================
# ПАРСЕРЫ ССЫЛОК -> СТРУКТУРИРОВАННЫЙ СЛОВАРЬ
# =============================================================================
def clean_url(url: str) -> str:
    return url.strip().replace("\ufeff", "").replace("\u200b", "")


def parse_vless(url: str) -> Optional[dict]:
    try:
        url = clean_url(url)
        if not url.startswith("vless://"):
            return None
        main = url
        tag = "vless"
        if "#" in url:
            parts = url.split("#", 1)
            main = parts[0]
            tag = urllib.parse.unquote(parts[1]).strip()
        m = re.search(r"vless://([^@]+)@([^:]+):(\d+)", main)
        if not m:
            return None
        uuid, address, port = m.group(1).strip(), m.group(2).strip(), int(m.group(3))
        params = {}
        if "?" in main:
            params = urllib.parse.parse_qs(main.split("?", 1)[1])

        def g(k, d=""):
            v = params.get(k, [d])[0].strip()
            return v if v else d

        net = g("type", "tcp").lower()
        if net == "raw":
            net = "tcp"
        if net not in ("tcp", "ws", "websocket", "httpupgrade", "xhttp", "grpc", "h2", "kcp", "quic"):
            net = "tcp"
        security = g("security", "none").lower()
        if security not in ("tls", "reality", "none"):
            security = "none"
        pbk = g("pbk", "")
        # reality имеет смысл только при наличии публичного ключа (pbk)
        if pbk and security in ("tls", "reality"):
            security = "reality"
        elif security == "reality" and not pbk:
            security = "none"
        return {
            "protocol": "vless", "uuid": uuid, "address": address, "port": port,
            "type": net, "security": security,
            "path": urllib.parse.unquote(g("path", "")),
            "host": g("host", ""), "sni": g("sni", ""), "fp": g("fp", "chrome"),
            "alpn": g("alpn", ""), "serviceName": g("serviceName", ""),
            "flow": g("flow", ""), "headerType": g("headerType", ""),
            "quicSecurity": g("quicSecurity", ""), "key": g("key", ""),
            "pbk": pbk, "sid": g("sid", ""), "tag": tag,
        }
    except Exception:
        return None


def parse_trojan(url: str) -> Optional[dict]:
    try:
        url = clean_url(url)
        if not url.startswith("trojan://"):
            return None
        u = url.replace("%23", "___HASH___")
        if "#" in u:
            clean, tag = u.split("#", 1)
            tag = urllib.parse.unquote(tag).strip().replace("___HASH___", "#")
        else:
            clean, tag = u, "trojan"
        p = urllib.parse.urlparse(clean)
        q = urllib.parse.parse_qs(p.query)
        password = urllib.parse.unquote(p.username or "trojan").replace("___HASH___", "#")
        if not p.hostname or not p.port:
            return None

        def g(k, d=""):
            v = q.get(k, [d])[0]
            return urllib.parse.unquote(v).strip() if v else d

        net = g("type", "tcp").lower()
        if net not in ("tcp", "ws", "websocket", "httpupgrade", "xhttp", "grpc", "h2", "kcp", "quic"):
            net = "tcp"
        security = g("security", "tls").lower()
        if security not in ("tls", "none"):
            security = "tls"
        return {
            "protocol": "trojan", "password": password, "address": p.hostname,
            "port": int(p.port), "type": net, "security": security,
            "path": g("path", ""), "host": g("host", ""), "sni": g("sni", ""),
            "fp": g("fp", "chrome"), "alpn": g("alpn", ""),
            "serviceName": g("serviceName", ""), "headerType": g("headerType", ""),
            "quicSecurity": g("quicSecurity", ""), "key": g("key", ""), "tag": tag,
        }
    except Exception:
        return None


def parse_hy2(url: str) -> Optional[dict]:
    try:
        url = clean_url(url)
        if not url.startswith(("hysteria2://", "hy2://")):
            return None
        u = url.replace("%23", "___HASH___")
        if "#" in u:
            clean, tag = u.split("#", 1)
            tag = urllib.parse.unquote(tag).strip().replace("___HASH___", "#")
        else:
            clean, tag = u, "hy2"
        p = urllib.parse.urlparse(clean)
        q = urllib.parse.parse_qs(p.query)
        host, port = p.hostname, p.port or 443
        auth = ""
        if "@" in p.netloc:
            auth_part, host_part = p.netloc.split("@", 1)
            auth = urllib.parse.unquote(auth_part)
            if ":" in host_part:
                host, port = host_part.split(":", 1)
                port = int(port)
            else:
                host = host_part

        def g(k, d=""):
            v = q.get(k, [d])[0]
            return urllib.parse.unquote(v).strip() if v else d

        return {
            "protocol": "hysteria2", "auth": auth, "address": host,
            "port": int(port), "sni": g("sni", host or ""),
            "insecure": g("insecure", "true").lower() in ("true", "1", "yes"),
            "alpn": g("alpn", "h3"), "obfs": g("obfs", ""),
            "obfs-password": g("obfs-password", ""),
            "upmbps": g("upmbps", ""), "downmbps": g("downmbps", ""), "tag": tag,
        }
    except Exception:
        return None


SS_CIPHER_ALIASES = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "chacha20-ietf-poly1305": "chacha20-ietf-poly1305",
    "aes-256-gcm": "aes-256-gcm",
    "aes-128-gcm": "aes-128-gcm",
    "aes-192-gcm": "aes-192-gcm",
    "chacha20-ietf": "chacha20-ietf",
    "chacha20": "chacha20",
    "aes-256-cfb": "aes-256-cfb",
    "aes-128-cfb": "aes-128-cfb",
    "rc4-md5": "rc4-md5",
}


def normalize_ss_cipher(method: str) -> str:
    return SS_CIPHER_ALIASES.get(method.strip().lower(), method.strip())


def normalize_reality_sid(sid: str) -> str:
    """Валидирует REALITY short-id для Clash: чётная длина, hex, до 16 байт.

    Clash падает с 'invalid REALITY short ID', если значение не hex или
    нечётной длины. Невалидные/пустые значения отбрасываются.
    """
    if not sid:
        return ""
    sid = sid.strip().lower()
    if len(sid) % 2 != 0:
        sid = sid[:-1]
    if len(sid) > 32:
        sid = sid[:32]
    if re.fullmatch(r"[0-9a-f]+", sid or ""):
        return sid
    return ""


def parse_ss(url: str) -> Optional[dict]:
    try:
        url = clean_url(url)
        if not url.startswith("ss://"):
            return None
        u = url.replace("%23", "___HASH___")
        if "#" in u:
            clean, tag = u.split("#", 1)
            tag = urllib.parse.unquote(tag).strip().replace("___HASH___", "#")
        else:
            clean, tag = u, "ss"
        body = clean[len("ss://"):]
        if "@" not in body:
            return None
        left, right = body.rsplit("@", 1)
        if "#" in right:
            right = right.split("#", 1)[0]
        method = password = host = port = None
        if re.match(r"^[A-Za-z0-9+/=]+$", left):
            try:
                dec = base64.b64decode(left + "=" * (-len(left) % 4)).decode("utf-8", "ignore")
                if ":" in dec:
                    method, password = dec.split(":", 1)
            except Exception:
                pass
        else:
            if ":" in left:
                method, password = left.split(":", 1)
        if ":" in right:
            host, port = right.rsplit(":", 1)
            try:
                port = int(port)
            except Exception:
                return None
        if not (method and password and host and port):
            return None
        return {
            "protocol": "ss", "method": normalize_ss_cipher(method),
            "password": password,
            "address": host, "port": port, "tag": tag,
        }
    except Exception:
        return None


def parse_mtproto(url: str) -> Optional[dict]:
    try:
        url = clean_url(url)
        raw = url.split("#", 1)[0]
        secret = server = None
        port = None
        if raw.startswith("mtproto://"):
            m = re.match(r"mtproto://([^@]+)@([^:]+):(\d+)", raw)
            if m:
                secret, server, port = m.group(1), m.group(2), int(m.group(3))
        elif "t.me/proxy" in raw:
            q = urllib.parse.urlparse(raw).query
            params = urllib.parse.parse_qs(q)
            server = params.get("server", [None])[0]
            port = params.get("port", [None])[0]
            secret = params.get("secret", [None])[0]
            if port:
                port = int(port)
        if not (secret and server and port):
            return None
        # t.me/proxy — единственный формат, который понимает Telegram
        tme = f"https://t.me/proxy?server={server}&port={port}&secret={secret}"
        return {
            "protocol": "mtproto", "raw": raw, "tag": "mtproto",
            "address": server, "port": port, "secret": secret, "tme": tme,
        }
    except Exception:
        return None


def config_url_to_parsed(url: str) -> Optional[dict]:
    for prefix, fn in (
        ("vless://", parse_vless),
        ("trojan://", parse_trojan),
        ("hysteria2://", parse_hy2),
        ("hy2://", parse_hy2),
        ("ss://", parse_ss),
        ("mtproto://", parse_mtproto),
        ("https://t.me/proxy", parse_mtproto),
        ("http://t.me/proxy", parse_mtproto),
    ):
        if url.startswith(prefix):
            return fn(url)
    return None


COUNTRY_NAMES_RU = {
    'RU': 'Россия', 'US': 'США', 'GB': 'Великобритания', 'DE': 'Германия',
    'FR': 'Франция', 'NL': 'Нидерланды', 'SG': 'Сингапур', 'HK': 'Гонконг',
    'JP': 'Япония', 'KR': 'Южная Корея', 'CA': 'Канада', 'AU': 'Австралия',
    'CH': 'Швейцария', 'SE': 'Швеция', 'NO': 'Норвегия', 'DK': 'Дания',
    'FI': 'Финляндия', 'IT': 'Италия', 'ES': 'Испания', 'PT': 'Португалия',
    'PL': 'Польша', 'CZ': 'Чехия', 'SK': 'Словакия', 'HU': 'Венгрия',
    'RO': 'Румыния', 'BG': 'Болгария', 'GR': 'Греция', 'TR': 'Турция',
    'AE': 'ОАЭ', 'IL': 'Израиль', 'IN': 'Индия', 'TH': 'Таиланд',
    'VN': 'Вьетнам', 'ID': 'Индонезия', 'PH': 'Филиппины', 'MY': 'Малайзия',
    'TW': 'Тайвань', 'CN': 'Китай', 'BR': 'Бразилия', 'MX': 'Мексика',
    'ZA': 'ЮАР', 'EG': 'Египет', 'UA': 'Украина', 'KZ': 'Казахстан',
    'GE': 'Грузия', 'AM': 'Армения', 'AZ': 'Азербайджан', 'BY': 'Беларусь',
    'LT': 'Литва', 'LV': 'Латвия', 'EE': 'Эстония', 'IE': 'Ирландия',
    'AT': 'Австрия', 'BE': 'Бельгия', 'LU': 'Люксембург', 'CY': 'Кипр',
    'MT': 'Мальта', 'CR': 'Коста-Рика', 'PA': 'Панама', 'SA': 'Саудовская Аравия',
    'QA': 'Катар', 'KW': 'Кувейт', 'BD': 'Бангладеш', 'NP': 'Непал',
    'LK': 'Шри-Ланка', 'KH': 'Камбоджа', 'MN': 'Монголия', 'UZ': 'Узбекистан',
    'KG': 'Кыргызстан', 'TJ': 'Таджикистан', 'RS': 'Сербия', 'HR': 'Хорватия',
    'SI': 'Словения', 'BA': 'Босния и Герцеговина', 'AL': 'Албания',
    'PE': 'Перу', 'EC': 'Эквадор', 'VE': 'Венесуэла', 'UY': 'Уругвай',
    'PY': 'Парагвай', 'BO': 'Боливия', 'CL': 'Чили', 'CO': 'Колумбия',
    'AR': 'Аргентина', 'NZ': 'Новая Зеландия', 'NG': 'Нигерия', 'KE': 'Кения',
    'PK': 'Пакистан', 'MM': 'Мьянма', 'LA': 'Лаос', 'MD': 'Молдова',
    'IS': 'Исландия', 'LI': 'Лихтенштейн', 'MC': 'Монако',
}


def _code_to_flag(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return ''
    code = country_code.upper()
    return chr(127462 + ord(code[0]) - ord('A')) + chr(127462 + ord(code[1]) - ord('A'))


def country_label(code: str) -> str:
    """Возвращает строку '🇷🇺 Россия' для ISO-кода, иначе ''."""
    if not code:
        return ''
    return f"{_code_to_flag(code)} {COUNTRY_NAMES_RU.get(code.upper(), code.upper())}"


def generate_proxy_name(p: dict, idx: int, country: str = "") -> str:
    tag = p.get("tag", "").strip()
    proto = p.get("protocol", "unk")
    addr = p.get("address", "unknown")
    geo = country_label(country)
    if geo:
        geo += " "
    if tag and tag.lower() not in ("vless", "trojan", "hy2", "hysteria2", "ss", "mtproto"):
        return f"{geo}{tag} #{idx:03d}"
    return f"{geo}{proto.upper()}-{addr}-{idx:03d}"


def parsed_to_clash_proxy(p: dict) -> Optional[dict]:
    proto = p.get("protocol")
    name = p.get("tag", proto)
    if proto == "vless":
        proxy = {
            "name": name, "type": "vless",
            "server": p["address"], "port": p["port"],
            "uuid": p["uuid"], "udp": True, "encryption": "none",
            "tls": p.get("security") in ("tls", "reality"),
            "servername": p.get("sni", p.get("address", "")),
            "client-fingerprint": p.get("fp", "chrome"),
        }
        if p.get("security") == "reality":
            if p.get("flow"):
                proxy["flow"] = p["flow"]
            else:
                proxy["flow"] = "xtls-rprx-vision"
        elif p.get("flow"):
            proxy["flow"] = p["flow"]
        net = p.get("type", "tcp")
        if net in ("ws", "websocket"):
            proxy["network"] = "ws"
            path, host = p.get("path", ""), p.get("host", "")
            if path or host:
                proxy["ws-opts"] = {}
                if path:
                    proxy["ws-opts"]["path"] = path
                if host:
                    proxy["ws-opts"]["headers"] = {"Host": host}
        elif net == "grpc":
            proxy["network"] = "grpc"
            if p.get("serviceName"):
                proxy.setdefault("grpc-opts", {})["grpc-service-name"] = p["serviceName"]
        elif net not in ("tcp",):
            proxy["network"] = net
        # reality-opts обязан содержать public-key, иначе Clash падает с ошибкой
        # 'reality-opts' has unset fields: public-key. Поэтому эмитим только при наличии pbk.
        if p.get("security") == "reality" and p.get("pbk"):
            proxy["reality-opts"] = {"public-key": p["pbk"]}
            sid = normalize_reality_sid(p.get("sid"))
            if sid:
                proxy["reality-opts"]["short-id"] = sid
        return proxy
    if proto == "trojan":
        proxy = {
            "name": name, "type": "trojan",
            "server": p["address"], "port": p["port"],
            "password": p["password"], "udp": True,
            "tls": p.get("security") == "tls",
            "servername": p.get("sni", p.get("address", "")),
        }
        if p.get("fp"):
            proxy["client-fingerprint"] = p["fp"]
        net = p.get("type", "tcp")
        if net in ("ws", "websocket"):
            proxy["network"] = "ws"
            path, host = p.get("path", ""), p.get("host", "")
            if path or host:
                proxy["ws-opts"] = {}
                if path:
                    proxy["ws-opts"]["path"] = path
                if host:
                    proxy["ws-opts"]["headers"] = {"Host": host}
        elif net == "grpc":
            proxy["network"] = "grpc"
            if p.get("serviceName"):
                proxy.setdefault("grpc-opts", {})["grpc-service-name"] = p["serviceName"]
        elif net not in ("tcp",):
            proxy["network"] = net
        return proxy
    if proto == "hysteria2":
        proxy = {
            "name": name, "type": "hysteria2",
            "server": p["address"], "port": p["port"],
            "password": p.get("auth", ""), "udp": True,
        }
        if p.get("sni"):
            proxy["sni"] = p["sni"]
        if p.get("insecure"):
            proxy["skip-cert-verify"] = True
        if p.get("obfs") == "salamander" and p.get("obfs-password"):
            proxy["obfs"] = "salamander"
            proxy["obfs-password"] = p["obfs-password"]
        if p.get("alpn") and p["alpn"] != "h3":
            proxy["alpn"] = [a.strip() for a in p["alpn"].split(",")]
        if p.get("upmbps"):
            proxy["up"] = str(p["upmbps"])
        if p.get("downmbps"):
            proxy["down"] = str(p["downmbps"])
        return proxy
    if proto == "ss":
        return {
            "name": name, "type": "ss",
            "server": p["address"], "port": p["port"],
            "cipher": p["method"], "password": p["password"], "udp": True,
        }
    return None
