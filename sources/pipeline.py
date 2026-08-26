# =============================================================================
# pipeline.py - сбор, проверка, формирование пулов и генерация подписок
# =============================================================================
import base64
import os
import re
import json
import ssl
import time
import threading
import socket
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor

from core import (
    cfg, lists, BASE_DIR, now_str, safe_print, http_get, normalize_config,
    extract_links, config_url_to_parsed, parsed_to_clash_proxy,
    generate_proxy_name, country_label,
)

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

SUBSCRIPTIONS = ["BLACK_FULL", "BLACK_LTE", "WHITE_FULL", "WHITE_LITE"]

# Заголовок профиля подписки (info-строки Clash/Mihomo).
# {name} в #profile-title заменяется на читаемое имя подписки (с подчёркиваниями -> пробелами).
SUBSCRIPTION_HEADER = """\
#announce: 🔰 Нажми на спидометр или молнию, чтобы проверить соединение. Меньше ms - лучше | n/a - не работает. Если ВПН плохо работает, то нажмите на 🔄️.
#profile-web-page-url: https://flat447.github.io/v2ray-lists-site
#profile-title: V2Ray Lists - {name}
#support-url: https://t.me/flat447
#profile-update-interval: 1
"""


def _subscription_header(name: str) -> str:
    """Возвращает info-заголовок подписки с подставленным именем."""
    display = name.replace("_", " ")
    return SUBSCRIPTION_HEADER.format(name=display)

# Какой rule-provider и режим маршрутизации у каждой подписки
# mode: "black" -> по умолчанию через прокси, список (direct) -> DIRECT
#       "white" -> по умолчанию DIRECT, список (proxy) -> через прокси
SUB_META = {
    "BLACK_FULL": {"mode": "black", "list_key": "domestic_full"},
    "BLACK_LTE":  {"mode": "black", "list_key": "domestic_lite"},
    "WHITE_FULL": {"mode": "white", "list_key": "blocked_full"},
    "WHITE_LITE": {"mode": "white", "list_key": "blocked_lite"},
}

FALLBACK_RULES = {
    "domestic_full": "example.com\n",
    "domestic_lite": "example.com\n",
    "blocked_full": "example.com\n",
    "blocked_lite": "example.com\n",
}


# =============================================================================
# СБОР КОНФИГОВ (отдельно для ЧЁРНОГО и БЕЛОГО пулов)
# =============================================================================
def _read_lines(path) -> List[str]:
    path = Path(path)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


# Протоколы, которые явно отбрасываем (не подходят для подписок)
REJECT_PROTOCOLS = ("socks5://", "socks://", "http://", "https://")

# Прямые ссылки на конфиги (не HTTP-источник)
DIRECT_PROTOCOLS = ("vless://", "trojan://", "hysteria2://", "hy2://", "ss://", "mtproto://")

# Кэш разрешения хост -> IPv4 и кэш whitelist-IP
_RESOLVE_CACHE: Dict[str, Optional[str]] = {}
_WHITELIST_CACHE: Optional[set] = None

# =============================================================================
# GEOIP (MMDB) — определение страны по IP для имён конфигов
# =============================================================================
_MMDB_PATH = BASE_DIR / "country.mmdb"
_GEO_READER = None
_GEO_CACHE: Dict[str, str] = {}

MMDB_URLS = [
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-only-cn-private.mmdb",
]


def _download_mmdb():
    """Скачивает GeoIP-базу, если её нет локально."""
    for url in MMDB_URLS:
        try:
            safe_print(f"[*] Загрузка GeoIP базы: {url}")
            urllib.request.urlretrieve(url, str(_MMDB_PATH))
            if _MMDB_PATH.exists() and _MMDB_PATH.stat().st_size > 0:
                return True
        except Exception as e:
            safe_print(f"[!] Не удалось загрузить {url}: {e}")
    return False


def _load_geoip():
    global _GEO_READER
    if _GEO_READER is not None:
        return _GEO_READER
    try:
        import maxminddb
    except ImportError:
        safe_print("[!] maxminddb не установлен — страны не определяются")
        return None
    if not _MMDB_PATH.exists():
        _download_mmdb()
    if _MMDB_PATH.exists():
        try:
            _GEO_READER = maxminddb.open_database(str(_MMDB_PATH))
            safe_print(f"[*] GeoIP база загружена: {_MMDB_PATH}")
        except Exception as e:
            safe_print(f"[!] Ошибка загрузки GeoIP базы: {e}")
    return _GEO_READER


def _country_for_ip(ip: Optional[str]) -> str:
    if not ip:
        return ""
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    code = ""
    reader = _load_geoip()
    if reader:
        try:
            resp = reader.get(ip)
            if resp:
                if "country" in resp and "iso_code" in resp["country"]:
                    code = resp["country"]["iso_code"]
                elif "registered_country" in resp and "iso_code" in resp["registered_country"]:
                    code = resp["registered_country"]["iso_code"]
        except Exception:
            pass
    _GEO_CACHE[ip] = code
    return code


def enrich_countries(black, white, black_mtproto, white_mtproto):
    """Дописывает каждому конфигу c['country'] (ISO-код) по его IP."""
    all_cfgs = black + white + black_mtproto + white_mtproto
    total = len(all_cfgs)
    if total == 0:
        return
    safe_print(f"[*] GeoIP: определение стран для {total} конфигов...")

    def _resolve_one(c):
        # Если health-check уже установил IP по реальному соединению — берём его,
        # иначе резолвим хост заново. Это устраняет cfg-NNN у живых конфигов,
        # чей хост не резолвился в момент отдельного обогащения страной.
        ip = c.get("ip")
        if not ip:
            p = c["parsed"]
            host = p.get("address")
            ip = _resolve_ip(host) if host else None
        return c, _country_for_ip(ip)

    # Параллельный DNS-резолв (тысячи хостов последовательно — слишком долго)
    with ThreadPoolExecutor(max_workers=200) as ex:
        for c, code in ex.map(_resolve_one, all_cfgs):
            c["country"] = code

    known = sum(1 for c in all_cfgs if c.get("country"))
    safe_print(f"[*] GeoIP: страны определены для {known}/{total} конфигов")


def _link_with_country(raw: str, country: str, idx: int) -> str:
    """Подставляет страну в #имя ссылки конфига."""
    if "#" in raw:
        base, orig = raw.split("#", 1)
    else:
        base, orig = raw, ""
    label = country_label(country).strip()
    if label and orig:
        name = f"{label} {orig}"
    elif label:
        name = label
    else:
        name = orig
    if not name:
        name = f"cfg-{idx:03d}"
    return f"{base}#{name}"


def _is_valid(parsed):
    """Базовая валидация распарсенного конфига."""
    if not parsed:
        return False
    proto = parsed.get("protocol")
    if proto == "mtproto":
        return bool(parsed.get("raw"))
    addr = parsed.get("address")
    port = parsed.get("port")
    if not addr or not isinstance(port, int) or not (1 <= port <= 65535):
        return False
    if proto == "vless":
        return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                                parsed.get("uuid", "")))
    if proto == "trojan":
        return bool(parsed.get("password"))
    if proto == "hysteria2":
        return bool(parsed.get("auth"))
    if proto == "ss":
        return bool(parsed.get("method")) and bool(parsed.get("password"))
    return False


def _add_link(link, seen_norm, target, mtproto_target, rejected):
    low = link.lower()
    if low.startswith(REJECT_PROTOCOLS):
        rejected["count"] += 1
        return
    norm = normalize_config(link)
    if cfg.get("dedup", True) and norm in seen_norm:
        return
    parsed = config_url_to_parsed(link)
    if parsed is None or not _is_valid(parsed):
        rejected["count"] += 1
        return
    seen_norm.add(norm)
    if parsed["protocol"] == "mtproto":
        mtproto_target.append({"raw": link, "parsed": parsed, "protocol": "mtproto", "verified": False})
    else:
        target.append({"raw": link, "parsed": parsed, "protocol": parsed["protocol"], "verified": False})


def _resolve_ip(host):
    """Разрешает хост в IPv4 (кэшируется). Возвращает None при ошибке."""
    if not host:
        return None
    if host in _RESOLVE_CACHE:
        return _RESOLVE_CACHE[host]
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = None
    _RESOLVE_CACHE[host] = ip
    return ip


def _load_whitelist(url):
    """Загружает whitelist IPv4 из URL (кэшируется). Возвращает set IP."""
    global _WHITELIST_CACHE
    if _WHITELIST_CACHE is not None:
        return _WHITELIST_CACHE
    ips = set()
    if url:
        text = http_get(url, timeout=30)
        if text:
            for line in text.splitlines():
                line = line.strip()
                if line and re.fullmatch(r"[\d.]+", line):
                    ips.add(line)
    _WHITELIST_CACHE = ips
    return ips


def _stage_link(link, seen, staging, rejected):
    """Валидирует ссылку и кладёт в staging без привязки к пулу
       (пул будет определён позже по IP)."""
    norm = normalize_config(link)
    if cfg.get("dedup", True) and norm in seen:
        return
    parsed = config_url_to_parsed(link)
    if parsed is None or not _is_valid(parsed):
        rejected["count"] += 1
        return
    seen.add(norm)
    staging.append({"raw": link, "parsed": parsed, "protocol": parsed["protocol"], "verified": False})


def _ingest_file(filepath, black_list, white_list, black_mtproto, white_mtproto, seen, rejected,
                 staging=None, is_black=None):
    """Строка файла либо HTTP-источник, либо готовая ссылка конфига.

       Если staging=None — конфиги сразу раскладываются по пулам
       (чёрный/белый определяется is_black).
       Если staging задан — все конфиги копятся в staging для последующего
       автоматического распределения (используется для fusion-файлов)."""
    cur_bl = black_list if is_black else white_list
    cur_mt = black_mtproto if is_black else white_mtproto

    for line in _read_lines(filepath):
        low = line.lower()
        if line.startswith(DIRECT_PROTOCOLS):
            # готовая ссылка конфига (vless/trojan/ss/hy2/mtproto)
            links = [line]
        else:
            # всё остальное (в т.ч. https/http-источники) — скачиваем и
            # извлекаем конфиги; неподдерживаемые ссылки дадут 0 конфигов
            text = http_get(line, timeout=30)
            if not text:
                safe_print(f"[!] Источник не загружен ({len(staging) if staging is not None else (len(black_list) + len(white_list))} собрано): {line[:90]}")
                continue
            links = extract_links(text)

        for link in links:
            if staging is not None:
                _stage_link(link, seen, staging, rejected)
            else:
                _add_link(link, seen, cur_bl, cur_mt, rejected)


def _distribute_by_ip(staging, whitelist_ips, black, white, black_mtproto, white_mtproto):
    """Раскладывает staged-конфиги по пулам по наличию их IP в whitelist.
        IP в whitelist -> белый пул, иначе -> чёрный пул. mtproto -> отдельные списки."""
    total = len(staging)

    def _resolve_item(item):
        parsed = item["parsed"]
        host = parsed.get("address")
        ip = _resolve_ip(host) if host else None
        return item, ip

    # Параллельный DNS-резолв (тысячи хостов последовательно — слишком долго)
    with ThreadPoolExecutor(max_workers=200) as ex:
        resolved = list(ex.map(_resolve_item, staging))

    for item, ip in resolved:
        is_white = bool(ip) and ip in whitelist_ips
        parsed = item["parsed"]
        if parsed["protocol"] == "mtproto":
            target = white_mtproto if is_white else black_mtproto
        else:
            target = white if is_white else black
        target.append(item)
    return total


def _as_list(val):
    if not val:
        return []
    if isinstance(val, str):
        return [val]
    return list(val)


def collect_configs():
    """Возвращает (black_proxies, white_proxies, black_mtproto, white_mtproto)."""
    seen = set()
    rejected = {"count": 0}
    black, white, black_mtproto, white_mtproto = [], [], [], []

    # Отдельные источники для чёрного и белого пулов (обычные + mtproto)
    _ingest_file(cfg.get("black_sources", "sources/black.txt"), black, white,
                 black_mtproto, white_mtproto, seen, rejected, is_black=True)
    _ingest_file(cfg.get("white_sources", "sources/white.txt"), black, white,
                 black_mtproto, white_mtproto, seen, rejected, is_black=False)
    _ingest_file(cfg.get("mtproto_black_sources", "sources/mtproto_black.txt"), black, white,
                 black_mtproto, white_mtproto, seen, rejected, is_black=True)
    _ingest_file(cfg.get("mtproto_white_sources", "sources/mtproto_white.txt"), black, white,
                 black_mtproto, white_mtproto, seen, rejected, is_black=False)

    # Fusion-файлы: конфиги собираются в staging и распределяются по IP
    whitelist_ips = _load_whitelist(cfg.get("fusion_whitelist_url"))
    safe_print(f"[*] Загружен whitelist IP: {len(whitelist_ips)} адресов")

    fusion_staging = []
    for fs in _as_list(cfg.get("fusion_sources", [])):
        _ingest_file(fs, black, white, black_mtproto, white_mtproto, seen, rejected,
                     staging=fusion_staging)
    _distribute_by_ip(fusion_staging, whitelist_ips, black, white, black_mtproto, white_mtproto)
    safe_print(f"[*] Fusion (обычный): распределено по IP {len(fusion_staging)} конфигов")

    mfusion_staging = []
    for fs in _as_list(cfg.get("mtproto_fusion_sources", [])):
        _ingest_file(fs, black, white, black_mtproto, white_mtproto, seen, rejected,
                     staging=mfusion_staging)
    _distribute_by_ip(mfusion_staging, whitelist_ips, black, white, black_mtproto, white_mtproto)
    safe_print(f"[*] Fusion (mtproto): распределено по IP {len(mfusion_staging)} конфигов")

    # Импорт выходов RKP_Parser (whitelist -> белый, blacklist -> чёрный)
    if cfg.get("import_rkp"):
        wl = cfg.get("rkp_whitelist")
        bl = cfg.get("rkp_blacklist")
        if wl and Path(wl).exists():
            _ingest_file(wl, black, white, black_mtproto, white_mtproto, seen, rejected, is_black=False)
        if bl and Path(bl).exists():
            _ingest_file(bl, black, white, black_mtproto, white_mtproto, seen, rejected, is_black=True)

    max_c = cfg.get("max_configs", 0)
    if max_c:
        if len(black) > max_c:
            black = black[:max_c]
        if len(white) > max_c:
            white = white[:max_c]

    safe_print(f"[*] Собрано: чёрных прокси {len(black)}, белых прокси {len(white)}, "
                f"mtproto (чёрн {len(black_mtproto)} / бел {len(white_mtproto)}), отбраковано {rejected['count']}")
    return black, white, black_mtproto, white_mtproto


# =============================================================================
# ПРОВЕРКА ЖИВУЧЕСТИ (TCP-connect + TLS/Reality handshake + латентность)
# =============================================================================
def _connect_check(addr, port, timeout, parsed):
    """TCP-connect, а для TLS/Reality/HY2 ещё и TLS-рукопожатие.

    Обычный TCP-connect только проверяет, что порт открыт, — через него
    легко проходят «мёртвые» конфиги (порт есть, а сервиса нет). Рукопожатие
    TLS доказывает, что на другом конце реально поднят нужный протокол.
    Возвращает (ok, latency_ms): latency — время connect+handshake в мс."""
    try:
        start = time.perf_counter()
        sock = socket.create_connection((addr, int(port)), timeout=timeout)
    except Exception:
        return False, None, None
    proto = parsed.get("protocol")
    security = (parsed.get("security") or "").lower()
    needs_tls = False
    sni = None
    if proto == "vless":
        needs_tls = security in ("tls", "reality")
        sni = parsed.get("sni") or parsed.get("address")
    elif proto == "trojan":
        needs_tls = security != "none"
        sni = parsed.get("sni") or parsed.get("address")
    elif proto == "hysteria2":
        needs_tls = True
        sni = parsed.get("sni") or parsed.get("address")
    if needs_tls:
        # handshake получает отдельный бюджет: хотим узнать, что прокси
        # реально работает, даже если он медленный (медленный потом отсеем
        # по латентности, а не по факту «не живой»)
        hs_timeout = max(timeout, 3.0)
        try:
            sock.settimeout(hs_timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname=sni or addr)
            ssock.do_handshake()
            ssock.close()
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return False, None, None
    else:
        try:
            sock.close()
        except Exception:
            pass
    latency_ms = (time.perf_counter() - start) * 1000.0
    ip = None
    try:
        ip = sock.getpeername()[0]
    except Exception:
        pass
    return True, round(latency_ms, 1), ip


def health_check(black, white, black_mtproto, white_mtproto):
    allcfg = black + white + black_mtproto + white_mtproto
    if not cfg.get("health_check", True):
        for c in allcfg:
            c["verified"] = True
            c["latency"] = None
        return
    timeout = cfg.get("health_check_timeout", 4)
    workers = cfg.get("health_check_workers", 200)
    targets = []
    for c in allcfg:
        p = c["parsed"]
        if p.get("address") and p.get("port"):
            targets.append((c, p["address"], p["port"]))
    safe_print(f"[*] Проверка живучести: {len(targets)} конфигов "
               f"(таймаут {timeout}s, TLS-рукопожатие + латентность)...")
    lock = threading.Lock()

    def worker(item):
        c, addr, port = item
        ok, lat, ip = _connect_check(addr, port, timeout, c["parsed"])
        with lock:
            c["verified"] = ok
            c["latency"] = lat
            if ip:
                c["ip"] = ip

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(worker, targets))
    vb = sum(1 for c in black if c["verified"])
    vw = sum(1 for c in white if c["verified"])
    vbm = sum(1 for c in black_mtproto if c["verified"])
    vwm = sum(1 for c in white_mtproto if c["verified"])
    lats = [c["latency"] for c in allcfg if c.get("latency") is not None]
    avg = (sum(lats) / len(lats)) if lats else 0
    safe_print(f"[*] Живых: чёрных {vb}/{len(black)}, белых {vw}/{len(white)}, "
               f"mtproto чёрн {vbm}/{len(black_mtproto)}, бел {vwm}/{len(white_mtproto)}; "
               f"средняя латентность {avg:.0f} ms")


def build_pools(black, white):
    """Формирует пулы подписок.

    - FULL: только живые (прошедшие TCP+TLS-проверку) конфиги. Мёртвые
      выбрасываются полностью — это решает проблему «кучи нерабочих конфигов».
    - LTE/LITE: живые И быстрые (латентность <= latency_threshold). Медленные
      отсеиваются — решает проблему «конфигов с низкой скоростью».
    - full_drop_slow: опционально применять порог скорости и к FULL-пулам.
    """
    thr = float(cfg.get("latency_threshold", 0) or 0)
    full_drop = bool(cfg.get("full_drop_slow", False))

    def ok_cfg(c, apply_thr):
        if not c.get("verified"):
            return False
        if apply_thr and thr > 0 and (c.get("latency") is None or c["latency"] > thr):
            return False
        return True

    pools = {
        "BLACK_FULL": [c for c in black if ok_cfg(c, full_drop)],
        "BLACK_LTE": [c for c in black if ok_cfg(c, True)],
        "WHITE_FULL": [c for c in white if ok_cfg(c, full_drop)],
        "WHITE_LITE": [c for c in white if ok_cfg(c, True)],
    }
    return pools


# =============================================================================
# СПИСКИ ПРАВИЛ (используются напрямую с upstream-URL, без локальной папки rules)
# =============================================================================
def download_rule_lists():
    """Возвращает dict key -> URL списка правил (берётся напрямую у источника).
    Локальная папка rules не нужна: Clash/Mihomo подгружает списки по URL."""
    return {
        "domestic_full": lists.get("domestic_full", ""),
        "domestic_lite": lists.get("domestic_lite", ""),
        "blocked_full": lists.get("blocked_full", ""),
        "blocked_lite": lists.get("blocked_lite", ""),
    }


# =============================================================================
# ГЕНЕРАЦИЯ CLASH YAML
# =============================================================================
def _build_clash_yaml(pool, mode, list_url, list_key):
    proxies = []
    names = []
    for idx, c in enumerate(pool):
        cp = parsed_to_clash_proxy(c["parsed"])
        if not cp:
            continue
        cp["name"] = generate_proxy_name(c["parsed"], idx + 1, c.get("country", ""))
        proxies.append(cp)
        names.append(cp["name"])

    if not names:
        names = ["DIRECT"]

    rule_provider_name = "ru-rules"
    rule_providers = {
        rule_provider_name: {
            "type": "http",
            "behavior": "domain",
            "format": "text",
            "url": list_url,
            "path": f"./{list_key}.txt",
            "interval": 86400,
        }
    }

    rules = []
    if mode == "black":
        # по умолчанию через прокси; отечественное/разрешённое -> DIRECT
        rules.append(f"RULE-SET,{rule_provider_name},DIRECT")
        rules += [
            "GEOIP,RU,DIRECT",
            "DOMAIN-SUFFIX,ru,DIRECT",
            "DOMAIN-SUFFIX,su,DIRECT",
            "DOMAIN-SUFFIX,рф,DIRECT",
            "MATCH,PROXY",
        ]
    else:  # white
        # по умолчанию DIRECT; заблокированное -> через прокси
        rules.append(f"RULE-SET,{rule_provider_name},PROXY")
        rules += [
            "GEOIP,RU,DIRECT",
            "DOMAIN-SUFFIX,ru,DIRECT",
            "DOMAIN-SUFFIX,su,DIRECT",
            "DOMAIN-SUFFIX,рф,DIRECT",
            "MATCH,DIRECT",
        ]

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO", "DIRECT"] + names},
            {"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204",
             "interval": 300, "tolerance": 50, "proxies": names},
        ],
        "rule-providers": rule_providers,
        "rules": rules,
    }
    return config


def _dump_yaml(config: dict) -> str:
    if HAVE_YAML:
        return yaml.safe_dump(config, allow_unicode=True, sort_keys=False, default_flow_style=False)
    # fallback: очень простой дамп
    return json.dumps(config, ensure_ascii=False, indent=2)


def save_clash(name, pool, mode, list_url, list_key):
    out = Path(cfg["output_dir"]) / "CLASH"
    out.mkdir(parents=True, exist_ok=True)
    config = _build_clash_yaml(pool, mode, list_url, list_key)
    text = _dump_yaml(config)
    path = out / f"{name}.yaml"
    path.write_text(text, encoding="utf-8")
    safe_print(f"    CLASH {name}: {len(config['proxies'])} прокси -> {path}")


# =============================================================================
# ГЕНЕРАЦИЯ BASE64 ПОДПИСКИ
# =============================================================================
def save_base64(name, pool):
    out_root = Path(cfg["output_dir"])
    out_b64 = out_root / "BASE64"
    out_b64.mkdir(parents=True, exist_ok=True)
    # только прокси, mtproto — в отдельных файлах; подставляем страну в #имя
    links = [_link_with_country(c["raw"], c.get("country", ""), i + 1) for i, c in enumerate(pool)]
    body = "\n".join(links) + ("\n" if links else "")
    # info-заголовок профиля в начале каждой подписки
    content = _subscription_header(name) + body
    b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    # читаемая (plain) версия — в корень репозитория
    (out_root / f"{name}.txt").write_text(content, encoding="utf-8")
    # base64-версия — в папку BASE64/
    (out_b64 / f"{name}.txt").write_text(b64, encoding="utf-8")
    # убираем устаревший файл старого формата
    stale = out_b64 / f"{name}_links.txt"
    if stale.exists():
        stale.unlink()
    safe_print(f"    BASE64 {name}: {len(links)} ссылок -> {out_b64 / f'{name}.txt'}")


# =============================================================================
# ФАЙЛЫ MTPROTO (отдельно, в корне репозитория)
# =============================================================================
def save_mtproto_files(black_mtproto, white_mtproto):
    out = Path(cfg["output_dir"])
    out.mkdir(parents=True, exist_ok=True)
    # Сохраняем в формате https://t.me/proxy (его понимает Telegram),
    # страну добавляем в #имя (для списков/читаемости; Telegram его игнорирует)
    black_links = "\n".join(
        _link_with_country(c.get("tme") or c["raw"], c.get("country", ""), i + 1)
        for i, c in enumerate(black_mtproto)
    ) + ("\n" if black_mtproto else "")
    white_links = "\n".join(
        _link_with_country(c.get("tme") or c["raw"], c.get("country", ""), i + 1)
        for i, c in enumerate(white_mtproto)
    ) + ("\n" if white_mtproto else "")
    (out / "blacklist.txt").write_text(black_links, encoding="utf-8")
    (out / "whitelist.txt").write_text(white_links, encoding="utf-8")
    safe_print(f"[*] mtproto: blacklist.txt ({len(black_mtproto)}), whitelist.txt ({len(white_mtproto)})")


# =============================================================================
# STATS.JSON
# =============================================================================
def write_stats(pools, black_mtproto, white_mtproto):
    ts = now_str()
    stats = {
        "last_global_update": ts,
        "files": {
            "mtproto": {
                "white_count": len(white_mtproto),
                "black_count": len(black_mtproto),
                "updated": ts,
            }
        },
        "configs": {
            "black": {"count": len(pools["BLACK_FULL"]), "updated": ts},
            "black_lte": {"count": len(pools["BLACK_LTE"]), "updated": ts},
            "white_full": {"count": len(pools["WHITE_FULL"]), "updated": ts},
            "white_lite": {"count": len(pools["WHITE_LITE"]), "updated": ts},
        },
    }
    path = Path(cfg["output_dir"]) / "stats.json"
    path.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    safe_print(f"[*] stats.json записан: {path}")


# =============================================================================
# ЗЕРКАЛИРОВАНИЕ: GitHub (основной) + GitVerse (зеркало) — через PyGithub
# =============================================================================
def _auth_repo_url(repo_url: str, token: str) -> str:
    """Вставляет учётные данные в URL репозитория.

    GitHub принимает токен как логин (https://<token>@github.com/...),
    GitVerse — по схеме oauth2 (https://oauth2:<token>@gitverse.ru/...).
    """
    p = urllib.parse.urlparse(repo_url)
    if "gitverse" in p.netloc:
        netloc = f"oauth2:{token}@{p.netloc}"
    else:
        netloc = f"{token}@{p.netloc}"
    path = p.path
    if not path.endswith(".git"):
        path = path + ".git"
    return urllib.parse.urlunparse((p.scheme, netloc, path, "", "", ""))


def _run_git(args, cwd, timeout=120):
    return subprocess.run(
        args, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=timeout,
    )


def _push_remote(label, remote_cfg, token_env):
    """Пушит результаты в удалённый репозиторий через git (clone → commit → push).

    Этот способ не зависит от REST API хостинга (в частности, у GitVerse
    GitHub-совместимый API недоступен по адресу api.gitverse.ru, откуда
    всегда приходил 400), а коммит всегда делается ПОВЕРХ актуального
    удалённого tip'а, поэтому push является fast-forward и не вызывает
    ошибку 422 «Update is not a fast forward». При редком race (другой пуш
    между clone и push) делается повторная попытка."""
    if not remote_cfg or not remote_cfg.get("enabled"):
        safe_print(f"[i] {label}: отключён")
        return False
    token = os.environ.get(token_env, "")
    repo_url = remote_cfg.get("repo_url", "")
    branch = remote_cfg.get("branch", "main")
    local = Path(cfg.get("output_dir")).resolve()

    if not token:
        safe_print(f"[!] {label}: не задан токен ({token_env})")
        return False
    if not repo_url:
        safe_print(f"[!] {label}: repo_url не задан")
        return False

    auth_url = _auth_repo_url(repo_url, token)

    # Собираем локальные файлы с путями относительно корня репозитория
    files = []  # (repo_path, content)
    for name in ("BLACK_FULL", "BLACK_LTE", "WHITE_FULL", "WHITE_LITE"):
        p = local / f"{name}.txt"
        if p.exists():
            files.append((f"{name}.txt", p.read_text(encoding="utf-8")))
    for p in sorted((local / "BASE64").glob("*.txt")):
        files.append((f"BASE64/{p.name}", p.read_text(encoding="utf-8")))
    for p in sorted((local / "CLASH").glob("*.yaml")):
        files.append((f"CLASH/{p.name}", p.read_text(encoding="utf-8")))
    for mf in ("whitelist.txt", "blacklist.txt", "stats.json"):
        p = local / mf
        if p.exists():
            files.append((mf, p.read_text(encoding="utf-8")))

    if not files:
        safe_print(f"[i] {label}: нет файлов для пуша")
        return True

    # Устаревшие «плоские» копии прошлых версий, которые больше не генерируем
    stale_names = []
    for name in ("BLACK_FULL", "BLACK_LTE", "WHITE_FULL", "WHITE_LITE"):
        stale_names += [f"{name}_links.txt", f"{name}.yaml"]

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        with tempfile.TemporaryDirectory(prefix=f"{label}_") as tmp_dir:
            clone_dir = os.path.join(tmp_dir, "repo")
            try:
                clone = _run_git(
                    ["git", "clone", "--depth", "1", "--branch", branch, auth_url, clone_dir],
                    tmp_dir,
                )
                if clone.returncode != 0:
                    stderr = clone.stderr.lower()
                    if ("empty repository" in stderr or "couldn't find remote ref" in stderr
                            or "remote head" in stderr):
                        # Репозиторий пустой — инициализируем локально
                        os.makedirs(clone_dir, exist_ok=True)
                        init = _run_git(["git", "init", "-b", branch], clone_dir)
                        if init.returncode != 0:
                            _run_git(["git", "init"], clone_dir)
                            _run_git(["git", "checkout", "-b", branch], clone_dir)
                        _run_git(["git", "remote", "add", "origin", auth_url], clone_dir)
                    else:
                        if attempt == max_attempts:
                            safe_print(f"[!] {label}: ошибка clone: {clone.stderr.strip()[:400]}")
                        continue

                _run_git(["git", "config", "user.name", "v2ray-collector-bot"], clone_dir)
                _run_git(["git", "config", "user.email",
                          "v2ray-collector-bot@users.noreply.github.com"], clone_dir)

                for rel_path, content in files:
                    abs_path = os.path.join(clone_dir, rel_path)
                    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
                    with open(abs_path, "w", encoding="utf-8") as f:
                        f.write(content)

                # Удаляем устаревшие файлы (если они остались в репозитории)
                for stale in stale_names:
                    sp = os.path.join(clone_dir, stale)
                    if os.path.exists(sp):
                        os.remove(sp)

                _run_git(["git", "add", "-A"], clone_dir)
                status = _run_git(["git", "status", "--porcelain"], clone_dir)
                if not status.stdout.strip():
                    safe_print(f"[i] {label}: изменений нет, пуш не требуется")
                    return True

                commit = _run_git(
                    ["git", "commit", "-m", f"update {now_str()}"],
                    clone_dir,
                )
                if commit.returncode != 0:
                    safe_print(f"[!] {label}: ошибка commit: {commit.stderr.strip()[:400]}")
                    return False

                push = _run_git(["git", "push", "origin", branch], clone_dir)
                if push.returncode == 0:
                    safe_print(f"[*] {label}: обновлён ({len(files)} файлов) -> {repo_url}")
                    return True

                err = push.stderr.lower()
                if "non-fast-forward" in err or "rejected" in err or "fetch first" in err:
                    # Race с другим пушем — повторим с чистого clone
                    safe_print(f"[!] {label}: попытка {attempt}/{max_attempts} отклонена "
                               f"(non-fast-forward), повторяем...")
                    continue
                safe_print(f"[!] {label}: ошибка push: {push.stderr.strip()[:400]}")
                return False
            except subprocess.TimeoutExpired:
                safe_print(f"[!] {label}: попытка {attempt}/{max_attempts} — превышен таймаут git")
            except Exception as e:
                safe_print(f"[!] {label}: ошибка пуша: {e}")
                return False

    safe_print(f"[!] {label}: не удалось запушить за {max_attempts} попыток")
    return False


def mirror_all():
    """GitHub — основной репозиторий, GitVerse — зеркало."""
    _push_remote("GitHub", cfg.get("github"), "GITHUB_TOKEN")
    _push_remote("GitVerse", cfg.get("git"), "GITVERSE_TOKEN")


# =============================================================================
# УВЕДОМЛЕНИЕ В TELEGRAM
# =============================================================================
def notify_telegram(text: str):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("TELEGRAM_CHANNEL_ID")
    if not token or not chat:
        safe_print("[i] Telegram не настроен (нет TELEGRAM_BOT_TOKEN / TELEGRAM_CHANNEL_ID)")
        return
    url = (
        f"https://api.telegram.org/bot{token}/sendMessage"
        f"?chat_id={urllib.parse.quote(chat)}"
        f"&text={urllib.parse.quote(text)}"
        f"&parse_mode=Markdown"
    )
    r = http_get(url, timeout=20)
    if r is None or '"ok":false' in (r or "") or '"ok": false' in (r or ""):
        safe_print("[!] Не удалось отправить уведомление в Telegram")
    else:
        safe_print("[*] Уведомление в Telegram отправлено")
