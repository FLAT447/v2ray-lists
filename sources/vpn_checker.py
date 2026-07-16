import sys
import os
import re
import json
import base64
import logging
import asyncio
import ipaddress
import random
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import List, Set, Dict, Tuple, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
import requests
from github import Github, Auth, InputGitTreeElement
from async_lru import alru_cache
import maxminddb

# ============================================================================
# НАСТРОЙКА ЛОГИРОВАНИЯ И ГЛОБАЛЬНЫЕ ПАТТЕРНЫ
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vpn_collector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

INSECURE_PATTERN = re.compile(r'(?:allowinsecure|allow_insecure|insecure)[%3B]*=(?:1|true|yes)', re.IGNORECASE)
ALLOWED_FPS = ['qq', 'firefox', 'edge']

CLOUDFLARE_NETWORKS = [
    ipaddress.ip_network("173.245.48.0/20"), ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"), ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"), ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"), ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"), ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"), ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"), ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22")
]

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

@alru_cache(maxsize=8192)
async def _global_resolve_doh(hostname: str, servers: Tuple[str, ...]) -> Optional[str]:
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) or ":" in hostname:
        return hostname
    async def fetch_dns(session: aiohttp.ClientSession, provider: str) -> Optional[str]:
        try:
            params = {"name": hostname, "type": "A"}
            async with session.get(provider, params=params, headers={"accept": "application/dns-json"}, timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if "Answer" in data:
                        for ans in data["Answer"]:
                            if ans.get("type") == 1:
                                return ans["data"]
        except Exception:
            pass
        return None
    async with aiohttp.ClientSession() as session:
        for provider in servers:
            res = await fetch_dns(session, provider)
            if res:
                return res
    return None

def _is_cloudflare_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip('[]'))
        return any(ip_obj in net for net in CLOUDFLARE_NETWORKS)
    except Exception:
        return False

# ============================================================================
# ФУНКЦИИ ВАЛИДАЦИИ И ПАРСИНГА
# ============================================================================

def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    if re.match(r'^[\d.]+$', domain) or ":" in domain:
        return False
    return re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', domain.lower()) is not None

def _is_valid_host(host: str) -> bool:
    if not host:
        return False
    clean_host = host.strip('[]')
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass
    return _is_valid_domain(clean_host)

def _normalize_url_delimiters(config_url: str) -> str:
    cleaned = config_url.replace('&amp%3B', '&').replace('&amp;', '&').replace('%3B', '&')
    cleaned = re.sub(r'[?&]type=raw(&|$)', r'\1', cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.replace('?&', '?')
    if cleaned.endswith('?'):
        cleaned = cleaned[:-1]
    return cleaned

def _force_update_fp_in_url(config_url: str, new_fp: str) -> str:
    try:
        cleaned_url = _normalize_url_delimiters(config_url)
        parsed = urlparse(cleaned_url)
        query_params = parse_qs(parsed.query)
        query_params['fp'] = [new_fp]
        if 'client-fingerprint' in query_params:
            del query_params['client-fingerprint']
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    except Exception:
        return config_url

def parse_config(config: str) -> Tuple[str, int, str]:
    host, port, sni = '', 0, ''
    try:
        config = config.strip()
        if not config:
            return host, port, sni
        if config.startswith('vmess://'):
            rem = config[8:].split('#')[0].strip()
            if '?' in rem or '@' in rem or (':' in rem and not rem.replace(':', '').isalnum()):
                parsed = urlparse(config)
                netloc = parsed.netloc
                host_port = netloc.rsplit('@', 1)[1] if '@' in netloc else netloc
                if host_port.startswith('['):
                    end_bracket = host_port.find(']')
                    if end_bracket != -1:
                        host = host_port[1:end_bracket]
                        port_part = host_port[end_bracket + 1:]
                        if port_part.startswith(':'):
                            port = int(port_part.split(':')[1].split('?')[0])
                else:
                    if ':' in host_port:
                        host, port_str = host_port.split(':', 1)
                        port = int(port_str.split('?')[0])
                    else:
                        host = host_port
                query_params = parse_qs(parsed.query)
                sni = query_params.get('sni', [''])[0] or query_params.get('peer', [''])[0] or query_params.get('host', [''])[0]
                return host.lower(), port, sni.lower()
            else:
                b64_str = rem + "=" * ((4 - len(rem) % 4) % 4)
                data = json.loads(base64.b64decode(b64_str).decode('utf-8', errors='ignore'))
                host = str(data.get('add', ''))
                port = int(data.get('port', 0))
                sni = str(data.get('sni', '') or data.get('host', ''))
                return host.lower(), port, sni.lower()

        parsed = urlparse(config)
        netloc = parsed.netloc
        host_port = netloc.rsplit('@', 1)[1] if '@' in netloc else netloc
        if host_port.startswith('['):
            end_bracket = host_port.find(']')
            if end_bracket != -1:
                host = host_port[1:end_bracket]
                port_part = host_port[end_bracket + 1:]
                if port_part.startswith(':'):
                    port = int(port_part.split(':')[1].split('?')[0])
        else:
            if ':' in host_port:
                host, port_str = host_port.split(':', 1)
                port = int(port_str.split('?')[0])
            else:
                host = host_port
        query_params = parse_qs(parsed.query)
        sni = query_params.get('sni', [''])[0] or query_params.get('peer', [''])[0]
        return host.lower(), port, sni.lower()
    except Exception:
        return '', 0, ''

def validate_config(config: str, host: str, port: int, sni: str) -> bool:
    if not host or port <= 0 or port > 65535:
        return False
    if not _is_valid_host(host):
        return False
    if sni and not _is_valid_domain(sni):
        return False
    return True

# ============================================================================
# ТЕСТ ДОСТУПНОСТИ СЕРВЕРА ПО TCP (TCP PING)
# ============================================================================

async def _tcp_ping(host: str, port: int, timeout: float = 3.0) -> bool:
    """Проверка TCP-доступности сервера напрямую (host:port)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

# ============================================================================
# ВАЛИДАТОР ДОСТУПНОСТИ СЕРВЕРА (TCP PING, БЕЗ SING-BOX)
# ============================================================================

class TcpPingValidator:
    """Проверяет доступность конфигов простым TCP-подключением к host:port,
    без использования sing-box и без HTTP-запросов через туннель."""

    def __init__(self, max_concurrent: int = 200):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.stat_tcp_ping_fail = 0
        self.stat_success = 0
        self._sample_logged = 0

    async def check(self, host: str, port: int) -> bool:
        async with self.semaphore:
            ok = await _tcp_ping(host, port)
            if ok:
                self.stat_success += 1
            else:
                self.stat_tcp_ping_fail += 1
                if self._sample_logged < 10:
                    self._sample_logged += 1
                    logger.warning(f"[SAMPLE] TCP Ping не прошёл до {host}:{port}")
            return ok

class TelegramNotifier:
    def __init__(self, token: str, chat_id: str, channel_id: str = None):
        self.token = token
        self.chat_id = chat_id
        self.channel_id = channel_id
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_message(self, text: str, is_report: bool = False):
        if is_report and self.channel_id:
            tz_msk = timezone(timedelta(hours=3))
            time_str = datetime.now(tz_msk).strftime("%H:%M | %d.%m.%Y")
            total_configs = sum(int(''.join(filter(str.isdigit, line)) or 0) for line in text.split('\n') if any(k in line for k in ['black', 'white_full', 'white_lite']))
            channel_text = (
                f"🔄 V2Ray подписки обновлены!\n📅 Время: {time_str}\n📊 Всего конфигураций: {total_configs}\n\n"
                f"📦 <a href=\"https://github.com/FLAT447/v2ray-lists\">Репозиторий проекта</a>\n⚡ <a href=\"https://flat447.github.io/v2ray-lists-site\">Сайт проекта</a>"
            )
            payload = {"chat_id": self.channel_id, "text": channel_text, "parse_mode": "HTML", "disable_web_page_preview": True}
        else:
            payload = {"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown", "disable_web_page_preview": True}
        try: requests.post(self.api_url, json=payload, timeout=10)
        except Exception as e: logger.error(f"Telegram error: {e}")

class GithubManager:
    def __init__(self, token: str):
        auth = Auth.Token(token)
        self.gh = Github(auth=auth)
        self.repo_name = os.getenv('GITHUB_REPOSITORY', 'FLAT447/v2ray-lists')

    def _push_sync(self, files: Dict[str, str]) -> bool:
        try:
            repo = self.gh.get_repo(self.repo_name)
            ref = repo.get_git_ref("heads/main")
            old_commit = repo.get_git_commit(ref.object.sha)
            base_tree = repo.get_git_tree(old_commit.tree.sha)

            if 'stats.json' in files:
                try:
                    contents = repo.get_contents('stats.json')
                    old_data = json.loads(contents.decoded_content.decode('utf-8'))
                except Exception: old_data = {}
                try: old_data['configs'] = json.loads(files['stats.json'])
                except Exception: old_data['configs'] = files['stats.json']
                files['stats.json'] = json.dumps(old_data, indent=2, ensure_ascii=False)

            element_list = []
            for path, content in files.items():
                element_list.append(InputGitTreeElement(path=path, mode='100644', type='blob', content=content))

            tree = repo.create_git_tree(element_list, base_tree)
            time_str_msk = datetime.now(timezone(timedelta(hours=3))).strftime("%d.%m.%Y %H:%M:%S MSK")

            new_commit = repo.create_git_commit(f"🔄 Автоматическое обновление подписок [{time_str_msk}]", tree, [old_commit])
            ref.edit(new_commit.sha)
            logger.info("⚡ Все файлы успешно синхронизированы с GitHub.")
            return True
        except Exception as e:
            logger.error(f"GitHub Manager критический сбой API: {str(e)}", exc_info=True)
            return False

    async def push_files(self, files: Dict[str, str]) -> bool:
        return await asyncio.to_thread(self._push_sync, files)

class GitVerseManager:
    def __init__(self, token: Optional[str], repo: Optional[str],
                 host: str = "gitverse.ru", branch: str = "main"):
        self.token = token
        self.repo = repo
        self.host = host
        self.branch = branch
        self.enabled = bool(token and repo)
        if not self.enabled:
            logger.warning("⚠️ GitVerse: GITVERSE_TOKEN не заданы — синхронизация с GitVerse отключена.")

    def _run(self, args: List[str], cwd: str, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            args, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=120
        )

    def _push_sync(self, files: Dict[str, str]) -> bool:
        if not self.enabled:
            return False

        remote_url = f"https://oauth2:{self.token}@{self.host}/{self.repo}.git"
        safe_remote_for_log = f"https://{self.host}/{self.repo}.git"

        with tempfile.TemporaryDirectory(prefix="gitverse_") as tmp_dir:
            clone_dir = os.path.join(tmp_dir, "repo")
            try:
                clone_res = self._run(
                    ["git", "clone", "--depth", "1", remote_url, clone_dir],
                    cwd=tmp_dir
                )

                repo_is_empty = False

                if clone_res.returncode != 0:
                    stderr_low = clone_res.stderr.lower()
                    if "you appear to have cloned an empty repository" in stderr_low or \
                       "remote head" in stderr_low or \
                       "couldn't find remote ref" in stderr_low:
                        repo_is_empty = True
                        logger.warning(
                            f"GitVerse: похоже, репозиторий {safe_remote_for_log} пустой "
                            f"(нет коммитов/веток). Инициализируем локально."
                        )
                    else:
                        logger.error(
                            f"GitVerse: ошибка клонирования {safe_remote_for_log}: "
                            f"{clone_res.stderr.strip()[:500]}"
                        )
                        return False

                if repo_is_empty:
                    os.makedirs(clone_dir, exist_ok=True)
                    init_res = self._run(["git", "init", "-b", self.branch], cwd=clone_dir)
                    if init_res.returncode != 0:
                        init_res = self._run(["git", "init"], cwd=clone_dir)
                        if init_res.returncode != 0:
                            logger.error(f"GitVerse: ошибка git init: {init_res.stderr.strip()[:500]}")
                            return False
                        self._run(["git", "checkout", "-b", self.branch], cwd=clone_dir)
                    self._run(["git", "remote", "add", "origin", remote_url], cwd=clone_dir)
                else:
                    checkout_res = self._run(["git", "checkout", self.branch], cwd=clone_dir)
                    if checkout_res.returncode != 0:
                        checkout_res = self._run(["git", "checkout", "-b", self.branch], cwd=clone_dir)
                        if checkout_res.returncode != 0:
                            logger.error(
                                f"GitVerse: не удалось переключиться на ветку '{self.branch}': "
                                f"{checkout_res.stderr.strip()[:500]}"
                            )
                            return False

                self._run(["git", "config", "user.name", "v2ray-collector-bot"], cwd=clone_dir)
                self._run(["git", "config", "user.email", "v2ray-collector-bot@users.noreply.gitverse.ru"], cwd=clone_dir)

                for rel_path, content in files.items():
                    abs_path = os.path.join(clone_dir, rel_path)
                    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
                    with open(abs_path, 'w', encoding='utf-8') as f:
                        f.write(content)

                self._run(["git", "add", "-A"], cwd=clone_dir)

                status_res = self._run(["git", "status", "--porcelain"], cwd=clone_dir)
                if not status_res.stdout.strip():
                    logger.info("ℹ️ GitVerse: изменений нет, коммит не требуется.")
                    return True

                time_str_msk = datetime.now(timezone(timedelta(hours=3))).strftime("%d.%m.%Y %H:%M:%S MSK")
                commit_res = self._run(
                    ["git", "commit", "-m", f"🔄 Автоматическое обновление подписок [{time_str_msk}]"],
                    cwd=clone_dir
                )
                if commit_res.returncode != 0:
                    logger.error(f"GitVerse: ошибка коммита: {commit_res.stderr.strip()[:500]}")
                    return False

                push_res = self._run(["git", "push", "-u", "origin", self.branch], cwd=clone_dir)
                if push_res.returncode != 0:
                    logger.error(f"GitVerse: ошибка push в {safe_remote_for_log}: {push_res.stderr.strip()[:500]}")
                    return False

                logger.info(f"⚡ GitVerse: файлы успешно запушены в {safe_remote_for_log} ({self.branch}).")
                return True
            except subprocess.TimeoutExpired:
                logger.error("GitVerse: операция git превысила лимит времени.")
                return False
            except Exception as e:
                logger.error(f"GitVerse: критический сбой синхронизации: {e}", exc_info=True)
                return False

    async def push_files(self, files: Dict[str, str]) -> bool:
        return await asyncio.to_thread(self._push_sync, files)

class ConfigFetcher:
    def __init__(self):
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        self.sources: List[str] = []

        try:
            with open('sources/subscriptions.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        self.sources.append(url)
            logger.info(f"✅ Успешно загружено {len(self.sources)} ссылок на подписки из subscriptions.txt")
        except FileNotFoundError:
            logger.error("❌ Файл subscriptions.txt не найден в текущей директории!")
        except Exception as e:
            logger.error(f"❌ Ошибка при чтении файла subscriptions.txt: {e}")

    async def fetch_source(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        try:
            async with session.get(url, headers=self.headers, timeout=15) as response:
                if response.status == 200:
                    text = await response.text()
                    text_stripped = text.strip()
                    if text_stripped and not any(text_stripped.startswith(p) for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria', 'tuic://', '#']):
                        try:
                            cleaned_b64 = "".join(text_stripped.split()) + "=" * ((4 - len(text_stripped.strip()) % 4) % 4)
                            decoded = base64.b64decode(cleaned_b64).decode('utf-8', errors='ignore')
                            if any(p in decoded for p in ['://', 'vless://', 'vmess://']): text = decoded
                        except Exception: pass
                    configs = []
                    for line in text.splitlines():
                        line_stripped = line.strip()
                        if not line_stripped or line_stripped.startswith('#') or '://' not in line_stripped: continue
                        if INSECURE_PATTERN.search(_normalize_url_delimiters(line_stripped)): continue
                        configs.append(line_stripped)
                    return configs
                return []
        except Exception: return []

    async def fetch_all_configs(self) -> List[str]:
        all_configs = []
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_source(session, url) for url in self.sources]
            results = await asyncio.gather(*tasks)
            for config_list in results: all_configs.extend(config_list)

        unique_nodes = {}
        for cfg in all_configs:
            host, port, _ = parse_config(cfg)
            if host and port:
                key = f"{host}:{port}"
                if key not in unique_nodes:
                    unique_nodes[key] = cfg
        return list(unique_nodes.values())

class ConfigPinger:
    def __init__(self):
        self.tcp_validator = TcpPingValidator()
        self._unsupported_count = 0
        self._total_checked = 0

    async def _check_config(self, config: str) -> Optional[str]:
        host, port, sni = parse_config(config)
        if not validate_config(config, host, port, sni): return None

        self._total_checked += 1
        if await self.tcp_validator.check(host, port):
            return config
        return None

    async def ping_configs(self, configs: List[str]) -> List[str]:
        logger.info(f"Проверка {len(configs)} уникальных серверов (TCP Ping)...")
        tasks = [self._check_config(cfg) for cfg in configs]
        results = await asyncio.gather(*tasks)
        res = [r for r in results if r is not None]
        v = self.tcp_validator
        logger.info(f"Успешно прошли валидацию: {len(res)} из {self._total_checked} проверенных")
        logger.info(
            f"📊 Диагностика причин провала: "
            f"tcp_ping_fail={v.stat_tcp_ping_fail}, "
            f"success={v.stat_success}"
        )
        return res

class ConfigFilter:
    def __init__(self):
        self.doh_servers = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")

    async def filter_configs(self, configs: List[str], whitelist_sni: Set[str], whitelist_cidr: List[str]) -> Tuple[List[str], List[str], List[str]]:
        white, black_lte, black = [], [], []
        sni_set = {s.lower().strip() for s in whitelist_sni if s.strip()}
        networks = [ipaddress.ip_network(n.strip(), strict=False) for n in whitelist_cidr if n.strip()]

        async def process_single(config: str):
            host, port, sni = parse_config(config)
            resolved_ip = await _global_resolve_doh(host, self.doh_servers)

            if resolved_ip and _is_cloudflare_ip(resolved_ip):
                return None

            is_ip_whitelisted = False
            if resolved_ip:
                try:
                    ip_obj = ipaddress.ip_address(resolved_ip.strip('[]'))
                    is_ip_whitelisted = any(ip_obj in net for net in networks)
                except Exception: pass

            is_sni_whitelisted = bool(sni) and sni in sni_set
            return config, is_ip_whitelisted, is_sni_whitelisted

        tasks = [process_single(cfg) for cfg in configs]
        results = await asyncio.gather(*tasks)

        for res in results:
            if not res: continue
            cfg, is_ip_w, is_sni_w = res
            if is_ip_w: white.append(cfg)
            elif is_sni_w: black_lte.append(cfg)
            else: black.append(cfg)
        return white, black_lte, black

# ============================================================================
# ЗАГРУЗКА MMDB И ГЕОIP-РАЗРЕШЕНИЕ
# ============================================================================

MMDB_URLS = [
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-only-cn-private.mmdb",
]

async def _download_mmdb(db_path: str = 'country.mmdb') -> bool:
    for url in MMDB_URLS:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=60) as resp:
                    if resp.status == 200:
                        with open(db_path, 'wb') as f:
                            f.write(await resp.read())
                        logger.info(f"✅ GeoIP база загружена: {db_path}")
                        return True
        except Exception as e:
            logger.warning(f"⚠️ Не удалось загрузить {url}: {e}")
    logger.error("❌ Не удалось загрузить GeoIP базу ни с одного источника")
    return False

class GeoIPResolver:
    def __init__(self, db_path: str = 'country.mmdb'):
        self.db_path = db_path
        self.reader = None
        if os.path.exists(db_path):
            try:
                self.reader = maxminddb.open_database(db_path)
                logger.info(f"✅ GeoIP база загружена: {db_path}")
            except Exception as e:
                logger.error(f"❌ Ошибка загрузки GeoIP базы: {e}")

    def lookup(self, ip: str) -> Optional[str]:
        if not self.reader:
            return None
        try:
            response = self.reader.get(ip)
            if response:
                if 'country' in response and 'iso_code' in response['country']:
                    return response['country']['iso_code']
                if 'registered_country' in response and 'iso_code' in response['registered_country']:
                    return response['registered_country']['iso_code']
        except Exception:
            pass
        return None

    def close(self):
        if self.reader:
            self.reader.close()

class VPNConfigCollector:
    def __init__(self):
        self.config_fetcher = ConfigFetcher()
        self.config_filter = ConfigFilter()
        self.config_pinger = ConfigPinger()
        self.github_manager = GithubManager(os.getenv('GITHUB_TOKEN'))
        self.gitverse_manager = GitVerseManager(
            os.getenv('GITVERSE_TOKEN'),
            os.getenv('GITVERSE_REPOSITORY', 'FLAT447/my-repo'),
            host=os.getenv('GITVERSE_HOST', 'gitverse.ru'),
            branch=os.getenv('GITVERSE_BRANCH', 'main')
        )
        t_token, t_chat, t_chan = os.getenv('TELEGRAM_BOT_TOKEN'), os.getenv('TELEGRAM_CHAT_ID'), os.getenv('TELEGRAM_CHANNEL_ID')
        self.notifier = TelegramNotifier(t_token, t_chat, t_chan) if t_token and t_chat else None

    def _clean_config(self, config: str) -> str:
        return config.split('#')[0].strip() if "#" in config and '://' in config.split('#')[0] else config.strip()

    def _generate_subscription_content(self, title: str, configs: List[str], config_countries: Dict[str, str] = None) -> str:
        meta = [
            f"#announce: 🔰 Нажми на спидометр или молнию, чтобы проверить соединение. Меньше ms - лучше | n/a - не работает. Если ВПН плохо работает, то нажмите на 🔄️.",
            f"#profile-web-page-url: https://flat447.github.io/v2ray-lists-site",
            f"#profile-title: {title}", f"#support-url: https://t.me/flat447", f"#profile-update-interval: 1\n"
        ]
        cleaned_configs = []
        for index, cfg in enumerate(configs, start=1):
            clean_key = self._clean_config(cfg)
            if not clean_key:
                continue

            clean_with_fp = _force_update_fp_in_url(clean_key, random.choice(ALLOWED_FPS))

            country_code = config_countries.get(clean_key, '') if config_countries else ''
            flag = _code_to_flag(country_code) if country_code else ''
            country_name = COUNTRY_NAMES_RU.get(country_code, '') if country_code else ''
            prefix = f"{flag} {country_name} " if flag else ''

            display_name = f"{prefix}{title.replace('V2Ray Lists - ', '')} [{index}]"
            final_line = f"{clean_with_fp}#{display_name}"
            cleaned_configs.append(final_line)

        return '\n'.join(meta + cleaned_configs)

    async def _batch_http_geoip(self, ips: List[str]) -> Dict[str, Optional[str]]:
        """Fallback GeoIP через ip-api.com batch API (free, 45 req/min, batch до 100 IP)."""
        result = {}
        valid_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip.strip('[]'))
                valid_ips.append(ip.strip('[]'))
            except ValueError:
                pass
        if not valid_ips:
            return result

        for i in range(0, len(valid_ips), 100):
            batch = valid_ips[i:i + 100]
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        'http://ip-api.com/batch',
                        json=batch,
                        headers={'Content-Type': 'application/json'},
                        timeout=15
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for entry in data:
                                ip = entry.get('query', '')
                                if entry.get('status') == 'success':
                                    result[ip] = entry.get('countryCode', '')
            except Exception as e:
                logger.warning(f"HTTP GeoIP batch failed (batch {i // 100}): {e}")
        return result

    async def run(self):
        tz_msk = timezone(timedelta(hours=3))
        start_time = datetime.now(tz_msk)
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            sni_res = requests.get('https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt', headers=headers, timeout=20)
            whitelist_sni = {line.strip() for line in sni_res.text.splitlines() if line.strip() and not line.startswith('#')}
            cidr_res = requests.get('https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt', headers=headers, timeout=20)
            whitelist_cidr = [line.strip() for line in cidr_res.text.splitlines() if line.strip() and not line.startswith('#')]

            all_configs = await self.config_fetcher.fetch_all_configs()
            if not all_configs: return

            alive_configs = await self.config_pinger.ping_configs(all_configs)

            # --- GeoIP resolution (maxminddb + HTTP fallback) ---
            config_countries = {}
            need_http_fallback = True

            if not os.path.exists('country.mmdb'):
                await _download_mmdb()
            geo_resolver = GeoIPResolver()
            if geo_resolver.reader:
                logger.info(f"🌍 Начинаем GeoIP-резолвинг (maxminddb) для {len(alive_configs)} конфигов...")
                for cfg in alive_configs:
                    host, _, _ = parse_config(cfg)
                    ip = await _global_resolve_doh(host, self.config_filter.doh_servers)
                    if ip:
                        code = geo_resolver.lookup(ip)
                        if code:
                            config_countries[self._clean_config(cfg)] = code
                            logger.debug(f"GeoIP: {host} -> {ip} -> {code}")
                logger.info(f"🌍 GeoIP (maxminddb): найдено {len(config_countries)} стран для {len(alive_configs)} живых конфигов")

                if len(config_countries) > 0:
                    need_http_fallback = False
                geo_resolver.close()
            else:
                logger.warning("⚠️ GeoIP: база не загружена, страны не будут определены через mmdb")

            # --- HTTP fallback GeoIP ---
            # Если maxminddb не дал результатов (или вообще недоступен) — используем ip-api.com
            if need_http_fallback or len(config_countries) < len(alive_configs):
                logger.info(f"🌍 Запускаем HTTP GeoIP fallback для конфигов без страны...")
                unresolved_cfgs = [cfg for cfg in alive_configs if self._clean_config(cfg) not in config_countries]
                if unresolved_cfgs:
                    # Собираем уникальные IP для всех неразрешённых конфигов
                    ip_to_cfgs: Dict[str, List[str]] = {}
                    for cfg in unresolved_cfgs:
                        host, _, _ = parse_config(cfg)
                        ip = await _global_resolve_doh(host, self.config_filter.doh_servers)
                        if ip:
                            clean_ip = ip.strip('[]')
                            ip_to_cfgs.setdefault(clean_ip, []).append(cfg)

                    if ip_to_cfgs:
                        http_results = await self._batch_http_geoip(list(ip_to_cfgs.keys()))
                        resolved_count = 0
                        for clean_ip, code in http_results.items():
                            if code:
                                for cfg in ip_to_cfgs.get(clean_ip, []):
                                    config_countries[self._clean_config(cfg)] = code
                                    resolved_count += 1
                        logger.info(f"🌍 HTTP GeoIP fallback: resolved {resolved_count} конфигов")

            logger.info(f"🌍 Итого GeoIP: определены страны для {len(config_countries)} из {len(alive_configs)} конфигов")

            white_full, black_lte, black = await self.config_filter.filter_configs(alive_configs, whitelist_sni, whitelist_cidr)
            white_lite = white_full[:500]
            current_time_str = datetime.now(tz_msk).strftime("%H:%M | %d.%m.%Y")

            stats = {
                "black": {"count": len(black), "updated": current_time_str}, "black_lte": {"count": len(black_lte), "updated": current_time_str},
                "white_full": {"count": len(white_full), "updated": current_time_str}, "white_lite": {"count": len(white_lite), "updated": current_time_str}
            }

            black_txt = self._generate_subscription_content('V2Ray Lists - BLACK FULL', black, config_countries)
            black_lte_txt = self._generate_subscription_content('V2Ray Lists - BLACK LTE', black_lte, config_countries)
            white_full_txt = self._generate_subscription_content('V2Ray Lists - WHITE FULL', white_full, config_countries)
            white_lite_txt = self._generate_subscription_content('V2Ray Lists - WHITE LITE', white_lite, config_countries)

            files_to_push = {
                'BLACK_FULL.txt': black_txt,
                'BLACK_LTE.txt': black_lte_txt,
                'WHITE_FULL.txt': white_full_txt,
                'WHITE_LITE.txt': white_lite_txt,
                'BASE64/BLACK_FULL.txt': base64.b64encode(black_txt.encode('utf-8')).decode('utf-8'),
                'BASE64/BLACK_LTE.txt': base64.b64encode(black_lte_txt.encode('utf-8')).decode('utf-8'),
                'BASE64/WHITE_FULL.txt': base64.b64encode(white_full_txt.encode('utf-8')).decode('utf-8'),
                'BASE64/WHITE_LITE.txt': base64.b64encode(white_lite_txt.encode('utf-8')).decode('utf-8'),
                'stats.json': json.dumps(stats, indent=2, ensure_ascii=False)
            }

            files_for_gitverse = dict(files_to_push)

            github_result, gitverse_result = await asyncio.gather(
                self.github_manager.push_files(files_to_push),
                self.gitverse_manager.push_files(files_for_gitverse),
                return_exceptions=True
            )

            if isinstance(github_result, Exception):
                logger.error(f"GitHub push исключение: {github_result}", exc_info=True)
                github_result = False
            if isinstance(gitverse_result, Exception):
                logger.error(f"GitVerse push исключение: {gitverse_result}", exc_info=True)
                gitverse_result = False

            duration = (datetime.now(tz_msk) - start_time).total_seconds()

            if self.notifier:
                msg_channel = f"black: {len(black)}\nblack_lte: {len(black_lte)}\nwhite_full: {len(white_full)}\nwhite_lite: {len(white_lite)}"
                self.notifier.send_message(msg_channel, is_report=True)
                sync_status = f"GitHub: {'✅' if github_result else '❌'} | GitVerse: {'✅' if gitverse_result else '❌'}"
                self.notifier.send_message(f"✅ *Сбор завершен за {duration:.1f} сек!*\n{sync_status}", is_report=False)
        except Exception as e:
            logger.critical(f"Критический сбой: {e}", exc_info=True)
            if self.notifier: self.notifier.send_message(f"❌ *Критическая ошибка скрипта:* `{e}`", is_report=False)

if __name__ == '__main__':
    collector = VPNConfigCollector()
    asyncio.run(collector.run())
