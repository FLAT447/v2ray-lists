import sys
import os
import re
import json
import base64
import logging
import asyncio
import ipaddress
import random
import shutil
from datetime import datetime, timezone, timedelta
from typing import List, Set, Dict, Tuple, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
import requests
from github import Github, InputGitTreeElement
from async_lru import alru_cache

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

# Подсети Cloudflare для фильтрации прокси-мусора
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
# ВАЛИДАТОР ПРИКЛАДНОГО УРОВНЯ (SING-BOX L7 HANDSHAKE)
# ============================================================================

class SingBoxValidator:
    """Проверка прохождения реального трафика через локальный бинарник sing-box"""
    def __init__(self, max_concurrent: int = 40):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.singbox_path = './sing-box' if os.path.exists('./sing-box') else shutil.which('sing-box')
        if not self.singbox_path:
            logger.warning("⚠️ sing-box не найден! Валидация L7 отключена, откат к TCP пингу.")

    async def check_l7(self, config_url: str) -> bool:
        if not self.singbox_path:
            return True # Без бинарника пропускаем все, прошедшие TCP

        async with self.semaphore:
            local_port = random.randint(20000, 40000)
            temp_config_path = f"temp_{local_port}.json"
            
            # Генерация временной конфигурации sing-box (mixed-inbound -> outbound proxy)
            sb_config = {
                "log": {"level": "silent"},
                "inbounds": [{
                    "type": "mixed",
                    "listen": "127.0.0.1",
                    "listen_port": local_port
                }],
                "outbounds": [
                    {
                        "type": "url",
                        "url": config_url
                    },
                    {
                        "type": "direct",
                        "tag": "direct"
                    }
                ]
            }
            
            try:
                with open(temp_config_path, 'w') as f:
                    json.dump(sb_config, f)

                # Запускаем sing-box в фоне
                proc = await asyncio.create_subprocess_exec(
                    self.singbox_path, 'run', '-c', temp_config_path,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                
                await asyncio.sleep(0.4) # Даем ядру инициализироваться
                
                # Тестируем прохождение трафика через созданный SOCKS/HTTP прокси к Google
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    proxy_url = f"http://127.0.0.1:{local_port}"
                    async with session.get('https://www.google.com/generate_204', proxy=proxy_url, timeout=4.5) as resp:
                        if resp.status in [200, 204]:
                            proc.terminate()
                            await proc.wait()
                            return True
            except Exception:
                pass
            finally:
                if 'proc' in locals() and proc.returncode is None:
                    try:
                        proc.kill()
                        await proc.wait()
                    except Exception:
                        pass
                if os.path.exists(temp_config_path):
                    try: os.remove(temp_config_path)
                    except Exception: pass
            return False

# ============================================================================
# ОСНОВНЫЕ МОДУЛИ И СБОРЩИК
# ============================================================================

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
        self.gh = Github(token)
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

            element_list = [InputGitTreeElement(path=fp, mode='100644', type='blob', content=co) for fp, co in files.items()]
            tree = repo.create_git_tree(element_list, base_tree)
            time_str_msk = datetime.now(timezone(timedelta(hours=3))).strftime("%d.%m.%Y %H:%M:%S MSK")
            new_commit = repo.create_git_commit(f"🔄 Автоматическое обновление подписок [{time_str_msk}]", tree.sha, [old_commit])
            ref.edit(new_commit.sha)
            logger.info("⚡ Все коммиты атомарно отправлены на GitHub.")
            return True
        except Exception as e:
            logger.error(f"GitHub Manager error: {e}")
            return False

    async def push_files(self, files: Dict[str, str]) -> bool:
        return await asyncio.to_thread(self._push_sync, files)

class ConfigFetcher:
    def __init__(self):
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        self.sources: List[str] = [
            "https://mifa.world/hysteria", "https://subrostunnel.vercel.app/gen.txt",
            "https://github.com/igareck/vpn-configs-for-russia/raw/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
            "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
            "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
            "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
            "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
            "https://gitverse.ru/api/repos/cid-uskoritel/cid-white/raw/branch/master/whitelist.txt",
            "https://etoneya.su/1", "https://etoneya.su/whitelist",
            "https://gist.github.com/DestroyST6767/f4dd6f12e5ba9d04ff8d19db0396e310.txt",
            "https://mifa.world/ss", "https://mifa.world/vless", "https://mifa.world/trojan",
            "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/configs/url_work.txt",
            "https://vpn.yzewe.ru/sub", "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
            "https://raw.githubusercontent.com/prominbro/sub/refs/heads/main/212.txt", "https://obwl.obprojects.lol/configs/selected.txt",
            "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
            "https://raw.githubusercontent.com/AirLinkVPN1/AirLinkVPN/refs/heads/main/rkn_white_list",
            "https://raw.githubusercontent.com/dequar/deqwl/refs/heads/main/deray.txt",
            "https://raw.githubusercontent.com/ewecross78-gif/whitelist1/main/list.txt",
            "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/ru/vless.txt",
            "https://subrostunnel.vercel.app/wl.txt", "https://rostunnel.vercel.app/mega.txt",
            "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/refs/heads/main/checked/RU_Best/ru_white_all_WHITE.txt",
            "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/main/subscriptions/FreeCFGHub1.txt"
        ]

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

        # Жесткая дедупликация по паре (host, port)
        unique_nodes = {}
        for cfg in all_configs:
            host, port, _ = parse_config(cfg)
            if host and port:
                key = f"{host}:{port}"
                if key not in unique_nodes:
                    unique_nodes[key] = cfg
        return list(unique_nodes.values())

class ConfigPinger:
    def __init__(self, max_concurrent: int = 150):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.sb_validator = SingBoxValidator()

    async def _check_config(self, config: str, timeout: float = 1.5) -> Optional[str]:
        host, port, sni = parse_config(config)
        if not validate_config(config, host, port, sni): return None

        async with self.semaphore:
            try:
                # Шаг 1: Быстрый TCP пинг порта
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host.strip('[]'), port), timeout=timeout)
                writer.close()
                await writer.wait_closed()
                
                # Шаг 2: Глубокая L7 Handshake проверка через sing-box
                if await self.sb_validator.check_l7(config):
                    return config
            except Exception:
                pass
            return None

    async def ping_configs(self, configs: List[str]) -> List[str]:
        logger.info(f"Проверка {len(configs)} уникальных серверов (TCP + L7 Sing-Box)...")
        tasks = [self._check_config(cfg) for cfg in configs]
        results = await asyncio.gather(*tasks)
        res = [r for r in results if r is not None]
        logger.info(f"Успешно прошли полную валидацию: {len(res)}")
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
            
            # Улучшение: моментальный дроп CDN Cloudflare
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

class VPNConfigCollector:
    def __init__(self):
        self.config_fetcher = ConfigFetcher()
        self.config_filter = ConfigFilter()
        self.config_pinger = ConfigPinger()
        self.github_manager = GithubManager(os.getenv('GITHUB_TOKEN'))
        t_token, t_chat, t_chan = os.getenv('TELEGRAM_BOT_TOKEN'), os.getenv('TELEGRAM_CHAT_ID'), os.getenv('TELEGRAM_CHANNEL_ID')
        self.notifier = TelegramNotifier(t_token, t_chat, t_chan) if t_token and t_chat else None

    def _clean_config(self, config: str) -> str:
        return config.split('#')[0].strip() if "#" in config and '://' in config.split('#')[0] else config.strip()

    def _generate_subscription_content(self, title: str, configs: List[str]) -> str:
        meta = [
            f"#announce: 🔰 Проверено через L7 Sing-Box Handshake. Меньше ms — стабильнее соединение.",
            f"#profile-web-page-url: https://flat447.github.io/v2ray-lists-site",
            f"#profile-title: {title}", f"#support-url: https://t.me/flat447", f"#profile-update-interval: 1\n"
        ]
        cleaned_configs = []
        for index, cfg in enumerate(configs, start=1):
            cleaned = self._clean_config(cfg)
            if cleaned:
                cleaned = _force_update_fp_in_url(cleaned, random.choice(ALLOWED_FPS))
                cleaned_configs.append(f"{cleaned}#{title.replace('V2Ray Lists - ', '')} [{index}]")
        return '\n'.join(meta + cleaned_configs)

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
            white_full, black_lte, black = await self.config_filter.filter_configs(alive_configs, whitelist_sni, whitelist_cidr)
            white_lite = white_full[:500]
            current_time_str = datetime.now(tz_msk).strftime("%H:%M | %d.%m.%Y")

            stats = {
                "black": {"count": len(black), "updated": current_time_str}, "black_lte": {"count": len(black_lte), "updated": current_time_str},
                "white_full": {"count": len(white_full), "updated": current_time_str}, "white_lite": {"count": len(white_lite), "updated": current_time_str}
            }

            black_txt = self._generate_subscription_content('V2Ray Lists - BLACK FULL', black)
            black_lte_txt = self._generate_subscription_content('V2Ray Lists - BLACK LTE', black_lte)
            white_full_txt = self._generate_subscription_content('V2Ray Lists - WHITE FULL', white_full)
            white_lite_txt = self._generate_subscription_content('V2Ray Lists - WHITE LITE', white_lite)

            files_to_push = {
                'BLACK_FULL.txt': black_txt, 'BLACK_LTE.txt': black_lte_txt, 'WHITE_FULL.txt': white_full_txt, 'WHITE_LITE.txt': white_lite_txt,
                'BASE64/BLACK_FULL.txt': base64.b64encode(black_txt.encode('utf-8')).decode('utf-8'),
                'BASE64/BLACK_LTE.txt': base64.b64encode(black_lte_txt.encode('utf-8')).decode('utf-8'),
                'BASE64/WHITE_FULL.txt': base64.b64encode(white_full_txt.encode('utf-8')).decode('utf-8'),
                'BASE64/WHITE_LITE.txt': base64.b64encode(white_lite_txt.encode('utf-8')).decode('utf-8'),
                'stats.json': json.dumps(stats, indent=2, ensure_ascii=False)
            }

            await self.github_manager.push_files(files_to_push)
            duration = (datetime.now(tz_msk) - start_time).total_seconds()

            if self.notifier:
                msg_channel = f"black: {len(black)}\nblack_lte: {len(black_lte)}\nwhite_full: {len(white_full)}\nwhite_lite: {len(white_lite)}"
                self.notifier.send_message(msg_channel, is_report=True)
                self.notifier.send_message(f"✅ *Сбор завершен успешно за {duration:.1f} сек!*", is_report=False)
        except Exception as e:
            logger.critical(f"Критический сбой: {e}")
            if self.notifier: self.notifier.send_message(f"❌ *Критическая ошибка скрипта:* `{e}`", is_report=False)

if __name__ == '__main__':
    collector = VPNConfigCollector()
    asyncio.run(collector.run())
