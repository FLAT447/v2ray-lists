import sys
import os
import re
import json
import base64
import logging
import asyncio
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import List, Set, Dict, Tuple, Any, Optional
from urllib.parse import urlparse, parse_qs
import aiohttp
import requests
import yaml
from github import Github, GithubException
from async_lru import alru_cache

# ============================================================================
# НАСТРОЙКА ЛОГИРОВАНИЯ
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


# ============================================================================
# ФУНКЦИИ ВАЛИДАЦИИ И ПАРСИНГА
# ============================================================================

def _is_valid_domain(domain: str) -> bool:
    """Проверяет валидность доменного имени"""
    if not domain or len(domain) > 253:
        return False

    if re.match(r'^[\d.]+$', domain):
        return False

    domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    return re.match(domain_pattern, domain.lower()) is not None


def _is_valid_host(host: str) -> bool:
    """Проверяет является ли host IP-адресом или доменом"""
    if not host:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if _is_valid_domain(host):
        return True

    return False


def parse_config(config: str) -> Tuple[str, int, str]:
    """
    Базовый парсер для валидации.
    Возвращает: (host, port, sni)
    """
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


def parse_config_detailed(config: str) -> dict:
    """
    Глубокий парсер конфигурации. Извлекает параметры для всех поддерживаемых
    протоколов (vless, vmess, trojan, hysteria2, tuic, ss).
    """
    result = {
        'type': 'unknown',
        'server': '',
        'port': 0,
        'sni': '',
        'udp': True,
        'flow': '',
        'client-fingerprint': '',
        'up': '30 Mbps',
        'down': '100 Mbps',
        'congestion_control': 'bbr',
        'udp_relay_mode': 'native',
        'auth_type': 'none'
    }
    try:
        config = config.strip()
        if not config:
            return result

        if config.startswith('vmess://'):
            rem = config[8:].split('#')[0].strip()
            if '?' in rem or '@' in rem or (':' in rem and not rem.replace(':', '').isalnum()):
                parsed = urlparse(config)
                result['type'] = 'vmess'
                netloc = parsed.netloc
                auth_part, _, host_port = netloc.rpartition('@')
                
                if host_port.startswith('['):
                    end_bracket = host_port.find(']')
                    if end_bracket != -1:
                        result['server'] = host_port[1:end_bracket]
                        port_part = host_port[end_bracket + 1:]
                        if port_part.startswith(':'):
                            result['port'] = int(port_part.split(':')[1].split('?')[0])
                else:
                    if ':' in host_port:
                        result['server'], port_str = host_port.split(':', 1)
                        result['port'] = int(port_str.split('?')[0])
                    else:
                        result['server'] = host_port

                result['uuid'] = auth_part
                query = parse_qs(parsed.query)
                result['sni'] = query.get('sni', [''])[0] or query.get('peer', [''])[0] or query.get('host', [''])[0]
                result['tls'] = query.get('security', [''])[0] == 'tls' or 'tls' in query
                
                net_type = query.get('type', [''])[0] or query.get('net', [''])[0]
                if net_type:
                    result['network'] = net_type
                    if net_type == 'ws':
                        result['ws-opts'] = {
                            'path': query.get('path', ['/'])[0],
                            'headers': {'Host': result['sni'] or result['server']}
                        }
                    elif net_type == 'grpc':
                        result['grpc-opts'] = {
                            'grpc-service-name': query.get('serviceName', [''])[0]
                        }
            else:
                b64_str = rem + "=" * ((4 - len(rem) % 4) % 4)
                data = json.loads(base64.b64decode(b64_str).decode('utf-8', errors='ignore'))
                result['type'] = 'vmess'
                result['server'] = str(data.get('add', ''))
                result['port'] = int(data.get('port', 0))
                result['uuid'] = str(data.get('id', ''))
                result['alterId'] = int(data.get('aid', 0))
                result['cipher'] = 'auto'
                result['sni'] = str(data.get('sni', '') or data.get('host', ''))
                result['tls'] = str(data.get('tls', '')).lower() in ['tls', 'true', '1']
                
                net_type = str(data.get('net', ''))
                if net_type in ['ws', 'grpc']:
                    result['network'] = net_type
                    if net_type == 'ws':
                        result['ws-opts'] = {
                            'path': str(data.get('path', '/')),
                            'headers': {'Host': result['sni'] or result['server']}
                        }
                    elif net_type == 'grpc':
                        result['grpc-opts'] = {
                            'grpc-service-name': str(data.get('path', ''))
                        }
            return result

        parsed = urlparse(config)
        scheme = parsed.scheme.lower()
        
        # ✅ Нормализация типов протоколов (hy2 → hysteria2, hysteria → hysteria2)
        PROTOCOL_MAP = {
            'hy2': 'hysteria2',
            'hysteria': 'hysteria2',
        }
        scheme = PROTOCOL_MAP.get(scheme, scheme)
        result['type'] = scheme

        netloc = parsed.netloc
        auth_part, _, host_port = netloc.rpartition('@')
        if not auth_part:
            host_port = netloc

        if host_port.startswith('['):
            end_bracket = host_port.find(']')
            if end_bracket != -1:
                result['server'] = host_port[1:end_bracket]
                port_part = host_port[end_bracket + 1:]
                if port_part.startswith(':'):
                    result['port'] = int(port_part.split(':')[1].split('?')[0])
        else:
            if ':' in host_port:
                result['server'], port_str = host_port.split(':', 1)
                result['port'] = int(port_str.split('?')[0])
            else:
                result['server'] = host_port

        query = parse_qs(parsed.query)
        result['sni'] = query.get('sni', [''])[0] or query.get('peer', [''])[0]

        if scheme == 'vless':
            result['uuid'] = auth_part
            result['cipher'] = 'none'
            result['flow'] = query.get('flow', [''])[0] or 'xtls-rprx-vision'
            security = query.get('security', [''])[0]
            if security in ['tls', 'reality']:
                result['tls'] = True
            if security == 'reality':
                result['reality-opts'] = {
                    'public-key': query.get('pbk', [''])[0],
                    'short-id': query.get('sid', [''])[0]
                }
            fp = query.get('fp', [''])[0]
            if fp:
                result['client-fingerprint'] = fp

            net_type = query.get('type', [''])[0] or query.get('net', [''])[0]
            if net_type:
                result['network'] = net_type
                if net_type == 'ws':
                    result['ws-opts'] = {
                        'path': query.get('path', ['/'])[0],
                        'headers': {'Host': query.get('host', [''])[0] or result['sni'] or result['server']}
                    }
                elif net_type == 'grpc':
                    result['grpc-opts'] = {
                        'grpc-service-name': query.get('serviceName', [''])[0]
                    }

        elif scheme == 'trojan':
            result['password'] = auth_part
            result['tls'] = True
            if query.get('insecure', [''])[0] in ['1', 'true']:
                result['skip-cert-verify'] = True

        elif scheme in ['hysteria2', 'hysteria']:
            result['type'] = 'hysteria2'
            result['password'] = auth_part
            up_str = query.get('up', [''])[0]
            down_str = query.get('down', [''])[0]
            if up_str:
                result['up'] = up_str
            if down_str:
                result['down'] = down_str
            if query.get('insecure', [''])[0] in ['1', 'true']:
                result['skip-cert-verify'] = True

        elif scheme == 'tuic':
            if ':' in auth_part:
                result['uuid'], result['password'] = auth_part.split(':', 1)
            else:
                result['uuid'] = auth_part
            result['alpn'] = query.get('alpn', [['h3']])[0].split(',')
            result['congestion_control'] = query.get('congestion_control', ['bbr'])[0]
            result['udp_relay_mode'] = query.get('udp_relay_mode', ['native'])[0]

        elif scheme == 'ss':
            try:
                if ':' in auth_part:
                    result['cipher'], result['password'] = auth_part.split(':', 1)
                else:
                    padded = auth_part + "=" * ((4 - len(auth_part) % 4) % 4)
                    decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                    if ':' in decoded:
                        result['cipher'], result['password'] = decoded.split(':', 1)
            except Exception:
                pass

        return result
    except Exception as e:
        logger.debug(f"Ошибка парсинга конфига: {e}")
        return result


def validate_config(config: str, host: str, port: int, sni: str) -> bool:
    """Валидирует распарсенную конфигурацию."""
    if not host or port <= 0 or port > 65535:
        return False

    if not _is_valid_host(host):
        return False

    if sni and not _is_valid_domain(sni):
        return False

    return True


# ============================================================================
# КЛАССЫ СБОРЩИКА И МОДУЛИ КЛИЕНТОВ
# ============================================================================

class TelegramNotifier:
    """Отправка уведомлений и статусов работы в Telegram"""
    def __init__(self, token: str, chat_id: str, channel_id: str = None):
        self.token = token
        self.chat_id = chat_id          
        self.channel_id = channel_id    
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_message(self, text: str, is_report: bool = False):
        if is_report and self.channel_id:
            tz_msk = timezone(timedelta(hours=3))
            time_str = datetime.now(tz_msk).strftime("%H:%M | %d.%m.%Y")
            
            total_configs = 0
            try:
                for line in text.split('\n'):
                    if any(k in line for k in ['black', 'white_full', 'white_lite']):
                        digits = ''.join(filter(str.isdigit, line))
                        if digits:
                            total_configs += int(digits)
            except Exception:
                total_configs = "N/A"

            channel_text = (
                f"🔄 V2Ray подписки обновлены!\n"
                f"📅 Время: {time_str}\n"
                f"📊 Всего конфигураций: {total_configs}\n\n"
                f"📦 <a href=\"https://github.com/FLAT447/v2ray-lists\">Репозиторий проекта</a>\n"
                f"⚡ <a href=\"https://flat447.github.io/v2ray-lists-site\">Сайт проекта</a>"
            )

            payload = {
                "chat_id": self.channel_id,
                "text": channel_text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            }
            logger.info("Отправка итогового отчета в Telegram-канал...")
        else:
            payload = {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True
            }
            logger.info("Отправка системного уведомления в чат...")

        try:
            response = requests.post(self.api_url, json=payload, timeout=10)
            if response.status_code != 200:
                logger.error(f"Telegram API вернул ошибку: {response.text}")
        except Exception as e:
            logger.error(f"Не удалось отправить уведомление в Telegram: {e}")


class GithubManager:
    """Коммит и пуш файлов напрямую в репозиторий GitHub через API"""
    def __init__(self, token: str):
        self.gh = Github(token)
        self.repo_name = os.getenv('GITHUB_REPOSITORY', 'FLAT447/v2ray-lists')

    def _push_sync(self, files: Dict[str, str]) -> bool:
        try:
            repo = self.gh.get_repo(self.repo_name)
            tz_msk = timezone(timedelta(hours=3))
            time_str_msk = datetime.now(tz_msk).strftime("%d.%m.%Y %H:%M:%S MSK")

            for file_path, content in files.items():
                commit_content = content
                try:
                    contents = repo.get_contents(file_path)
                    sha = contents.sha

                    if file_path == 'stats.json':
                        try:
                            existing_text = contents.decoded_content.decode('utf-8')
                            data = json.loads(existing_text)
                        except Exception:
                            data = {}
                        
                        try:
                            data['configs'] = json.loads(content)
                        except Exception:
                            data['configs'] = content
                        
                        commit_content = json.dumps(data, indent=2, ensure_ascii=False)

                    repo.update_file(
                        path=file_path,
                        message=f"🔄 Обновление {file_path} по времени МСК [{time_str_msk}]",
                        content=commit_content,
                        sha=sha
                    )
                    logger.info(f"Файл {file_path} успешно обновлен в репозитории.")
                except GithubException as e:
                    if e.status == 404:
                        if file_path == 'stats.json':
                            try:
                                data = {'configs': json.loads(content)}
                            except Exception:
                                data = {'configs': content}
                            commit_content = json.dumps(data, indent=2, ensure_ascii=False)

                        repo.create_file(
                            path=file_path,
                            message=f"✨ Create {file_path} via API [{time_str_msk}]",
                            content=commit_content
                        )
                        logger.info(f"Файл {file_path} успешно создан в репозитории.")
                    else:
                        raise e
            return True
        except Exception as e:
            logger.error(f"Ошибка при работе с GitHub API: {e}")
            return False

    async def push_files(self, files: Dict[str, str]) -> bool:
        return await asyncio.to_thread(self._push_sync, files)


class ConfigFetcher:
    """Сбор и Base64-декодирование сырых конфигов"""
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        self.sources: List[str] = [
            "https://mifa.world/hysteria",
            "https://subrostunnel.vercel.app/gen.txt",
            "https://github.com/igareck/vpn-configs-for-russia/raw/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
            "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
            "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
            "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
            "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
            "https://gitverse.ru/api/repos/cid-uskoritel/cid-white/raw/branch/master/whitelist.txt",
            "https://etoneya.su/1",
            "https://etoneya.su/whitelist",
            "https://gist.github.com/DestroyST6767/f00837ad379aa3272183fdaabcfd50da.txt",
            "https://gist.github.com/DestroyST6767/50af50221ca1858ba2084efc0f524fbc.txt"
            "https://mifa.world/ss",
            "https://mifa.world/vless",
            "https://mifa.world/trojan",
            "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/configs/url_work.txt",
            "https://vpn.yzewe.ru/sub",
            "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
            "https://raw.githubusercontent.com/prominbro/sub/refs/heads/main/212.txt",
            "https://obwl.obprojects.lol/configs/selected.txt",
            "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
            "https://raw.githubusercontent.com/AirLinkVPN1/AirLinkVPN/refs/heads/main/rkn_white_list",
            "https://raw.githubusercontent.com/dequar/deqwl/refs/heads/main/deray.txt",
            "https://raw.githubusercontent.com/ewecrow78-gif/whitelist1/main/list.txt",
            "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/ru/vless.txt",
            "https://subrostunnel.vercel.app/wl.txt",
            "https://rostunnel.vercel.app/mega.txt",
            "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/refs/heads/main/checked/RU_Best/ru_white_all_WHITE.txt",
            "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/main/subscriptions/FreeCFGHub1.txt"
        ]

    async def fetch_source(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        try:
            logger.info(f"Запрос к источнику: {url}")
            async with session.get(url, headers=self.headers, timeout=15) as response:
                if response.status == 200:
                    text = await response.text()
                    text_stripped = text.strip()
                    
                    if text_stripped and not any(text_stripped.startswith(p) for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria', 'tuic://', '#']):
                        try:
                            cleaned_b64 = "".join(text_stripped.split())
                            cleaned_b64 += "=" * ((4 - len(cleaned_b64) % 4) % 4)
                            decoded = base64.b64decode(cleaned_b64).decode('utf-8', errors='ignore')
                            if any(p in decoded for p in ['://', 'vless://', 'vmess://', 'ss://', 'trojan://']):
                                text = decoded
                        except Exception:
                            pass

                    configs = [
                        line.strip() for line in text.splitlines()
                        if line.strip() and not line.strip().startswith('#') and '://' in line
                    ]
                    return configs
                logger.warning(f"Источник {url} вернул статус {response.status}")
                return []
        except Exception as e:
            logger.error(f"Ошибка при скачивании из {url}: {e}")
            return []

    async def fetch_all_configs(self) -> List[str]:
        if not self.sources:
            return []
        all_configs = []
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_source(session, url) for url in self.sources]
            results = await asyncio.gather(*tasks)
            for config_list in results:
                all_configs.extend(config_list)
        
        unique_configs = {}
        for cfg in all_configs:
            cfg_stripped = cfg.strip()
            if not cfg_stripped:
                continue
            core_part = cfg_stripped.split('#')[0].strip()
            if core_part and core_part not in unique_configs:
                unique_configs[core_part] = cfg_stripped

        return list(unique_configs.values())


class ConfigPinger:
    """Асинхронная проверка доступности портов с защитой от перегрузки сети"""
    def __init__(self, max_concurrent: int = 100):
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def _check_config(self, config: str, timeout: float = 2.5) -> str | None:
        host, port, sni = parse_config(config)
        
        if not validate_config(config, host, port, sni):
            return None

        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return config
            except Exception:
                return None

    async def ping_configs(self, configs: List[str]) -> List[str]:
        logger.info(f"Проверяем доступность {len(configs)} конфигов...")
        tasks = [self._check_config(cfg) for cfg in configs]
        results = await asyncio.gather(*tasks)
        valid_configs = [res for res in results if res is not None]
        logger.info(f"Валидных конфигов после пинга: {len(valid_configs)}")
        return valid_configs


class ConfigFilter:
    """Асинхронная фильтрация по спискам ТСПУ на базе параллельного DoH"""
    def __init__(self):
        self.doh_servers = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]

    @alru_cache(maxsize=8192)
    async def _resolve_doh(self, session: aiohttp.ClientSession, hostname: str) -> str | None:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            return hostname

        for provider in self.doh_servers:
            try:
                params = {"name": hostname, "type": "A"}
                async with session.get(provider, params=params, headers={"accept": "application/dns-json"}, timeout=3) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if "Answer" in data:
                            for ans in data["Answer"]:
                                if ans["type"] == 1:
                                    return ans["data"]
            except Exception:
                continue
        return None

    async def filter_configs(
        self, configs: List[str], whitelist_sni: Set[str], whitelist_cidr: List[str]
    ) -> Tuple[List[str], List[str], List[str]]:
        white, black_lte, black = [], [], []
        sni_set = {s.lower().strip() for s in whitelist_sni if s.strip()}
        
        networks = []
        for net_str in whitelist_cidr:
            try:
                networks.append(ipaddress.ip_network(net_str.strip(), strict=False))
            except Exception:
                continue

        async def process_single(config: str, session: aiohttp.ClientSession):
            host, port, sni = parse_config(config)
            
            if not validate_config(config, host, port, sni):
                return None

            resolved_ip = await self._resolve_doh(session, host)
            is_ip_whitelisted = False
            
            if resolved_ip:
                try:
                    ip_obj = ipaddress.ip_address(resolved_ip)
                    for net in networks:
                        if ip_obj in net:
                            is_ip_whitelisted = True
                            break
                except Exception:
                    pass

            is_sni_whitelisted = bool(sni) and sni in sni_set
            return config, is_ip_whitelisted, is_sni_whitelisted

        async with aiohttp.ClientSession() as session:
            tasks = [process_single(cfg, session) for cfg in configs]
            results = await asyncio.gather(*tasks)

            for res in results:
                if not res:
                    continue
                cfg, is_ip_whitelisted, is_sni_whitelisted = res
                
                if is_ip_whitelisted:
                    white.append(cfg)
                elif is_sni_whitelisted:
                    black_lte.append(cfg)
                else:
                    black.append(cfg)

        logger.info(f"Фильтрация завершена: white={len(white)}, black_lte={len(black_lte)}, black={len(black)}")
        return white, black_lte, black


class VPNConfigCollector:
    """Главный координатор процесса выполнения сборщика"""
    def __init__(self):
        self.config_fetcher = ConfigFetcher()
        self.config_filter = ConfigFilter()
        self.config_pinger = ConfigPinger(max_concurrent=120)
        
        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            raise ValueError("Переменная окружения GITHUB_TOKEN не задана")
        self.github_manager = GithubManager(github_token)
        
        telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')
        telegram_channel_id = os.getenv('TELEGRAM_CHANNEL_ID')
        
        if telegram_token and telegram_chat_id:
            self.notifier = TelegramNotifier(telegram_token, telegram_chat_id, telegram_channel_id)
        else:
            self.notifier = None
            logger.warning("Telegram не настроен")
        
        self.whitelist_sni: Set[str] = set()
        self.whitelist_cidr: List[str] = []

    def _clean_config(self, config: str) -> str:
        if not config:
            return ""
        if "#" in config:
            parts = config.split('#')
            if '://' in parts[0]:
                return parts[0].strip()
        return config.strip()

    def _generate_subscription_content(self, title: str, configs: List[str]) -> str:
        """Генерирует текстовую подписку в формате V2Ray"""
        meta = [
            f"#announce: 🔰 Нажми на спидометр или молнию, чтобы проверить соединение. Меньше ms - лучше | n/a - не работает. Если ВПН плохо работает, то нажмите на 🔄️.",
            f"#profile-web-page-url: https://flat447.github.io/v2ray-lists-site",
            f"#profile-title: {title}",
            f"#support-url: https://t.me/flat447",
            f"#profile-update-interval: 1\n"
        ]
    
        cleaned_configs = []
        for index, cfg in enumerate(configs, start=1):
            cleaned = self._clean_config(cfg)
            if cleaned:
                named_config = f"{cleaned}#{title.replace('V2Ray Lists - ', '')} [{index}]"
                cleaned_configs.append(named_config)

        return '\n'.join(meta + cleaned_configs)

    # ========================================================================
    # ИСПРАВЛЕННЫЕ МЕТОДЫ ДЛЯ ГЕНЕРАЦИИ CLASH YAML
    # ========================================================================
    
    # SS cipher mapping для нормализации
    SS_CIPHER_MAP = {
        'chacha20-poly1305': 'chacha20-ietf-poly1305',
        'chacha20-ietf': 'chacha20-ietf-poly1305',
        'aes-128-ctr': 'aes-128-gcm',
        'aes-192-ctr': 'aes-192-gcm',
        'aes-256-ctr': 'aes-256-gcm',
    }
    
    # Допустимые SS cipher в Clash
    VALID_SS_CIPHERS = {
        'aes-128-gcm',
        'aes-192-gcm',
        'aes-256-gcm',
        'chacha20-ietf-poly1305',
        'xchacha20-ietf-poly1305',
    }

    def _normalize_ss_cipher(self, cipher: str) -> str:
        """Нормализует Shadowsocks cipher на правильный формат"""
        cipher_lower = cipher.lower().strip()
        return self.SS_CIPHER_MAP.get(cipher_lower, cipher_lower)

    def _validate_reality_opts(self, reality_opts: dict) -> bool:
        """Валидирует REALITY параметры с полной проверкой public-key"""
        public_key = reality_opts.get('public-key', '').strip()
        short_id = reality_opts.get('short-id', '').strip()
        
        # ✅ ПРОВЕРКА 1: public-key не пусто
        if not public_key:
            logger.debug("Invalid public-key: empty")
            return False
        
        # ✅ ПРОВЕРКА 2: Длина public-key (43-44 символа для валидного base64)
        if len(public_key) < 43 or len(public_key) > 44:
            logger.debug(f"Invalid public-key length: {len(public_key)}, expected 43-44")
            return False
        
        # ✅ ПРОВЕРКА 3: Полная валидация base64 - должен декодироваться в 32 байта
        try:
            # Добавляем padding для корректного декодирования
            padded = public_key + "=" * ((4 - len(public_key) % 4) % 4)
            
            # Декодируем base64
            decoded = base64.b64decode(padded, validate=True)
            
            # Проверяем что получилось ровно 32 байта (256 бит для Ed25519)
            if len(decoded) != 32:
                logger.debug(f"Invalid public-key: decoded to {len(decoded)} bytes, expected 32")
                return False
        except Exception as e:
            logger.debug(f"Invalid public-key format: {e}")
            return False
        
        # ✅ ПРОВЕРКА 4: short-id должен быть hex (0-9, a-f) и максимум 16 символов
        if short_id:
            # Проверяем hex формат
            if not all(c in '0123456789abcdefABCDEF' for c in short_id):
                logger.debug(f"Invalid short-id format (not hex): {short_id}")
                return False
            if len(short_id) > 16:
                logger.debug(f"Invalid short-id: too long ({len(short_id)} > 16)")
                return False
        # else: short-id пусто - это OK
        
        return True

    def _build_clash_proxy(self, details: dict, index: int, proxy_name_prefix: str) -> Optional[dict]:
        """Строит словарь прокси для Clash на основе распарсенных данных"""
        ptype = details['type']
        if ptype == 'unknown' or not details['server'] or details['port'] <= 0:
            return None

        proxy = {
            'name': f'{proxy_name_prefix} [{index}]',
            'type': ptype,
            'server': details['server'],
            'port': int(details['port']),
        }

        # ✅ ИСПРАВЛЕНИЕ 1: Убрать 'udp' если он не поддерживается типом прокси
        # UDP поддерживается только некоторыми типами
        if ptype in ['hysteria2', 'tuic']:
            proxy['udp'] = details.get('udp', True)

        if details.get('sni') and ptype not in ['vless']:  # sni для не-VLESS типов
            proxy['sni'] = details['sni']
        if details.get('skip-cert-verify'):
            proxy['skip-cert-verify'] = True

        if ptype == 'vless':
            if not details.get('uuid'):
                return None
            proxy['uuid'] = details['uuid']
            proxy['encryption'] = 'none'
            
            # ✅ ИСПРАВЛЕНИЕ: flow XTLS-RprxVision ТОЛЬКО с REALITY!
            # flow + TLS + WebSocket = конфликт и ошибка!
            has_reality = bool(details.get('reality-opts'))
            has_network = bool(details.get('network'))
            
            if details.get('flow'):
                # flow требует REALITY и НЕСОВМЕСТИМ с network
                if not has_reality:
                    logger.debug(f"Flow without REALITY - skipping flow parameter")
                    # Не добавляем flow без REALITY
                elif has_network:
                    logger.debug(f"Flow + network incompatible - skipping flow")
                    # Не добавляем flow с network параметрами
                else:
                    # ✅ Добавляем flow только если есть REALITY и НЕТ network
                    proxy['flow'] = details['flow']
            
            if details.get('tls'):
                proxy['tls'] = True
            if details.get('client-fingerprint'):
                proxy['client-fingerprint'] = details['client-fingerprint']
            
            # ✅ ИСПРАВЛЕНИЕ 2: Правильно обрабатывать reality-opts с валидацией
            if details.get('reality-opts'):
                reality_opts = details['reality-opts']
                
                # Валидируем REALITY параметры
                if not self._validate_reality_opts(reality_opts):
                    logger.debug(f"Invalid REALITY opts for {details.get('server')}")
                    return None
                
                # Добавляем валидированные параметры
                public_key = reality_opts.get('public-key', '').strip()
                short_id = reality_opts.get('short-id', '').strip()
                
                proxy['reality-opts'] = {}
                proxy['reality-opts']['public-key'] = public_key
                
                # Добавляем short-id только если он есть и валидно
                if short_id:
                    proxy['reality-opts']['short-id'] = short_id.lower()
            
            # ✅ ИСПРАВЛЕНИЕ 3: servername вместо sni для VLESS (ВСЕГДА требуется для TLS)
            # Используется для SNI в TLS handshake (неважно REALITY это или обычное TLS)
            if details.get('sni') and details.get('tls'):
                proxy['servername'] = details['sni']
            
            # ✅ ИСПРАВЛЕНИЕ 4: Network параметры (ws/grpc)
            # ВАЖНО: network параметры НЕ совместимы с REALITY!
            # Добавляем только если НЕТ REALITY параметров
            if not details.get('reality-opts'):
                if details.get('network') == 'ws' and details.get('ws-opts'):
                    proxy['network'] = 'ws'
                    ws_opts = details['ws-opts']
                    proxy['ws-opts'] = {}
                    if ws_opts.get('path'):
                        proxy['ws-opts']['path'] = ws_opts['path']
                    if ws_opts.get('headers'):
                        proxy['ws-opts']['headers'] = ws_opts['headers']
                elif details.get('network') == 'grpc' and details.get('grpc-opts'):
                    proxy['network'] = 'grpc'
                    proxy['grpc-opts'] = {}
                    if details['grpc-opts'].get('grpc-service-name'):
                        proxy['grpc-opts']['grpc-service-name'] = details['grpc-opts']['grpc-service-name']

        elif ptype == 'vmess':
            if not details.get('uuid'):
                return None
            proxy['uuid'] = details['uuid']
            proxy['alterId'] = int(details.get('alterId', 0))
            proxy['cipher'] = details.get('cipher', 'auto')
            if details.get('tls'):
                proxy['tls'] = True
            if details.get('sni'):
                proxy['servername'] = details['sni']
            
            # ✅ ИСПРАВЛЕНИЕ 5: Правильно обрабатывать network для VMess
            if details.get('network') == 'ws' and details.get('ws-opts'):
                proxy['network'] = 'ws'
                ws_opts = details['ws-opts']
                proxy['ws-opts'] = {}
                if ws_opts.get('path'):
                    proxy['ws-opts']['path'] = ws_opts['path']
                if ws_opts.get('headers'):
                    proxy['ws-opts']['headers'] = ws_opts['headers']
            elif details.get('network') == 'grpc' and details.get('grpc-opts'):
                proxy['network'] = 'grpc'
                proxy['grpc-opts'] = {}
                if details['grpc-opts'].get('grpc-service-name'):
                    proxy['grpc-opts']['grpc-service-name'] = details['grpc-opts']['grpc-service-name']

        elif ptype == 'trojan':
            if not details.get('password'):
                return None
            proxy['password'] = details['password']
            proxy['sni'] = details.get('sni', '')
            if details.get('skip-cert-verify'):
                proxy['skip-cert-verify'] = True

        elif ptype == 'hysteria2':
            if not details.get('password'):
                return None
            proxy['password'] = details['password']
            proxy['obfs'] = 'salamander'
            proxy['obfs-password'] = details.get('password', '')
            proxy['up'] = details.get('up', '30 Mbps')
            proxy['down'] = details.get('down', '100 Mbps')
            if details.get('sni'):
                proxy['sni'] = details['sni']

        elif ptype == 'tuic':
            if not details.get('uuid'):
                return None
            proxy['uuid'] = details['uuid']
            if details.get('password'):
                proxy['password'] = details['password']
            if details.get('alpn'):
                alpn = details['alpn']
                if isinstance(alpn, list):
                    proxy['alpn'] = alpn
                elif isinstance(alpn, str):
                    proxy['alpn'] = [alpn]
            proxy['congestion-control'] = details.get('congestion_control', 'bbr')
            proxy['udp-relay-mode'] = details.get('udp_relay_mode', 'native')
            if details.get('sni'):
                proxy['sni'] = details['sni']

        elif ptype == 'ss':
            if not details.get('cipher') or not details.get('password'):
                return None
            
            # ✅ Нормализуем cipher (исправляем неправильные форматы)
            cipher = self._normalize_ss_cipher(details['cipher'])
            
            # ✅ Валидируем что cipher поддерживается в Clash
            if cipher not in self.VALID_SS_CIPHERS:
                logger.debug(f"Unsupported SS cipher: {cipher}")
                return None
            
            proxy['cipher'] = cipher
            proxy['password'] = details['password']

        return proxy

    def _generate_clash_yaml_content(self, title: str, configs: List[str]) -> str:
        """Генерирует корректный Clash YAML"""
        proxy_name_prefix = title.replace('V2Ray Lists - ', '').strip()
        proxies = []
        invalid_count = 0

        for idx, cfg in enumerate(configs, start=1):
            cleaned = self._clean_config(cfg)
            if not cleaned:
                continue
            
            try:
                details = parse_config_detailed(cleaned)
                proxy = self._build_clash_proxy(details, idx, proxy_name_prefix)
                if proxy:
                    proxies.append(proxy)
                else:
                    invalid_count += 1
            except Exception as e:
                logger.debug(f"Ошибка при обработке конфига {idx}: {e}")
                invalid_count += 1

        if not proxies:
            logger.warning(f"Никаких валидных проксей для {title}")
            return "# No valid proxies found"

        logger.info(f"Сгенерировано {len(proxies)} проксей для {title} (пропущено {invalid_count})")

        # ✅ ИСПРАВЛЕНИЕ 6: Правильная структура YAML с пустыми полями
        clash_config = {
            'proxies': proxies,
            'proxy-groups': [
                {
                    'name': 'Selector',
                    'type': 'select',
                    'proxies': [p['name'] for p in proxies]
                },
                {
                    'name': 'Auto Fallback',
                    'type': 'fallback',
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300,
                    'proxies': [p['name'] for p in proxies]
                }
            ],
            'rules': ['MATCH,Selector']
        }

        comments = (
            f"# 🔰 V2Ray Clash Subscription\n"
            f"# Profile: {title}\n"
            f"# Support: https://t.me/flat447\n"
            f"# Update interval: 1 hour\n"
            f"# Valid proxies: {len(proxies)}\n\n"
        )

        # ✅ ИСПРАВЛЕНИЕ 7: Правильные параметры PyYAML
        try:
            yaml_str = yaml.dump(
                clash_config,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                default_style=None,
                indent=2,
                explicit_start=False,
                explicit_end=False
            )
        except Exception as e:
            logger.error(f"Ошибка YAML сериализации: {e}")
            return comments + "# Error generating YAML"

        return comments + yaml_str

    async def run(self):
        tz_msk = timezone(timedelta(hours=3))
        start_time = datetime.now(tz_msk)

        try:
            logger.info("Загрузка списков ТСПУ...")
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            
            sni_res = requests.get('https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt', headers=headers, timeout=20)
            sni_res.raise_for_status()
            self.whitelist_sni = {line.strip() for line in sni_res.text.splitlines() if line.strip() and not line.startswith('#')}
            logger.info(f"Загружено {len(self.whitelist_sni)} SNI в whitelist")
            
            cidr_res = requests.get('https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt', headers=headers, timeout=20)
            cidr_res.raise_for_status()
            self.whitelist_cidr = [line.strip() for line in cidr_res.text.splitlines() if line.strip() and not line.startswith('#')]
            logger.info(f"Загружено {len(self.whitelist_cidr)} CIDR сетей в whitelist")
            
            all_configs = await self.config_fetcher.fetch_all_configs()
            logger.info(f"Всего уникальных сырых конфигураций собрано: {len(all_configs)}")
            
            if not all_configs:
                logger.warning("Конфиги не собраны.")
                return

            alive_configs = await self.config_pinger.ping_configs(all_configs)
            logger.info(f"Доступных конфигураций после пинга: {len(alive_configs)}")
            
            white_full, black_lte, black = await self.config_filter.filter_configs(
                alive_configs, self.whitelist_sni, self.whitelist_cidr
            )
            
            white_lite = white_full[:500]
            current_time_str = datetime.now(tz_msk).strftime("%H:%M | %d.%m.%Y")
            
            self.stats = {
                "black": {"count": len(black), "updated": current_time_str},
                "black_lte": {"count": len(black_lte), "updated": current_time_str},
                "white_full": {"count": len(white_full), "updated": current_time_str},
                "white_lite": {"count": len(white_lite), "updated": current_time_str}
            }
            
            # Генерация контента подписок
            black_txt = self._generate_subscription_content('V2Ray Lists - BLACK FULL', black)
            black_lte_txt = self._generate_subscription_content('V2Ray Lists - BLACK LTE', black_lte)
            white_full_txt = self._generate_subscription_content('V2Ray Lists - WHITE FULL', white_full)
            white_lite_txt = self._generate_subscription_content('V2Ray Lists - WHITE LITE', white_lite)

            black_b64 = base64.b64encode(black_txt.encode('utf-8')).decode('utf-8')
            black_lte_b64 = base64.b64encode(black_lte_txt.encode('utf-8')).decode('utf-8')
            white_full_b64 = base64.b64encode(white_full_txt.encode('utf-8')).decode('utf-8')
            white_lite_b64 = base64.b64encode(white_lite_txt.encode('utf-8')).decode('utf-8')
            
            files_to_push = {
                'BLACK_FULL.txt': black_txt,
                'BLACK_LTE.txt': black_lte_txt,
                'WHITE_FULL.txt': white_full_txt,
                'WHITE_LITE.txt': white_lite_txt,
                'BASE64/BLACK_FULL.txt': black_b64,
                'BASE64/BLACK_LTE.txt': black_lte_b64,
                'BASE64/WHITE_FULL.txt': white_full_b64,
                'BASE64/WHITE_LITE.txt': white_lite_b64,
                'CLASH/BLACK_FULL.yaml': self._generate_clash_yaml_content('V2Ray Lists - BLACK FULL', black),
                'CLASH/BLACK_LTE.yaml': self._generate_clash_yaml_content('V2Ray Lists - BLACK LTE', black_lte),
                'CLASH/WHITE_FULL.yaml': self._generate_clash_yaml_content('V2Ray Lists - WHITE FULL', white_full),
                'CLASH/WHITE_LITE.yaml': self._generate_clash_yaml_content('V2Ray Lists - WHITE LITE', white_lite),
                'stats.json': json.dumps(self.stats, indent=2, ensure_ascii=False)
            }
            
            await self.github_manager.push_files(files_to_push)
            
            duration = (datetime.now(tz_msk) - start_time).total_seconds()
            
            if self.notifier:
                msg_channel = (
                    f"black: {self.stats['black']['count']}\n"
                    f"black_lte: {self.stats['black_lte']['count']}\n"
                    f"white_full: {self.stats['white_full']['count']}\n"
                    f"white_lite: {self.stats['white_lite']['count']}"
                )
                self.notifier.send_message(msg_channel, is_report=True)
                
                msg_admin = (
                    f"✅ *Сбор завершен успешно!*\n\n"
                    f"📊 *Статистика подписок:*\n"
                    f"├ `black`: {self.stats['black']['count']}\n"
                    f"├ `black_lte`: {self.stats['black_lte']['count']}\n"
                    f"├ `white_full`: {self.stats['white_full']['count']}\n"
                    f"└ `white_lite`: {self.stats['white_lite']['count']}\n\n"
                    f"📦 *Форматы подписок:*\n"
                    f"├ Текстовые (.txt): BLACK_FULL, BLACK_LTE, WHITE_FULL, WHITE_LITE\n"
                    f"├ Закодированные Base64 (.txt): Директория `BASE64/`\n"
                    f"└ Clash YAML (.yaml): CLASH/BLACK_FULL, CLASH/BLACK_LTE, CLASH/WHITE_FULL, CLASH/WHITE_LITE\n\n"
                    f"⏱ Время выполнения: {duration:.1f} сек"
                )
                self.notifier.send_message(msg_admin, is_report=False)
                
            logger.info("✅ Сбор завершен успешно!")
                
        except Exception as e:
            logger.critical(f"Критический сбой: {e}")
            if self.notifier:
                self.notifier.send_message(f"❌ *Критическая ошибка скрипта:* `{e}`", is_report=False)


# ============================================================================
# ЮНИТ ТЕСТЫ ВАЛИДАЦИИ
# ============================================================================

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []

    def add_test(self, test_name: str, result: bool, details: str = ""):
        status = "✅ PASS" if result else "❌ FAIL"
        self.tests.append(f"{status} | {test_name}")
        if details:
            self.tests.append(f"         {details}")
        
        if result:
            self.passed += 1
        else:
            self.failed += 1

    def print_results(self):
        print("\n" + "=" * 80)
        print("РЕЗУЛЬТАТЫ ТЕСТОВ ВАЛИДАЦИИ")
        print("=" * 80)
        for test in self.tests:
            print(test)
        print("=" * 80)
        print(f"Всего: {self.passed + self.failed} | Успешно: {self.passed} ✅ | Ошибок: {self.failed} ❌")
        print("=" * 80)
        return self.failed == 0


def run_validation_tests():
    results = TestResults()

    print("\n📋 Тестирование ВАЛИДНЫХ конфигов...")
    results.add_test(
        "Конфиг с доменом и SNI",
        validate_config("vless://uuid@example.com:443?sni=example.com", "example.com", 443, "example.com"),
        "host=example.com, port=443, sni=example.com"
    )
    results.add_test(
        "Конфиг с IPv4 и без SNI",
        validate_config("trojan://pass@111.111.111.111:443", "111.111.111.111", 443, ""),
        "host=111.111.111.111, port=443, sni=''"
    )
    results.add_test(
        "Конфиг с IPv6 и SNI",
        validate_config("vless://uuid@[2001:db8::1]:443?sni=example.com", "2001:db8::1", 443, "example.com"),
        "host=2001:db8::1, port=443, sni=example.com"
    )
    results.add_test(
        "Конфиг с поддоменом",
        validate_config("vless://uuid@api.example.com:443?sni=api.example.com", "api.example.com", 443, "api.example.com"),
        "host=api.example.com, port=443, sni=api.example.com"
    )

    print("\n📋 Тестирование НЕВАЛИДНЫХ конфигов (проблемы с HOST)...")
    results.add_test("Конфиг с пустым host", not validate_config("vless://uuid", "", 443, ""), "host=''")
    results.add_test("Конфиг с пробелами", not validate_config("vless://uuid@not valid domain:443", "not valid domain", 443, ""), "host='not valid domain'")
    results.add_test("Конфиг со спецсимволами", not validate_config("vless://uuid@invalid!@#$:443", "invalid!@#$", 443, ""), "host='invalid!@#$'")

    print("\n📋 Тестирование НЕВАЛИДНЫХ конфигов (проблемы с PORT)...")
    results.add_test("Конфиг с port=0", not validate_config("vless://uuid@example.com:0", "example.com", 0, ""), "port=0")
    results.add_test("Конфиг с port > 65535", not validate_config("vless://uuid@example.com:99999", "example.com", 99999, ""), "port=99999")

    print("\n📋 Тестирование функций _is_valid_domain и _is_valid_host...")
    results.add_test("_is_valid_domain('example.com')", _is_valid_domain("example.com"), "Должен быть True")
    results.add_test("_is_valid_host('111.111.111.111')", _is_valid_host("111.111.111.111"), "IPv4 адрес должен быть валиден")
    results.add_test("_is_valid_host('999.999.999.999')", not _is_valid_host("999.999.999.999"), "Невалидный IPv4")

    success = results.print_results()
    if not success:
        sys.exit(1)


# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        run_validation_tests()
    else:
        asyncio.run(VPNConfigCollector().run())
