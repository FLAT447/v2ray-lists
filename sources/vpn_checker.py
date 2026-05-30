import asyncio
import json
import logging
import os
import re
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import List, Set, Dict, Tuple
from urllib.parse import urlparse, parse_qs
import aiohttp
import requests
from github import Github, GithubException
from async_lru import alru_cache

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vpn_collector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class TelegramNotifier:
    """Отправка уведомлений и статусов работы в Telegram"""
    def __init__(self, token: str, chat_id: str, channel_id: str = None):
        self.token = token
        self.chat_id = chat_id          # ID чата для логов запуска/ошибок
        self.channel_id = channel_id    # ID канала для финального отчета
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_message(self, text: str, is_report: bool = False):
        """
        Отправка сообщений в Telegram.
        Если это отчет (is_report=True) и задан channel_id, красиво форматируем под канал.
        Иначе шлем обычный системный лог админу.
        """
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

            # Названия обновляемых файлов по вашему шаблону
            files_str = "1.txt, 3.txt, 6.txt, 7.txt, 9.txt, 10.txt, 11.txt, 13.txt, 14.txt, 15.txt, 16.txt, 17.txt, 20.txt, 22.txt, 23.txt, 24.txt, 25.txt, 26.txt"

            channel_text = (
                f"<b>V2Ray Updates CH</b>\n"
                f"🔄 V2Ray подписки обновлены!\n"
                f"📅 Время: {time_str}\n"
                f"📁 Обновлены файлы: {files_str}\n"
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
            # Для технических логов админу отправляем в Markdown
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
    """Сбор сырых конфигов из внешних источников подписок"""
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
        }
        self.sources: List[str] = [
            "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
            "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
            "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
            "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
            "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
            "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/wifi",
            "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
            "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
            "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
            "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
            "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
            "https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt",
            "https://github.com/barry-far/V2ray-Config/raw/refs/heads/main/Splitted-By-Protocol/vless.txt",
            "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
            "https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/mixed_iran.txt",
            "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
            "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
            "https://mifa.world/hysteria",
            "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/tuic.txt",
            "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
            "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
            "https://subrostunnel.vercel.app/gen.txt",
            "https://github.com/igareck/vpn-configs-for-russia/raw/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
            "https://github.com/Mr-Meshky/vify/raw/refs/heads/main/configs/vless.txt",
            "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
            "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
            "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
            "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
            "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
            "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/whitelist_full",
            "https://gitverse.ru/api/repos/cid-uskoritel/cid-white/raw/branch/master/whitelist.txt",
            "https://etoneya.best/1",
            "https://etoneya.best/whitelist"
        ]

    async def fetch_source(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        try:
            logger.info(f"Запрос к источнику: {url}")
            async with session.get(url, headers=self.headers, timeout=15) as response:
                if response.status == 200:
                    text = await response.text()
                    configs = [
                        line.strip() for line in text.splitlines()
                        if line.strip() and not line.strip().startswith('#')
                    ]
                    return configs
                logger.warning(f"Источник {url} вернул статус {response.status}")
                return []
        except Exception as e:
            logger.error(f"Ошибка при скачивании из {url}: {e}")
            return []

    async def fetch_all_configs(self) -> List[str]:
        if not self.sources:
            logger.warning("Список источников пуст.")
            return []
        
        all_configs = []
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_source(session, url) for url in self.sources]
            results = await asyncio.gather(*tasks)
            for config_list in results:
                all_configs.extend(config_list)
                
        unique_configs = list(set(all_configs))
        return unique_configs


class ConfigPinger:
    """Асинхронная проверка доступности TCP-портов прокси-серверов"""
    async def _check_config(self, config: str, timeout: float = 5.0) -> str | None:
        try:
            parsed = urlparse(config)
            host_port = parsed.netloc.split('@')[-1]
            if ':' in host_port:
                host, port = host_port.split(':')
                port = int(port.split('?')[0])
            else:
                return None

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
        return [res for res in results if res is not None]


class ConfigFilter:
    """Асинхронная фильтрация на базе CIDR-подсетей РФ и белого списка SNI"""
    def __init__(self):
        self.doh_servers = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]

    @alru_cache(maxsize=4096)
    async def _resolve_doh(self, session: aiohttp.ClientSession, hostname: str) -> str | None:
        """Резолвинг домена в IP через DoH с кэшированием результатов в памяти"""
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

    def _parse_config_details(self, config: str) -> Tuple[str, str]:
        try:
            parsed = urlparse(config)
            host_port = parsed.netloc.split('@')[-1]
            host = host_port.split(':')[0] if ':' in host_port else host_port
            
            query_params = parse_qs(parsed.query)
            sni = query_params.get('sni', [''])[0] or query_params.get('peer', [''])[0]
            return host.lower(), sni.lower()
        except Exception:
            return '', ''

    async def filter_configs(
        self, configs: List[str], whitelist_sni: Set[str], whitelist_cidr: List[str]
    ) -> Tuple[List[str], List[str], List[str]]:
        white = []
        black_lte = []
        black = []

        sni_set = {s.lower().strip() for s in whitelist_sni if s.strip()}
        
        # Предварительная компиляция объектов CIDR-подсетей для ускорения проверок
        networks = []
        for net_str in whitelist_cidr:
            try:
                networks.append(ipaddress.ip_network(net_str.strip(), strict=False))
            except Exception:
                continue

        async with aiohttp.ClientSession() as session:
            for config in configs:
                host, sni = self._parse_config_details(config)
                if not host:
                    continue

                resolved_ip = await self._resolve_doh(session, host)
                
                # Проверяем, находится ли IP-хоста в российских CIDR-подсетях
                is_ip_in_russia = False
                if resolved_ip:
                    try:
                        ip_obj = ipaddress.ip_address(resolved_ip)
                        for net in networks:
                            if ip_obj in net:
                                is_ip_in_russia = True
                                break
                    except Exception:
                        pass

                is_sni_whitelisted = sni in sni_set if sni else False

                # 1. WHITE: Сервер физически находится в РФ (в CIDR-подсетях хостингов)
                if is_ip_in_russia:
                    white.append(config)
                
                # 2. BLACK_LTE: Сервер зарубежный, но его SNI маскируется под разрешенные сайты РФ (Авито, ВК, и др.)
                elif is_sni_whitelisted:
                    black_lte.append(config)
                
                # 3. BLACK: Обычные зарубежные сервера
                else:
                    black.append(config)

        return white, black_lte, black


class VPNConfigCollector:
    """Главный координатор процесса выполнения сборщика"""
    def __init__(self):
        self.config_fetcher = ConfigFetcher()
        self.config_filter = ConfigFilter()
        self.config_pinger = ConfigPinger()
        
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
            logger.warning("Telegram не настроен — уведомления отправляться не будут")
        
        self.whitelist_sni: Set[str] = set()
        self.whitelist_cidr: List[str] = []
        self.total_configs = 0
        self.alive_configs = 0
        self.stats: Dict[str, dict] = {}

    def _clean_config(self, config: str) -> str:
        if not config:
            return ""
        if "#" in config:
            parts = config.split('#')
            if '://' in parts[0]:
                return parts[0].strip()
        return config.strip()

    def _generate_subscription_content(self, title: str, configs: List[str]) -> str:
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

    async def load_filter_lists(self) -> bool:
        try:
            logger.info("Загрузка списков ТСПУ...")
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            
            # Домены для проверки SNI (маскировка под РФ сервисы)
            sni_res = requests.get('https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt', headers=headers, timeout=20)
            sni_res.raise_for_status()
            self.whitelist_sni = {line.strip() for line in sni_res.text.splitlines() if line.strip() and not line.startswith('#')}
            
            # Подсети РФ хостингов для точного определения категории WHITE
            cidr_res = requests.get('https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt', headers=headers, timeout=20)
            cidr_res.raise_for_status()
            self.whitelist_cidr = [line.strip() for line in cidr_res.text.splitlines() if line.strip() and not line.startswith('#')]
            return True
        except Exception as e:
            logger.error(f"Не удалось обновить списки фильтрации: {e}")
            return False

    async def run(self):
        tz_msk = timezone(timedelta(hours=3))
        start_time = datetime.now(tz_msk)
        
        if self.notifier:
            self.notifier.send_message("🚀 *Запуск сборщика VPN конфигураций...*")

        try:
            await self.load_filter_lists()
            
            all_configs = await self.config_fetcher.fetch_all_configs()
            self.total_configs = len(all_configs)
            
            if not all_configs:
                logger.warning("Конфиги не собраны.")
                if self.notifier:
                    self.notifier.send_message("⚠️ Сборщик завершился: списки конфигураций пусты.")
                return

            alive_configs = await self.config_pinger.ping_configs(all_configs)
            self.alive_configs = len(alive_configs)
            
            # Фильтрация по CIDR подсетям
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
            
            files_to_push = {
                'BLACK_FULL.txt': self._generate_subscription_content('V2Ray Lists - BLACK FULL', black),
                'BLACK_LTE.txt': self._generate_subscription_content('V2Ray Lists - BLACK LTE', black_lte),
                'WHITE_FULL.txt': self._generate_subscription_content('V2Ray Lists - WHITE FULL', white_full),
                'WHITE_LITE.txt': self._generate_subscription_content('V2Ray Lists - WHITE LITE', white_lite),
                'stats.json': json.dumps(self.stats, indent=2, ensure_ascii=False)
            }
            
            await self.github_manager.push_files(files_to_push)
            
            duration = (datetime.now(tz_msk) - start_time).total_seconds()
            
            if self.notifier:
                # 1. Отправляем красивый HTML отчет в Telegram-канал
                msg_channel = (
                    f"black: {self.stats['black']['count']}\n"
                    f"black_lte: {self.stats['black_lte']['count']}\n"
                    f"white_full: {self.stats['white_full']['count']}\n"
                    f"white_lite: {self.stats['white_lite']['count']}"
                )
                self.notifier.send_message(msg_channel, is_report=True)
                
                # 2. Дублируем технический лог успешного завершения админу в чат
                msg_admin = (
                    f"✅ *Сбор завершен успешно!*\n\n"
                    f"📊 *Статистика подписок:*\n"
                    f"├ `black`: {self.stats['black']['count']}\n"
                    f"├ `black_lte`: {self.stats['black_lte']['count']}\n"
                    f"├ `white_full`: {self.stats['white_full']['count']}\n"
                    f"└ `white_lite`: {self.stats['white_lite']['count']}\n\n"
                    f"⏱ Время выполнения: {duration:.1f} сек"
                )
                self.notifier.send_message(msg_admin, is_report=False)
                
        except Exception as e:
            logger.critical(f"Критический сбой: {e}")
            if self.notifier:
                self.notifier.send_message(f"❌ *Критическая ошибка скрипта:* `{e}`", is_report=False)


if __name__ == '__main__':
    asyncio.run(VPNConfigCollector().run())
