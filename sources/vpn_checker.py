#!/usr/bin/env python3

import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import List, Set, Dict, Tuple
from urllib.parse import urlparse, parse_qs
import aiohttp
import requests
from github import Github, GithubException

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
        self.chat_id = chat_id
        self.channel_id = channel_id
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_message(self, text: str):
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        if self.channel_id:
            payload["message_thread_id"] = self.channel_id

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
            async with session.get(url, timeout=15) as response:
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
            logger.warning("Список источников пуст. Добавьте ссылки в ConfigFetcher.__init__")
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
    """Фильтрация и разделение конфигов на основе SNI и IP вайтлистов"""
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

    def filter_configs(
        self, configs: List[str], whitelist_sni: Set[str], whitelist_ips: Set[str]
    ) -> Tuple[List[str], List[str], List[str]]:
        white = []
        black_lte = []
        black = []

        # Сначала собираем только белый список для точного сопоставления исключений
        for config in configs:
            host, sni = self._parse_config_details(config)
            if not host:
                continue
            
            if (sni and sni in whitelist_sni) or (host in whitelist_ips):
                white.append(config)

        # Переводим в set для мгновенного поиска пересечений
        white_set = set(white)

        # Распределяем оставшиеся конфиги, жестко исключая то, что уже в white
        for config in configs:
            if config in white_set:
                continue

            host, sni = self._parse_config_details(config)
            if not host:
                continue

            if "google" in sni or "yandex" in sni or "vk.com" in sni:
                black_lte.append(config)
            else:
                black.append(config)

        return white, black_lte, black


class VPNConfigCollector:
    """Главный координатор процесса выполнения"""
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
        
        if telegram_channel_id and telegram_chat_id:
            self.notifier = TelegramNotifier(telegram_token, telegram_chat_id, telegram_channel_id)
        else:
            self.notifier = None
            logger.warning("Telegram не настроен — уведомления отправляться не будут")
        
        self.whitelist_sni: Set[str] = set()
        self.whitelist_ips: Set[str] = set()
        self.total_configs = 0
        self.alive_configs = 0
        self.stats: Dict[str, dict] = {}

    def _clean_config(self, config: str) -> str:
        """Очистка конфигурации от чужих метаданных и комментариев в конце строки"""
        if not config:
            return ""
        # Если в строке есть '#', который идет после URI схемы (например vless://...#чужое_имя)
        # убираем всё, что находится после '#' в основной ссылке.
        if "#" in config:
            # Находим позицию '#' (главное не задеть тег в начале строки, но мы обрабатываем сами ссылки)
            parts = config.split('#')
            # Если это обычная URI ссылка, то её тело до знака '#' - чистый конфиг без чужого имени
            if '://' in parts[0]:
                return parts[0].strip()
        return config.strip()

    def _generate_subscription_content(self, title: str, configs: List[str]) -> str:
        """Генерация контента подписки с нумерацией серверов"""
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
                # Добавляем к очищенному конфигу ваше кастомное имя и порядковый номер
                # Например: "V2Ray Lists - BLACK FULL [Server 42]"
                named_config = f"{cleaned}#{title.replace('V2Ray Lists - ', '')} [{index}]"
                cleaned_configs.append(named_config)

        return '\n'.join(meta + cleaned_configs)

    async def load_filter_lists(self) -> bool:
        try:
            logger.info("Загрузка списков ТСПУ...")
            sni_res = requests.get('https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt', timeout=20)
            sni_res.raise_for_status()
            self.whitelist_sni = {line.strip() for line in sni_res.text.splitlines() if line.strip() and not line.startswith('#')}
            
            ip_res = requests.get('https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/ipwhitelist.txt', timeout=20)
            ip_res.raise_for_status()
            self.whitelist_ips = {line.strip() for line in ip_res.text.splitlines() if line.strip() and not line.startswith('#')}
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
                return

            alive_configs = await self.config_pinger.ping_configs(all_configs)
            self.alive_configs = len(alive_configs)
            
            white_full, black_lte, black = self.config_filter.filter_configs(
                alive_configs, self.whitelist_sni, self.whitelist_ips
            )
            
            white_lite = white_full[:500]
            current_time_str = datetime.now(tz_msk).strftime("%H:%M | %d.%m.%Y")
            
            self.stats = {
                "black": {"count": len(black), "updated": current_time_str},
                "black_lte": {"count": len(black_lte), "updated": current_time_str},
                "white_full": {"count": len(white_full), "updated": current_time_str},
                "white_lite": {"count": len(white_lite), "updated": current_time_str}
            }
            
            # Формируем файлы со своими метатегами и чистыми строками
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
                msg = (
                    f"✅ *Сбор завершен успешно!*\n\n"
                    f"📊 *Статистика подписок:*\n"
                    f"├ `black`: {self.stats['black']['count']}\n"
                    f"├ `black_lte`: {self.stats['black_lte']['count']}\n"
                    f"├ `white_full`: {self.stats['white_full']['count']}\n"
                    f"└ `white_lite`: {self.stats['white_lite']['count']}\n\n"
                    f"⏱ Время выполнения: {duration:.1f} сек"
                )
                self.notifier.send_message(msg)
                
        except Exception as e:
            logger.critical(f"Критический сбой: {e}")
            if self.notifier:
                self.notifier.send_message(f"❌ *Критическая ошибка скрипта:* `{e}`")


if __name__ == '__main__':
    asyncio.run(VPNConfigCollector().run())
