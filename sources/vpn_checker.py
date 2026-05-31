import asyncio
import aiohttp
import ipaddress
import json
import logging
import base64
from async_lru import alru_cache
from urllib.parse import urlparse, parse_qs

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)


class AsyncDNSResolver:
    """
    Класс для асинхронного DoH-резолва доменов с кэшированием результатов.
    """
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        # Привязываем кэш к методу конкретной сессии, защищаясь от ошибок хэширования self
        self.resolve = alru_cache(maxsize=2048)(self._resolve_impl)

    async def _resolve_impl(self, domain: str) -> str | None:
        try:
            ipaddress.ip_address(domain)
            return domain
        except ValueError:
            pass

        url = f"https://1.1.1.1/dns-query?name={domain}&type=A"
        headers = {"accept": "application/dns-json"}
        
        try:
            async with self.session.get(url, headers=headers, timeout=2.0) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if "Answer" in data:
                        for answer in data["Answer"]:
                            if answer["type"] == 1:  # IPv4 Type A
                                return answer["data"]
        except Exception:
            pass
        return None


class TelegramManager:
    """
    Класс для асинхронной отправки отчетов в Telegram.
    """
    def __init__(self, session: aiohttp.ClientSession, token: str, chat_id: str):
        self.session = session
        self.token = token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{token}/sendMessage"

    async def send_summary(self, whitelist_count: int, blacklist_count: int):
        text = (
            f"📊 *Результаты проверки конфигураций*\n\n"
            f"✅ *Режим Белого Списка (Whitelist):* `{whitelist_count}`\n"
            f"❌ *Стандартный обход (Blacklist):* `{blacklist_count}`\n\n"
            f"🔄 _Списки в репозитории успешно обновлены!_"
        )
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        try:
            async with self.session.post(self.api_url, json=payload, timeout=5.0) as resp:
                if resp.status == 200:
                    logger.info("Отчет успешно доставлен в Telegram.")
                else:
                    err_txt = await resp.text()
                    logger.error(f"Telegram API вернул ошибку: {resp.status} - {err_txt}")
        except Exception as e:
            logger.error(f"Не удалось отправить уведомление в Telegram: {e}")


class GithubManager:
    """
    Класс для асинхронного деплоя результатов через GitHub API.
    """
    def __init__(self, session: aiohttp.ClientSession, token: str, repo: str, branch: str = "main"):
        self.session = session
        self.repo = repo
        self.branch = branch
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.api_url = f"https://api.github.com/repos/{repo}/contents"

    async def upload_file(self, file_path: str, content: str, commit_message: str):
        url = f"{self.api_url}/{file_path}"
        params = {"ref": self.branch}
        sha = None

        try:
            async with self.session.get(url, headers=self.headers, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    sha = data.get("sha")
        except Exception as e:
            logger.error(f"Не удалось получить SHA для {file_path}: {e}")

        b64_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        payload = {
            "message": commit_message,
            "content": b64_content,
            "branch": self.branch
        }
        if sha:
            payload["sha"] = sha

        try:
            async with self.session.put(url, headers=self.headers, json=payload) as resp:
                if resp.status in [200, 201]:
                    logger.info(f"Файл {file_path} успешно запушен на GitHub.")
                else:
                    err_txt = await resp.text()
                    logger.error(f"Ошибка пуша {file_path}: {resp.status} - {err_txt}")
        except Exception as e:
            logger.error(f"Сетевой сбой при деплое {file_path}: {e}")


class ConfigPinger:
    def __init__(self, resolver: AsyncDNSResolver, max_concurrent: int = 300, timeout: float = 1.5):
        self.resolver = resolver
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout

    async def _check_single_config(self, config: str) -> tuple[str, str, str | None] | None:
        async with self.semaphore:
            try:
                parsed = urlparse(config)
                host = parsed.hostname
                port = parsed.port
                
                # Быстрый TCP-пинг порта
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                
                # Получаем IP из кэшируемого DoH
                ip = await self.resolver.resolve(host)
                return config, host, ip
            except Exception:
                return None

    async def check_configs(self, configs: list[str]) -> list[tuple[str, str, str | None]]:
        tasks = [self._check_single_config(conf) for conf in configs]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]


class VPNConfigCollector:
    def __init__(self, timeout: float = 1.5, max_concurrent: int = 300):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.cidr_whitelist = []
        self.domain_whitelist = set()

    async def fetch_external_lists(self, session: aiohttp.ClientSession, cidr_url: str, whitelist_url: str):
        """
        Параллельно выкачивает cidrwhitelist и whitelist из удаленных источников напрямую в память.
        """
        async def fetch_cidr():
            try:
                async with session.get(cidr_url, timeout=10.0) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if line and not line.startswith("#"):
                                try:
                                    net = ipaddress.ip_network(line, strict=False)
                                    if isinstance(net, ipaddress.IPv4Network):
                                        self.cidr_whitelist.append(net)
                                except ValueError:
                                    pass
                        logger.info(f"Загружено {len(self.cidr_whitelist)} подсетей в cidrwhitelist.")
            except Exception as e:
                logger.error(f"Ошибка загрузки cidrwhitelist: {e}")

        async def fetch_domains():
            try:
                async with session.get(whitelist_url, timeout=10.0) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        self.domain_whitelist = {line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")}
                        logger.info(f"Загружено {len(self.domain_whitelist)} объектов в доменный whitelist.")
            except Exception as e:
                logger.error(f"Ошибка загрузки доменного whitelist: {e}")

        logger.info("Старт скачивания внешних баз фильтрации...")
        await asyncio.gather(fetch_cidr(), fetch_domains())

    def is_whitelisted(self, host: str, ip_str: str | None) -> bool:
        """
        Проверяет, входит ли конфигурация в условия 'Белого Списка'.
        """
        # 1. Проверка по доменному листу
        if host in self.domain_whitelist:
            return True
            
        # 2. Проверка IP по подсетям CIDR
        if not ip_str:
            return False
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            if ip_addr.version == 6:
                return False  # IPv6 не чекаем по IPv4-базе
            return any(ip_addr in subnet for subnet in self.cidr_whitelist)
        except ValueError:
            return False

    def is_valid_config(self, config_url: str) -> bool:
        try:
            config_url = config_url.strip()
            if not config_url:
                return False
            parsed = urlparse(config_url)
            if parsed.scheme not in {'vless', 'vmess', 'ss', 'trojan', 'hysteria2', 'tuic'}:
                return False
            if not parsed.hostname or not parsed.port:
                return False
                
            query_params = parse_qs(parsed.query)
            sni = query_params.get('sni')
            peer = query_params.get('peer')
            
            if (not sni or not sni[0].strip()) and (not peer or not peer[0].strip()):
                return False
            return True
        except Exception:
            return False

    async def process(self, raw_configs_pool: list[str], cidr_url: str, whitelist_url: str, 
                      gh_token: str = None, gh_repo: str = None, tg_token: str = None, tg_chat_id: str = None):
        
        unique_raw = list(set(raw_configs_pool))
        valid_configs = [conf for conf in unique_raw if self.is_valid_config(conf)]
        logger.info(f"Валидация: к проверке допущено {len(valid_configs)} из {len(unique_raw)} строк.")

        if not valid_configs:
            logger.warning("Нет валидных конфигураций для обработки.")
            return

        async with aiohttp.ClientSession() as session:
            # 1. Скачиваем обе базы параллельно
            await self.fetch_external_lists(session, cidr_url, whitelist_url)

            # 2. Массовый асинхронный пинг
            resolver = AsyncDNSResolver(session)
            pinger = ConfigPinger(resolver, max_concurrent=self.max_concurrent, timeout=self.timeout)
            
            logger.info("Запуск параллельной проверки портов...")
            alive_results = await pinger.check_configs(valid_configs)
            logger.info(f"Доступные живые серверы: {len(alive_results)}")

            # 3. Разделение по спискам на основе скачанных баз
            whitelist = []
            blacklist = []

            for config, host, ip in alive_results:
                if self.is_whitelisted(host, ip):
                    whitelist.append(config)
                else:
                    blacklist.append(config)

            # Форматируем текстовые блоки
            whitelist_content = "\n".join(whitelist) + ("\n" if whitelist else "")
            blacklist_content = "\n".join(blacklist) + ("\n" if blacklist else "")
            stats_content = json.dumps({
                "total_whitelist": len(whitelist), 
                "total_blacklist": len(blacklist)
            }, indent=4, ensure_ascii=False)

            # 4. Асинхронный деплой результатов (GitHub + Telegram)
            tasks = []

            if gh_token and gh_repo:
                logger.info("Добавляем задачи пуша в GitHub...")
                gh = GithubManager(session, gh_token, gh_repo)
                tasks.append(gh.upload_file("whitelist.txt", whitelist_content, "Update whitelist.txt [CI]"))
                tasks.append(gh.upload_file("blacklist.txt", blacklist_content, "Update blacklist.txt [CI]"))
                tasks.append(gh.upload_file("stats.json", stats_content, "Update stats.json [CI]"))

            if tg_token and tg_chat_id:
                logger.info("Добавляем задачу отправки уведомления в Telegram...")
                tg = TelegramManager(session, tg_token, tg_chat_id)
                tasks.append(tg.send_summary(len(whitelist), len(blacklist)))

            if tasks:
                await asyncio.gather(*tasks)
            else:
                with open("whitelist.txt", "w", encoding="utf-8") as f: f.write(whitelist_content)
                with open("blacklist.txt", "w", encoding="utf-8") as f: f.write(blacklist_content)
                with open("stats.json", "w", encoding="utf-8") as f: f.write(stats_content)
                logger.info("Конфигурации сохранены локально на диск.")


if __name__ == "__main__":
    # Тестовый пул прокси-строк
    test_pool = [
        "vless://uuid@1.2.3.4:443?type=tcp&security=reality&sni=google.com",
    ]
    
    # Ссылки на внешние списки
    CIDR_LIST_URL = "https://github.com/hxehex/russia-mobile-internet-whitelist/raw/refs/heads/main/cidrwhitelist.txt"
    DOMAINS_LIST_URL = "https://github.com/hxehex/russia-mobile-internet-whitelist/raw/refs/heads/main/whitelist.txt"
    
    collector = VPNConfigCollector(timeout=1.5, max_concurrent=300)
    
    asyncio.run(collector.process(
        raw_configs_pool=test_pool,
        cidr_url=CIDR_LIST_URL,
        whitelist_url=DOMAINS_LIST_URL,
        gh_token=None,       
        gh_repo=None,        
        tg_token=None,       
        tg_chat_id=None      
    ))
