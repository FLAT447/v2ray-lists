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
        # Оборачиваем внутренний метод в async_lru, привязывая кэш к текущей сессии
        self.resolve = alru_cache(maxsize=2048)(self._resolve_impl)

    async def _resolve_impl(self, domain: str) -> str | None:
        try:
            # Если это уже готовый IP — отдаем сразу
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
    Полностью асинхронный класс для отправки красивых отчетов в Telegram канал/чат.
    """
    def __init__(self, session: aiohttp.ClientSession, token: str, chat_id: str):
        self.session = session
        self.token = token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{token}/sendMessage"

    async def send_summary(self, whitelist_count: int, blacklist_count: int):
        """
        Отправляет маркдаун-сообщение со статистикой проверки.
        """
        text = (
            f"🔄 V2Ray подписки обновлены!\n"
            f"📅 Время: {time_str}\n"
            f"📊 Всего конфигураций: {total_configs}\n\n"
            f"📦 <a href=\"https://github.com/FLAT447/v2ray-lists\">Репозиторий проекта</a>\n"
            f"⚡ <a href=\"https://flat447.github.io/v2ray-lists-site\">Сайт проекта</a>"
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
    Полностью асинхронный класс для работы с репозиторием.
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

        # 1. Получаем SHA текущего файла, если он есть
        try:
            async with self.session.get(url, headers=self.headers, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    sha = data.get("sha")
        except Exception as e:
            logger.error(f"Не удалось получить SHA для {file_path}: {e}")

        # 2. Кодируем в base64
        b64_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        payload = {
            "message": commit_message,
            "content": b64_content,
            "branch": self.branch
        }
        if sha:
            payload["sha"] = sha

        # 3. Заливаем изменения
        try:
            async with self.session.put(url, headers=self.headers, json=payload) as resp:
                if resp.status in [200, 201]:
                    logger.info(f"Файл {file_path} запушен на GitHub.")
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

    async def _check_single_config(self, config: str) -> tuple[str, str | None] | None:
        async with self.semaphore:
            try:
                parsed = urlparse(config)
                host = parsed.hostname
                port = parsed.port
                
                # TCP-пинг сокета
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                
                # Безопасный вызов изолированного DoH-резолвера
                ip = await self.resolver.resolve(host)
                return config, ip
            except Exception:
                return None

    async def check_configs(self, configs: list[str]) -> list[tuple[str, str | None]]:
        tasks = [self._check_single_config(conf) for conf in configs]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]


class VPNConfigCollector:
    def __init__(self, subnets_file: str = "subnets.txt", timeout: float = 1.5, max_concurrent: int = 300):
        self.subnets_file = subnets_file
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.subnets = self.load_subnets()

    def load_subnets(self) -> list[ipaddress.IPv4Network]:
        subnets_list = []
        try:
            with open(self.subnets_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            net = ipaddress.ip_network(line, strict=False)
                            if isinstance(net, ipaddress.IPv4Network):
                                subnets_list.append(net)
                        except ValueError:
                            pass
            logger.info(f"Загружено {len(subnets_list)} IPv4 подсетей.")
        except FileNotFoundError:
            logger.error(f"Файл подсетей '{self.subnets_file}' не найден!")
        return subnets_list

    def is_ip_blocked(self, ip_str: str | None) -> bool:
        if not ip_str:
            return False
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            if ip_addr.version == 6:
                return False  # Защита от TypeError. IPv6 чист, так как база чисто IPv4.
            return any(ip_addr in subnet for subnet in self.subnets)
        except ValueError:
            return False

    def is_valid_config(self, config_url: str) -> bool:
        """Валидация структуры и жесткий чек наличия sni/peer параметров."""
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

    async def process(self, raw_configs_pool: list[str], gh_token: str = None, gh_repo: str = None, tg_token: str = None, tg_chat_id: str = None):
        # 1. Фильтруем дубли и битый мусор без SNI прямо на входе
        unique_raw = list(set(raw_configs_pool))
        valid_configs = [conf for conf in unique_raw if self.is_valid_config(conf)]
        logger.info(f"Валидация: до пинга допущено {len(valid_configs)} из {len(unique_raw)} строк.")

        if not valid_configs:
            logger.warning("Нет пригодных конфигураций для проверки.")
            return

        # Инициализация единого асинхронного контекста на всё время работы
        async with aiohttp.ClientSession() as session:
            resolver = AsyncDNSResolver(session)
            pinger = ConfigPinger(resolver, max_concurrent=self.max_concurrent, timeout=self.timeout)

            # 2. Массовый TCP-пинг узлов (таймаут 1.5 сек)
            logger.info("Запуск массовой проверки портов...")
            alive_results = await pinger.check_configs(valid_configs)
            logger.info(f"Доступные серверы: {len(alive_results)}")

            # 3. Сортировка по спискам (без ложных вылетов IPv6)
            whitelist = []
            blacklist = []

            for config, ip in alive_results:
                if self.is_ip_blocked(ip):
                    blacklist.append(config)
                else:
                    whitelist.append(config)

            # Формируем сырые текстовые пакеты
            whitelist_content = "\n".join(whitelist) + ("\n" if whitelist else "")
            blacklist_content = "\n".join(blacklist) + ("\n" if blacklist else "")
            stats_content = json.dumps({"total_whitelist": len(whitelist), "total_blacklist": len(blacklist)}, indent=4, ensure_ascii=False)

            # 4. Полностью асинхронная выгрузка результатов
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
                # Запускаем всё сетевое взаимодействие параллельно
                await asyncio.gather(*tasks)
            else:
                # Если секреты для CI не переданы, пишем дампы локально на диск
                with open("whitelist.txt", "w", encoding="utf-8") as f: f.write(whitelist_content)
                with open("blacklist.txt", "w", encoding="utf-8") as f: f.write(blacklist_content)
                with open("stats.json", "w", encoding="utf-8") as f: f.write(stats_content)
                logger.info("Конфигурации сохранены локально в txt файлы.")


if __name__ == "__main__":
    # Тестовые данные для проверки логики
    test_pool = [
        "vless://any-uuid@1.2.3.4:443?type=tcp&security=reality&sni=google.com",
        "ss://YmFzZTY0@8.8.8.8:1080?peer=some-peer-server",
        "vless://broken-config-no-sni@9.9.9.9:443?type=ws"
    ]
    
    collector = VPNConfigCollector(subnets_file="subnets.txt", timeout=1.5, max_concurrent=300)
    
    asyncio.run(collector.process(
        raw_configs_pool=test_pool,
        gh_token=None,       # Сюда передавать секрет GitHub
        gh_repo=None,        # Сюда репозиторий "owner/repo"
        tg_token=None,       # Сюда токен бота Telegram
        tg_chat_id=None      # Сюда ID чата или канала
    ))
