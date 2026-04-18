import asyncio
import aiohttp
import socket
import ipaddress
import re
import logging
import os
import time
from datetime import datetime
import zoneinfo
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from github import Github, Auth
from async_lru import alru_cache

# --- КОНФИГУРАЦИЯ ---
MY_CHANNEL = "@flat447"
TIMEOUT = 4  # Секунд на проверку (отсекаем медленные прокси)
MAX_CONCURRENT_TASKS = 200 # Лимит одновременных соединений
MSK_TZ = zoneinfo.ZoneInfo("Europe/Moscow")
REPO_NAME = "FLAT447/v2ray-lists"

CIDR_SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/RU-ipv4-Hackers.Zone.txt"
]

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/all.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Argh94/telegram-proxy-scraper/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies-tested.txt",
    "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/mtproto.txt"
]

DOH_SERVERS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]

# Переменные окружения
TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TG_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID")
GH_TOKEN = os.environ.get("MY_TOKEN")

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# --- ФУНКЦИИ ---

@alru_cache(maxsize=1024)
async def resolve_doh(session, hostname):
    """Асинхронный резолвер с кэшированием."""
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError: pass

    for provider in DOH_SERVERS:
        try:
            params = {"name": hostname, "type": "A"}
            async with session.get(provider, params=params, headers={"accept": "application/dns-json"}, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if "Answer" in data:
                        for ans in data["Answer"]:
                            if ans["type"] == 1: return ans["data"]
        except: continue
    return None

async def check_proxy(session, link, networks, semaphore):
    """Проверка доступности с замером задержки (Latency)."""
    async with semaphore:
        try:
            parsed = urlparse(link)
            params = parse_qs(parsed.query)
            server = params.get('server', [None])[0]
            port = params.get('port', [None])[0]
            
            if not server or not port: return None

            ip = await resolve_doh(session, server)
            if not ip: return None

            # Замер задержки (RTT)
            start_time = time.perf_counter()
            try:
                conn = asyncio.open_connection(ip, int(port))
                reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                latency = int((time.perf_counter() - start_time) * 1000)
                writer.close()
                await writer.wait_closed()
            except:
                return None

            # Определяем тип по CIDR (Белый - РФ, Черный - мир)
            ip_obj = ipaddress.ip_address(ip)
            is_in_cidr = any(ip_obj in net for net in networks)
            
            # Формируем финальную ссылку с вашим каналом
            query = params.copy()
            query['channel'] = [MY_CHANNEL]
            new_query = urlencode(query, doseq=True, safe='@')
            final_link = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))

            return {
                "link": final_link, 
                "type": "white" if is_in_cidr else "black",
                "latency": latency,
                "id": f"{ip}:{port}" # Для дедупликации
            }
        except:
            return None

def update_github(white_content, black_content):
    """Обновление файлов в репозитории через GitHub API."""
    if not GH_TOKEN:
        logger.warning("GH_TOKEN не найден. Пропускаю.")
        return
    try:
        auth = Auth.Token(GH_TOKEN)
        g = Github(auth=auth)
        repo = g.get_repo(REPO_NAME)
        now_str = datetime.now(MSK_TZ).strftime('%d.%m.%Y %H:%M')
        
        files = {"whitelist.txt": white_content, "blacklist.txt": black_content}

        for path, content in files.items():
            try:
                curr = repo.get_contents(path)
                repo.update_file(path, f"🚀 Latency Sort Update: {now_str}", content, curr.sha)
                logger.info(f"GitHub: {path} обновлен.")
            except:
                repo.create_file(path, f"Create {path} {now_str}", content)
                logger.info(f"GitHub: {path} создан.")
    except Exception as e:
        logger.error(f"GitHub Error: {e}")

async def send_telegram_msg(white_list, black_list):
    """Отправка отчета с ТОП-3 быстрыми ссылками."""
    if not TG_BOT_TOKEN: return
    
    now = datetime.now(MSK_TZ)
    # Формируем список ссылок (тег <code> позволяет копировать нажатием)
    top_white = "\n".join([f"💎 <code>{p['link']}</code>" for p in white_list[:3]]) or "<i>Нет доступных</i>"
    top_black = "\n".join([f"🔌 <code>{p['link']}</code>" for p in black_list[:3]]) or "<i>Нет доступных</i>"

    text = (
        f"<b>🔔 Обновление MTProxy</b>\n"
        f"🕒 {now.strftime('%H:%M | %d.%m.%Y')}\n\n"
        f"✅ <b>Для работы в РФ (Белый список):</b>\n{top_white}\n\n"
        f"🌐 <b>Зарубежные (Черный список):</b>\n{top_black}\n\n"
        f"📊 Всего проверено и отсортировано:\n"
        f"└ Белых: {len(white_list)} | Остальных: {len(black_list)}\n\n"
        f"📍 <a href='https://github.com/{REPO_NAME}'>Исходники и полные списки</a>"
    )

    async with aiohttp.ClientSession() as session:
        for cid in [TG_CHAT_ID, TG_CHANNEL_ID]:
            if not cid: continue
            try:
                await session.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", 
                                   json={"chat_id": cid, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True})
            except Exception as e:
                logger.error(f"Ошибка TG ({cid}): {e}")

async def main():
    logger.info("Запуск процесса...")
    
    async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
        # 1. Загрузка сетей CIDR
        networks = []
        for url in CIDR_SOURCES:
            try:
                async with session.get(url) as r:
                    lines = (await r.text()).splitlines()
                    for line in lines:
                        if line.strip() and not line.startswith('#'):
                            try: networks.append(ipaddress.ip_network(line.strip(), strict=False))
                            except: continue
            except Exception as e:
                logger.error(f"Ошибка загрузки CIDR: {e}")
        
        # Схлопываем подсети для ускорения поиска
        networks = list(ipaddress.collapse_addresses(networks))

        # 2. Сбор ссылок из всех источников
        all_links = set()
        for url in PROXY_SOURCES:
            try:
                async with session.get(url, timeout=15) as r:
                    content = await r.text()
                    links = re.findall(r'(tg://(?:proxy|socks)\?\S+|https?://t\.me/(?:proxy|socks)\?\S+)', content)
                    all_links.update(links)
            except Exception as e:
                logger.info(f"Источник {url} недоступен (пропуск).")

        logger.info(f"Найдено {len(all_links)} ссылок. Начинаю проверку...")

        # 3. Асинхронная проверка с семафором
        sem = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
        tasks = [check_proxy(session, link, networks, sem) for link in all_links]
        results = await asyncio.gather(*tasks)

        # 4. Фильтрация дублей и распределение
        valid_proxies = [r for r in results if r]
        
        # Дедупликация: если IP:Port повторяется, берем тот, где пинг ниже
        unique_map = {}
        for p in valid_proxies:
            pid = p['id']
            if pid not in unique_map or p['latency'] < unique_map[pid]['latency']:
                unique_map[pid] = p

        # Разделение по спискам
        white_list = [p for p in unique_map.values() if p['type'] == 'white']
        black_list = [p for p in unique_map.values() if p['type'] == 'black']

        # Сортировка по задержке (быстрые в начале)
        white_list.sort(key=lambda x: x['latency'])
        black_list.sort(key=lambda x: x['latency'])

        # 5. Сохранение на GitHub
        white_final = "\n".join([p['link'] for p in white_list])
        black_final = "\n".join([p['link'] for p in black_list])
        
        # Выносим синхронный вызов GitHub за пределы асинхронной сессии
        await asyncio.to_thread(update_github, white_final, black_final)
        
        # 6. Уведомление в Telegram
        await send_telegram_msg(white_list, black_list)
        
        logger.info(f"Готово! Белых: {len(white_list)}, Остальных: {len(black_list)}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
