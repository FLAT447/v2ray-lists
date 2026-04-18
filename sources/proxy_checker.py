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
from github import Github
from async_lru import alru_cache

# --- КОНФИГУРАЦИЯ ---
MY_CHANNEL = "@flat447"
TIMEOUT = 4  # Оптимально для отсева медленных прокси
MAX_CONCURRENT_TASKS = 200
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

TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TG_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID")
GH_TOKEN = os.environ.get("MY_TOKEN")

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# --- ФУНКЦИИ ---

@alru_cache(maxsize=1024)
async def resolve_doh(session, hostname):
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
    """Проверка прокси с замером задержки (Latency)."""
    async with semaphore:
        try:
            parsed = urlparse(link)
            params = parse_qs(parsed.query)
            server = params.get('server', [None])[0]
            port = params.get('port', [None])[0]
            
            if not server or not port: return None

            ip = await resolve_doh(session, server)
            if not ip: return None

            # Замер задержки соединения
            start_time = time.perf_counter()
            try:
                conn = asyncio.open_connection(ip, int(port))
                reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                latency = int((time.perf_counter() - start_time) * 1000)
                writer.close()
                await writer.wait_closed()
            except:
                return None

            # Фильтрация по сетям
            ip_obj = ipaddress.ip_address(ip)
            is_in_cidr = any(ip_obj in net for net in networks)
            
            # Сборка финальной ссылки
            query = params.copy()
            query['channel'] = [MY_CHANNEL]
            new_query = urlencode(query, doseq=True, safe='@')
            final_link = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))

            return {
                "link": final_link, 
                "type": "white" if is_in_cidr else "black",
                "latency": latency,
                "id": f"{ip}:{port}" # Для удаления дублей
            }
        except:
            return None

def update_github(white_content, black_content):
    if not GH_TOKEN: return
    try:
        g = Github(GH_TOKEN)
        repo = g.get_repo(REPO_NAME)
        now_str = datetime.now(MSK_TZ).strftime('%d.%m.%Y %H:%M')
        for path, content in {"whitelist.txt": white_content, "blacklist.txt": black_content}.items():
            try:
                curr = repo.get_contents(path)
                repo.update_file(path, f"🚀 Latency Sort Update: {now_str}", content, curr.sha)
            except:
                repo.create_file(path, f"Create {path} {now_str}", content)
    except Exception as e: logger.error(f"GH Error: {e}")

async def send_telegram_msg(white_count, black_count):
    if not TG_BOT_TOKEN: return
    now = datetime.now(MSK_TZ)
    text = (
        f"<b>⚡️ Прокси обновлены и отсортированы!</b>\n"
        f"🕒 {now.strftime('%H:%M | %d.%m.%Y')}\n\n"
        f"💎 Белые (RU): <b>{white_count}</b>\n"
        f"🔌 Остальные: <b>{black_count}</b>\n\n"
        f"🚀 <i>Все прокси проверены на пинг и отсортированы по скорости.</i>"
    )
    async with aiohttp.ClientSession() as session:
        for cid in [TG_CHAT_ID, TG_CHANNEL_ID]:
            if cid:
                await session.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", 
                                   json={"chat_id": cid, "text": text, "parse_mode": "HTML"})

async def main():
    logger.info("Начало работы...")
    async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
        # 1. Сетки
        networks = []
        for url in CIDR_SOURCES:
            try:
                async with session.get(url) as r:
                    networks.extend([ipaddress.ip_network(l.strip(), False) for l in (await r.text()).splitlines() if l.strip() and not l.startswith('#')])
            except: pass
        networks = list(ipaddress.collapse_addresses(networks))

        # 2. Сбор
        all_links = set()
        for url in PROXY_SOURCES:
            try:
                async with session.get(url) as r:
                    all_links.update(re.findall(r'(tg://(?:proxy|socks)\?\S+|https?://t\.me/(?:proxy|socks)\?\S+)', await r.text()))
            except: pass

        # 3. Проверка
        sem = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
        tasks = [check_proxy(session, link, networks, sem) for link in all_links]
        results = await asyncio.gather(*tasks)

        # 4. Фильтрация дублей и сортировка
        valid_results = [r for r in results if r]
        
        # Используем словарь для дедупликации по IP:Port (оставляем самый быстрый вариант)
        unique_proxies = {}
        for p in valid_results:
            pid = p['id']
            if pid not in unique_proxies or p['latency'] < unique_proxies[pid]['latency']:
                unique_proxies[pid] = p

        # Распределение по спискам
        white_list = [p for p in unique_proxies.values() if p['type'] == 'white']
        black_list = [p for p in unique_proxies.values() if p['type'] == 'black']

        # СОРТИРОВКА ПО ПИНГУ (Latency)
        white_list.sort(key=lambda x: x['latency'])
        black_list.sort(key=lambda x: x['latency'])

        # 5. Сохранение
        update_github(
            "\n".join([p['link'] for p in white_list]),
            "\n".join([p['link'] for p in black_list])
        )
        
        await send_telegram_msg(len(white_list), len(black_list))
        logger.info("Обновление завершено успешно.")

if __name__ == "__main__":
    asyncio.run(main())
