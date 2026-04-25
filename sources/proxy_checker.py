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
import json

# --- КОНФИГУРАЦИЯ ---
MY_CHANNEL = "@flat447"
TIMEOUT = 6  # Увеличено для более стабильной проверки через ТСПУ
MAX_WORKERS = 200 
MSK_TZ = zoneinfo.ZoneInfo("Europe/Moscow")
REPO_NAME = "FLAT447/v2ray-lists"

# Использование стабильных агрегаторов российских подсетей
CIDR_SOURCES = [
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv4-aggregated.txt"
]

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/MTProto.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Argh94/telegram-proxy-scraper/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies-tested.txt",
    "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/mtproto.txt",
    "https://t.me/mtp4tg",
    "https://t.me/TProxyRU",
    "https://t.me/ProxyMTProto",
    "https://t.me/ProxyFree_Ru",
    "https://t.me/TelMTProto",
    "https://t.me/telega_proxies",
    "https://t.me/mtpro_xyz"
]

DOH_SERVERS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]

TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TG_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID")
GH_TOKEN = os.environ.get("MY_TOKEN")

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# --- ФУНКЦИИ ---

def get_faketls_domain(secret):
    """Извлекает домен маскировки из секрета FakeTLS для проверки его валидности"""
    secret = secret.lower()
    if not secret.startswith('ee') or len(secret) <= 34:
        return None
    try:
        domain_hex = secret[34:]
        domain = bytes.fromhex(domain_hex).decode('utf-8', errors='ignore')
        return domain if '.' in domain else None
    except:
        return None

def is_socks5_proxy(link):
    if 'socks' in link.lower(): return True
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    return params.get('user') and (params.get('pass') or params.get('password'))

def validate_mtproto_link(link):
    """Проверяет валидность MTProto и наличие FakeTLS (критично для БС)"""
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    
    server = params.get('server', [None])[0]
    port = params.get('port', [None])[0]
    secret = params.get('secret', [None])[0]
    
    if not server or not port or not secret:
        return False
    
    # ПРОВЕРКА: Только FakeTLS (начинается с ee) выживает при БС
    if not secret.lower().startswith('ee'):
        return False
        
    # Дополнительная проверка на наличие зашитого домена
    if not get_faketls_domain(secret):
        return False

    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535): return False
    except:
        return False
    
    return True

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
    async with semaphore:
        try:
            parsed = urlparse(link)
            params = parse_qs(parsed.query)
            server = params.get('server', [None])[0]
            port = params.get('port', [None])[0]
            if not server or not port: return None

            ip = await resolve_doh(session, server)
            if not ip: return None

            start_time = time.perf_counter()
            try:
                # В условиях БС важно проверять именно TCP хендшейк с чуть большим таймаутом
                conn = asyncio.open_connection(ip, int(port))
                reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                latency = int((time.perf_counter() - start_time) * 1000)
                writer.close()
                await writer.wait_closed()
            except: return None

            ip_obj = ipaddress.ip_address(ip)
            is_in_cidr = any(ip_obj in net for net in networks)
            
            query = params.copy()
            query['channel'] = [MY_CHANNEL]
            new_query = urlencode(query, doseq=True, safe='@')
            final_link = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))

            return {"link": final_link, "type": "white" if is_in_cidr else "black", "latency": latency, "id": f"{ip}:{port}"}
        except: return None

def update_github(white_content, black_content):
    if not GH_TOKEN: return
    try:
        auth = Auth.Token(GH_TOKEN)
        g = Github(auth=auth)
        repo = g.get_repo(REPO_NAME)
        now_str = datetime.now(MSK_TZ).strftime('%H:%M | %d.%m.%Y')

        # 1. Обновление текстовых файлов
        files = {"whitelist.txt": white_content, "blacklist.txt": black_content}
        for path, content in files.items():
            try:
                curr = repo.get_contents(path)
                commit_msg = f"🚀 Обновление {path} по часовому поясу Европа/Москва: {now_str}"
                repo.update_file(path, commit_msg, content, curr.sha)
                logger.info(f"GitHub: {path} обновлен.")
            except:
                repo.create_file(path, f"Create {path} {now_str}", content)

        # 2. Обновление статистики
        stats_path = "stats.json"
        white_count = len(white_content.splitlines()) if white_content else 0
        black_count = len(black_content.splitlines()) if black_content else 0

        try:
            curr_file = repo.get_contents(stats_path)
            current_stats = json.loads(curr_file.decoded_content.decode())
        except:
            current_stats = {}

        current_stats["last_global_update"] = now_str
        if "files" not in current_stats: current_stats["files"] = {}
        current_stats["files"]["mtproto"] = {
            "white_count": white_count,
            "black_count": black_count,
            "updated": now_str
        }

        new_content = json.dumps(current_stats, indent=2, ensure_ascii=False)
        commit_msg_stats = f"📊 Обновление статистики MTProto {now_str}"

        try:
            repo.update_file(stats_path, commit_msg_stats, new_content, curr_file.sha)
        except:
            repo.create_file(stats_path, f"Create {stats_path} {now_str}", new_content)

    except Exception as e:
        logger.error(f"GitHub Error: {e}")

async def send_telegram_msg(white_list, black_list):
    if not TG_BOT_TOKEN: return
    now = datetime.now(MSK_TZ)
    top_white = "\n".join([f"💎 {p['link']}" for p in white_list[:3]]) or "<i>Пусто</i>"
    top_black = "\n".join([f"🔌 {p['link']}" for p in black_list[:3]]) or "<i>Пусто</i>"

    text = (
        f"<b>🔔 Списки MTProxy обновлены!</b>\n"
        f"🕒 {now.strftime('%H:%M | %d.%m.%Y')}\n\n"
        f"✅ <b>Белые Списки:</b>\n{top_white}\n\n"
        f"🌐 <b>Чёрные Списки:</b>\n{top_black}\n\n"
        f"🔹 <a href='https://github.com/{REPO_NAME}/blob/main/whitelist.txt'>whitelist.txt</a> ({len(white_list)})\n"
        f"🔸 <a href='https://github.com/{REPO_NAME}/blob/main/blacklist.txt'>blacklist.txt</a> ({len(black_list)})\n\n"
        f"📍 <a href='https://github.com/{REPO_NAME}'>Репозиторий проекта</a>\n"
        f"⚡️ <a href='https://flat447.github.io/v2ray-lists-site'>Сайт проекта</a>"
    )

    async with aiohttp.ClientSession() as session:
        for cid in [TG_CHAT_ID, TG_CHANNEL_ID]:
            if not cid: continue
            try:
                await session.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", 
                    json={"chat_id": cid, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True})
            except Exception as e: logger.error(f"TG Error: {e}")

async def main():
    logger.info("Запуск процесса фильтрации для БС...")
    async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
        # 1. Загрузка CIDR
        networks = []
        for url in CIDR_SOURCES:
            try:
                async with session.get(url, timeout=10) as r:
                    if r.status == 200:
                        lines = (await r.text()).splitlines()
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                try: networks.append(ipaddress.ip_network(line, strict=False))
                                except: continue
            except: pass
        networks = list(ipaddress.collapse_addresses(networks))
        logger.info(f"Загружено {len(networks)} RU подсетей.")

        # 2. Сбор и жесткая фильтрация FakeTLS
        all_links = set()
        for url in PROXY_SOURCES:
            try:
                async with session.get(url, timeout=15) as r:
                    content = await r.text()
                    found = re.findall(r'(tg://(?:proxy|socks)\?\S+|https?://t\.me/(?:proxy|socks)\?\S+)', content)
                    for link in found:
                        if not is_socks5_proxy(link) and validate_mtproto_link(link):
                            all_links.add(link)
            except Exception as e:
                logger.error(f"Ошибка сбора из {url}: {e}")

        logger.info(f"Собрано {len(all_links)} потенциально рабочих FakeTLS ссылок.")

        # 3. Проверка работоспособности
        sem = asyncio.Semaphore(MAX_WORKERS)
        tasks = [check_proxy(session, link, networks, sem) for link in all_links]
        results = await asyncio.gather(*tasks)

        # 4. Фильтрация дублей и сортировка
        unique_map = {}
        for p in [r for r in results if r]:
            pid = p['id']
            if pid not in unique_map or p['latency'] < unique_map[pid]['latency']:
                unique_map[pid] = p

        white_list = sorted([p for p in unique_map.values() if p['type'] == 'white'], key=lambda x: x['latency'])
        black_list = sorted([p for p in unique_map.values() if p['type'] == 'black'], key=lambda x: x['latency'])

        logger.info(f"Итог: Вайтлист: {len(white_list)}, Блэклист: {len(black_list)}")

        # 5. Сохранение
        await asyncio.to_thread(update_github, "\n".join([p['link'] for p in white_list]), "\n".join([p['link'] for p in black_list]))
        await send_telegram_msg(white_list, black_list)
        logger.info("Готово!")

if __name__ == "__main__":
    asyncio.run(main())
