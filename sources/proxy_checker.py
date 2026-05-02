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
import cloudscraper 

MY_CHANNEL = "@flat447"
TIMEOUT = 6  
MAX_WORKERS = 200 
TIMEZONE = zoneinfo.ZoneInfo("Europe/Moscow")
REPO_NAME = "FLAT447/v2ray-lists"

CIDR_SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/RU-ipv4-Hackers.Zone.txt",
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv4-aggregated.txt"
]

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/MTProto.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Argh94/telegram-proxy-scraper/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies-tested.txt",
    "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/mtproto.txt"
]

EXTERNAL_SITES = [
    "https://mtprobe.cyou/en/",
    "https://mtpro.xyz/en/"
]

DOH_SERVERS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]

TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TG_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID")
GH_TOKEN = os.environ.get("MY_TOKEN")

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def get_faketls_domain(secret):
    """Извлекает домен маскировки из секрета FakeTLS"""
    secret = secret.lower()
    if not secret.startswith('ee') or len(secret) <= 34:
        return None
    try:
        domain_hex = secret[34:]
        domain = bytes.fromhex(domain_hex).decode('utf-8', errors='ignore')
        return domain if '.' in domain else None
    except:
        return None

def validate_mtproto_link(link):
    """Жесткая валидация для работы при БС"""
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    server = params.get('server', [None])[0]
    port = params.get('port', [None])[0]
    secret = params.get('secret', [None])[0]
    
    if not server or not port or not secret:
        return False
    
    if not secret.lower().startswith('ee'):
        return False
        
    if not get_faketls_domain(secret):
        return False

    try:
        if not (1 <= int(port) <= 65535): return False
    except: return False
    
    return True

def scrape_with_cloudscraper(urls):
    """Синхронный скрапинг сайтов с Cloudflare"""
    found_links = []
    scraper = cloudscraper.create_scraper()
    for url in urls:
        try:
            logger.info(f"Скрапинг через Cloudscraper: {url}")
            resp = scraper.get(url, timeout=15)
            if resp.status_code == 200:
                links = re.findall(r'(tg://proxy\?\S+|https?://t\.me/proxy\?\S+)', resp.text)
                found_links.extend(links)
        except Exception as e:
            logger.error(f"Ошибка Cloudscraper на {url}: {e}")
    return found_links

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

            return {
                "link": final_link, 
                "type": "white" if is_in_cidr else "black", 
                "latency": latency, 
                "id": f"{ip}:{port}",
                "port": int(port)
            }
        except: return None

def update_github(white_content, black_content):
    if not GH_TOKEN: return
    try:
        auth = Auth.Token(GH_TOKEN)
        g = Github(auth=auth)
        repo = g.get_repo(REPO_NAME)
        now_str = datetime.now(TIMEZONE).strftime('%H:%M | %d.%m.%Y')

        files = {"whitelist.txt": white_content, "blacklist.txt": black_content}
        for path, content in files.items():
            try:
                curr = repo.get_contents(path)
                commit_msg = f"🚀 Обновление {path} по часовому поясу Европа/Москва: {now_str}"
                repo.update_file(path, commit_msg, content, curr.sha)
            except:
                repo.create_file(path, f"Create {path} {now_str}", content)

        stats_path = "stats.json"
        try:
            curr_file = repo.get_contents(stats_path)
            stats = json.loads(curr_file.decoded_content.decode())
        except: stats = {}

        stats["last_global_update"] = now_str
        if "files" not in stats: stats["files"] = {}
        stats["files"]["mtproto"] = {
            "white_count": len(white_content.splitlines()) if white_content else 0,
            "black_count": len(black_content.splitlines()) if black_content else 0,
            "updated": now_str
        }

        new_stats_content = json.dumps(stats, indent=2, ensure_ascii=False)
        commit_msg_stats = f"📊 Обновление статистики MTProto {now_str}"
        try:
            repo.update_file(stats_path, commit_msg_stats, new_stats_content, curr_file.sha)
        except:
            repo.create_file(stats_path, f"Create {stats_path} {now_str}", new_stats_content)

    except Exception as e: logger.error(f"GitHub Error: {e}")

async def send_telegram_msg(white_list, black_list):
    if not TG_BOT_TOKEN: return
    now = datetime.now(TIMEZONE)
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
    logger.info("Запуск обновления...")
    async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
        networks = []
        for url in CIDR_SOURCES:
            try:
                async with session.get(url, timeout=10) as r:
                    if r.status == 200:
                        lines = (await r.text()).splitlines()
                        for line in lines:
                            if line.strip() and not line.startswith('#'):
                                try: networks.append(ipaddress.ip_network(line.strip(), strict=False))
                                except: continue
            except: pass
        networks = list(ipaddress.collapse_addresses(networks))

        all_links = set()
        
        for url in PROXY_SOURCES:
            try:
                async with session.get(url, timeout=15) as r:
                    found = re.findall(r'(tg://(?:proxy|socks)\?\S+|https?://t\.me/(?:proxy|socks)\?\S+)', await r.text())
                    for l in found:
                        if validate_mtproto_link(l): all_links.add(l)
            except: pass
            
        external_links = await asyncio.to_thread(scrape_with_cloudscraper, EXTERNAL_SITES)
        for l in external_links:
            if validate_mtproto_link(l): all_links.add(l)

        logger.info(f"Всего валидных FakeTLS ссылок собрано: {len(all_links)}")

        sem = asyncio.Semaphore(MAX_WORKERS)
        tasks = [check_proxy(session, link, networks, sem) for link in all_links]
        results = await asyncio.gather(*tasks)

        unique_map = {}
        for p in [r for r in results if r]:
            pid = p['id']
            if pid not in unique_map or p['latency'] < unique_map[pid]['latency']:
                unique_map[pid] = p

        white_list = sorted(
            [p for p in unique_map.values() if p['type'] == 'white'], 
            key=lambda x: (x['port'] != 443, x['latency'])
        )
        black_list = sorted(
            [p for p in unique_map.values() if p['type'] == 'black'], 
            key=lambda x: (x['port'] != 443, x['latency'])
        )

        await asyncio.to_thread(update_github, "\n".join([p['link'] for p in white_list]), "\n".join([p['link'] for p in black_list]))
        await send_telegram_msg(white_list, black_list)
        logger.info("Готово!")

if __name__ == "__main__":
    asyncio.run(main())
