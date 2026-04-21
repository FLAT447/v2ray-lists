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
TIMEOUT = 4  
MAX_WORKERS = 200 
MSK_TZ = zoneinfo.ZoneInfo("Europe/Moscow")
REPO_NAME = "FLAT447/v2ray-lists"

CIDR_SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/RU-ipv4-Hackers.Zone.txt"
]

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/MTProto.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
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

def is_socks5_proxy(link):
    """Проверяет, является ли ссылка SOCKS5 прокси - такие нужно отсеивать"""
    # Проверяем наличие слова socks в ссылке
    if 'socks' in link.lower():
        return True
    
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    
    # Проверяем наличие параметров, характерных для SOCKS5
    user = params.get('user', [None])[0]
    password = params.get('pass', [None])[0] or params.get('password', [None])[0]
    
    # SOCKS5 прокси обычно имеют параметры user и pass
    if user is not None and password is not None:
        return True
    
    return False

def validate_mtproto_link(link):
    """Проверяет валидность MTProto ссылки"""
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    
    # Проверяем наличие обязательных параметров для MTProto
    server = params.get('server', [None])[0]
    port = params.get('port', [None])[0]
    secret = params.get('secret', [None])[0]
    
    # MTProto прокси должен иметь server, port и secret
    if not server or not port or not secret:
        return False
    
    # Проверяем формат secret (должен быть hex строкой)
    try:
        int(secret, 16)
    except ValueError:
        return False
    
    # Проверяем, что порт - число в допустимом диапазоне
    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return False
    except ValueError:
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
    """Обновляет whitelist.txt, blacklist.txt и stats.json в репозитории."""
    if not GH_TOKEN:
        return
    try:
        auth = Auth.Token(GH_TOKEN)
        g = Github(auth=auth)
        repo = g.get_repo(REPO_NAME)
        now_str = datetime.now(MSK_TZ).strftime('%H:%M | %d.%m.%Y')
        now_iso = datetime.now(MSK_TZ).isoformat()

        # 1. Обновление текстовых файлов (whitelist.txt и blacklist.txt)
        files = {"whitelist.txt": white_content, "blacklist.txt": black_content}
        for path, content in files.items():
            try:
                curr = repo.get_contents(path)
                commit_msg = f"🚀 Обновление {path} по часовому поясу Европа/Москва: {now_str}"
                repo.update_file(path, commit_msg, content, curr.sha)
                logger.info(f"GitHub: {path} обновлен.")
            except:
                repo.create_file(path, f"Create {path} {now_str}", content)

        # 2. Обновление stats.json (поиск секции и частичное обновление)
        stats_path = "stats.json"
        white_count = len(white_content.splitlines()) if white_content else 0
        black_count = len(black_content.splitlines()) if black_content else 0

        try:
            curr_file = repo.get_contents(stats_path)
            current_stats = json.loads(curr_file.decoded_content.decode())
        except:
            # Если файла нет, создаём начальную структуру (но она уже есть, поэтому этот блок редко сработает)
            current_stats = {}

        # Обновляем глобальное время последнего обновления
        current_stats["last_global_update"] = now_str

        # Убеждаемся, что объект "files" существует
        if "files" not in current_stats:
            current_stats["files"] = {}

        # Добавляем / обновляем секцию "mtproto" внутри "files"
        current_stats["files"]["mtproto"] = {
            "white_count": white_count,
            "black_count": black_count,
            "updated": now_str
        }

        new_content = json.dumps(current_stats, indent=2, ensure_ascii=False)
        commit_msg_stats = f"📊 Обновление статистики MTProto {now_str}"

        try:
            repo.update_file(stats_path, commit_msg_stats, new_content, curr_file.sha)
            logger.info(f"GitHub: {stats_path} обновлен.")
        except NameError:
            repo.create_file(stats_path, f"Create {stats_path} {now_str}", new_content)
            logger.info(f"GitHub: {stats_path} создан.")

    except Exception as e:
        logger.error(f"GitHub Error: {e}")

async def send_telegram_msg(white_list, black_list):
    if not TG_BOT_TOKEN: return
    now = datetime.now(MSK_TZ)

    # Изначальный стиль формирования списка ТОП-3
    top_white = "\n".join([f"💎 {p['link']}" for p in white_list[:3]]) or "<i>Пусто</i>"
    top_black = "\n".join([f"🔌 {p['link']}" for p in black_list[:3]]) or "<i>Пусто</i>"

    # Изначальный текст сообщения
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
    logger.info("Запуск...")
    async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
        # 1. CIDR
        networks = []
        for url in CIDR_SOURCES:
            try:
                async with session.get(url) as r:
                    lines = (await r.text()).splitlines()
                    for line in lines:
                        if line.strip() and not line.startswith('#'):
                            try: networks.append(ipaddress.ip_network(line.strip(), strict=False))
                            except: continue
            except: pass
        networks = list(ipaddress.collapse_addresses(networks))

        # 2. Сбор ссылок с фильтрацией SOCKS5 и валидацией MTProto
        all_links = set()
        socks5_count = 0
        invalid_mtproto_count = 0
        
        for url in PROXY_SOURCES:
            try:
                async with session.get(url, timeout=10) as r:
                    found_links = re.findall(r'(tg://(?:proxy|socks)\?\S+|https?://t\.me/(?:proxy|socks)\?\S+)', await r.text())
                    
                    for link in found_links:
                        # Отсеиваем SOCKS5 прокси
                        if is_socks5_proxy(link):
                            socks5_count += 1
                            continue
                        
                        # Проверяем валидность MTProto
                        if validate_mtproto_link(link):
                            all_links.add(link)
                        else:
                            invalid_mtproto_count += 1
                            
            except Exception as e:
                logger.error(f"Ошибка при сборе из {url}: {e}")

        logger.info(f"Статистика сбора: SOCKS5 отсеяно - {socks5_count}, невалидных MTProto - {invalid_mtproto_count}")
        logger.info(f"Всего собрано {len(all_links)} валидных MTProto ссылок")

        # 3. Проверка работоспособности
        sem = asyncio.Semaphore(MAX_WORKERS)
        tasks = [check_proxy(session, link, networks, sem) for link in all_links]
        results = await asyncio.gather(*tasks)

        # 4. Фильтрация и Сортировка
        unique_map = {}
        for p in [r for r in results if r]:
            pid = p['id']
            if pid not in unique_map or p['latency'] < unique_map[pid]['latency']:
                unique_map[pid] = p

        white_list = sorted([p for p in unique_map.values() if p['type'] == 'white'], key=lambda x: x['latency'])
        black_list = sorted([p for p in unique_map.values() if p['type'] == 'black'], key=lambda x: x['latency'])

        logger.info(f"Итоговая статистика: Белый список - {len(white_list)} прокси, Черный список - {len(black_list)} прокси")

        # 5. Сохранение и ТГ
        await asyncio.to_thread(update_github, "\n".join([p['link'] for p in white_list]), "\n".join([p['link'] for p in black_list]))
        await send_telegram_msg(white_list, black_list)
        logger.info("Готово!")

if __name__ == "__main__":
    asyncio.run(main())
