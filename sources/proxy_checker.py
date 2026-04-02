import requests
import socket
import ipaddress
import re
import concurrent.futures
import logging
import sys
import os
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# --- КОНФИГУРАЦИЯ ---
MY_CHANNEL = "@flat447"
TIMEOUT = 3
MAX_WORKERS = 100

# Источники данных
CIDR_SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/RU-ipv4-Hackers.Zone.txt",
    "https://raw.githubusercontent.com/WhitePrime/xraycheck/refs/heads/main/cidrlist"
]

PROXY_SOURCES = {
    "black": ["https://raw.githubusercontent.com/WhitePrime/xraycheck/refs/heads/main/configs/mtproto"],
    "white": ["https://raw.githubusercontent.com/WhitePrime/xraycheck/refs/heads/main/configs/white-list_mtproto"]
}

DOH_SERVERS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query"
]

# Telegram API (из GitHub Secrets)
TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TG_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def resolve_doh(hostname):
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    for provider in DOH_SERVERS:
        try:
            params = {"name": hostname, "type": "A"}
            headers = {"accept": "application/dns-json"}
            resp = requests.get(provider, params=params, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if "Answer" in data:
                    for ans in data["Answer"]:
                        if ans["type"] == 1: return ans["data"]
        except: continue
    try: return socket.gethostbyname(hostname)
    except: return None

def check_proxy(link, networks, expected_mode):
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        server = params.get('server', [None])[0]
        port = params.get('port', [None])[0]
        if not server or not port: return None
        
        ip = resolve_doh(server)
        if not ip: return None

        with socket.create_connection((ip, int(port)), timeout=TIMEOUT):
            is_in_cidr = any(ipaddress.ip_address(ip) in net for net in networks)
            final_mode = "white" if (expected_mode == "white" and is_in_cidr) else "black"
            
            query = parse_qs(parsed.query)
            query['channel'] = [MY_CHANNEL]
            new_query = urlencode(query, doseq=True, safe='@')
            final_link = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))
            
            return {"link": final_link, "type": final_mode}
    except: return None

def send_telegram_msg(w_count, b_count):
    """Логика и структура сообщения как в FLAT447/v2ray-lists/main.py"""
    if not TG_BOT_TOKEN:
        logger.error("TG_BOT_TOKEN not set!")
        return

    # Список получателей (чат и канал)
    recipients = [r for r in [TG_CHAT_ID, TG_CHANNEL_ID] if r]

    text = (
        "<b>🔔 Списки прокси обновлены!</b>\n\n"
        f"🕒 <i>Время: {time.strftime('%H:%M')} | {time.strftime('%d.%m.%Y')}</i>\n\n"
        f"✅ <b>Белые Списки:</b> <a href='https://github.com/FLAT447/v2ray-lists/blob/main/whitelist.txt'>whitelist.txt</a>\n"
        f"🌐 <b>Чёрные Списки:</b> <a href='https://github.com/FLAT447/v2ray-lists/blob/main/blacklist.txt'>blacklist.txt</a>\n\n"
        f"📍 <i><a href='https://github.com/FLAT447/v2ray-lists'>Репозиторий с прокси</a></i>\n"
    )
    
    for chat_id in recipients:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        try:
            r = requests.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", json=payload, timeout=10)
            if r.status_code == 200:
                logger.info(f"Message sent to {chat_id}")
            else:
                logger.error(f"Error sending to {chat_id}: {r.text}")
        except Exception as e:
            logger.error(f"Failed to send to {chat_id}: {e}")

def main():
    logger.info("Starting proxy update...")
    networks = []
    for url in CIDR_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            for line in r.text.splitlines():
                if line.strip() and not line.startswith('#'):
                    try: networks.append(ipaddress.ip_network(line.strip(), strict=False))
                    except: continue
        except: logger.error(f"CIDR Load error: {url}")

    tasks = []
    for mode, urls in PROXY_SOURCES.items():
        for url in urls:
            try:
                content = requests.get(url, timeout=10).text
                links = re.findall(r'(tg://(?:proxy|socks)\?\S+|https?://t\.me/(?:proxy|socks)\?\S+)', content)
                for l in set(links): tasks.append((l, mode))
            except: logger.error(f"Source fetch error: {url}")

    white_res, black_res = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(check_proxy, t[0], networks, t[1]) for t in tasks]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                if res["type"] == "white": white_res.append(res["link"])
                else: black_res.append(res["link"])

    with open("whitelist.txt", "w", encoding="utf-8") as f: f.write("\n".join(white_res))
    with open("blacklist.txt", "w", encoding="utf-8") as f: f.write("\n".join(black_res))
    
    logger.info(f"Complete. W:{len(white_res)} B:{len(black_res)}")
    send_telegram_msg(len(white_res), len(black_res))

if __name__ == "__main__":
    main()
