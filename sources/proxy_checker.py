import requests
import socket
import ipaddress
import re
import concurrent.futures
import logging
import sys
import os
from datetime import datetime
import zoneinfo
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from github import Github

# --- КОНФИГУРАЦИЯ ---
MY_CHANNEL = "@flat447"
TIMEOUT = 3
MAX_WORKERS = 100
MSK_TZ = zoneinfo.ZoneInfo("Europe/Moscow")
REPO_NAME = "FLAT447/v2ray-lists" # Убедись, что путь верный

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

DOH_SERVERS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query"
]

# Переменные окружения
TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TG_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID")
GH_TOKEN = os.environ.get("MY_TOKEN")

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# --- ФУНКЦИИ ---

def resolve_doh(hostname):
    """DNS-over-HTTPS резолвер."""
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    for provider in DOH_SERVERS:
        try:
            params = {"name": hostname, "type": "A"}
            resp = requests.get(provider, params=params, headers={"accept": "application/dns-json"}, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if "Answer" in data:
                    for ans in data["Answer"]:
                        if ans["type"] == 1: return ans["data"]
        except Exception:
            continue
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def check_proxy(link, networks):
    """Проверка доступности и фильтрация по CIDR."""
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
            mode = "white" if is_in_cidr else "black"

            # Формируем новую ссылку с нашим каналом
            query = params.copy()
            query['channel'] = [MY_CHANNEL]
            new_query = urlencode(query, doseq=True, safe='@')
            final_link = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))

            return {"link": final_link, "type": mode}
    except Exception:
        return None

def update_github(white_content, black_content):
    """Сохранение файлов в репозиторий через PyGithub."""
    if not GH_TOKEN:
        logger.warning("GH_TOKEN не найден. Пропускаю обновление GitHub.")
        return

    try:
        g = Github(GH_TOKEN)
        repo = g.get_repo(REPO_NAME)
        now_str = datetime.now(MSK_TZ).strftime('%d.%m.%Y %H:%M')
        
        files = {
            "whitelist.txt": white_content,
            "blacklist.txt": black_content
        }

        for path, content in files.items():
            try:
                curr_file = repo.get_contents(path)
                repo.update_file(path, f"🚀 Обновление {path} по часовому поясу Европа/Москва: {now_str}", content, curr_file.sha)
                logger.info(f"Файл {path} обновлен.")
            except Exception:
                repo.create_file(path, f"Create {path} {now_str}", content)
                logger.info(f"Файл {path} создан.")
    except Exception as e:
        logger.error(f"Ошибка GitHub: {e}")

def send_telegram_msg(white_list, black_list):
    """Отправка отчета в Telegram."""
    if not TG_BOT_TOKEN: return
    
    now = datetime.now(MSK_TZ)
    top_white = "\n".join([f"💎 {l}" for l in white_list[:3]]) or "<i>Пусто</i>"
    top_black = "\n".join([f"🔌 {l}" for l in black_list[:3]]) or "<i>Пусто</i>"

    text = (
        f"<b>🔔 Списки MTProxy обновлены!</b>\n"
        f"🕒 {now.strftime('%H:%M | %d.%m.%Y')}\n\n"
        f"✅ <b>Белые Списки:</b>\n{top_white}\n\n"
        f"🌐 <b>Чёрные Списки:</b>\n{top_black}\n\n"
        f"🔹 <a href='https://github.com/{REPO_NAME}/blob/main/whitelist.txt'>whitelist.txt</a> ({len(white_list)})\n"
        f"🔸 <a href='https://github.com/{REPO_NAME}/blob/main/blacklist.txt'>blacklist.txt</a> ({len(black_list)})\n\n"
        f"📍 <a href='https://github.com/{REPO_NAME}'>Репозиторий проекта</a>\n"
        "⚡️ <a href='https://flat447.github.io/v2ray-lists-site'>Сайт проекта</a>"
    )

    for cid in [TG_CHAT_ID, TG_CHANNEL_ID]:
        if not cid: continue
        try:
            requests.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", 
                          json={"chat_id": cid, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}, timeout=10)
        except Exception as e:
            logger.error(f"Ошибка TG ({cid}): {e}")

# --- ГЛАВНЫЙ ЦИКЛ ---

def main():
    logger.info("Запуск процесса...")

    # 1. Загрузка сетей
    networks = []
    for url in CIDR_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            for line in r.text.splitlines():
                if line.strip() and not line.startswith('#'):
                    try: networks.append(ipaddress.ip_network(line.strip(), strict=False))
                    except: continue
        except Exception as e:
            logger.error(f"Ошибка загрузки CIDR: {e}")

    # 2. Сбор прокси
    all_links = set()
    for url in PROXY_SOURCES:
        try:
            content = requests.get(url, timeout=10).text
            links = re.findall(r'(tg://(?:proxy|socks)\?\S+|https?://t\.me/(?:proxy|socks)\?\S+)', content)
            all_links.update(links)
        except Exception as e:
            logger.error(f"Ошибка загрузки источников: {e}")

    # 3. Многопоточная проверка
    white_res, black_res = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Здесь check_proxy уже определена выше, ошибки NameError не будет
        future_to_link = {executor.submit(check_proxy, link, networks): link for link in all_links}
        for future in concurrent.futures.as_completed(future_to_link):
            res = future.result()
            if res:
                if res["type"] == "white": white_res.append(res["link"])
                else: black_res.append(res["link"])

    # 4. Сохранение и уведомление
    white_final = "\n".join(white_res)
    black_final = "\n".join(black_res)
    
    update_github(white_final, black_final)
    send_telegram_msg(white_res, black_res)
    logger.info("Готово!")

if __name__ == "__main__":
    main()
