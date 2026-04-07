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
from github import Github, InputGitTreeElement  # Добавляем PyGithub

# --- КОНФИГУРАЦИЯ ---
MY_CHANNEL = "@flat447"
TIMEOUT = 3
MAX_WORKERS = 100
MSK_TZ = zoneinfo.ZoneInfo("Europe/Moscow")

# Параметры GitHub
GH_TOKEN = os.environ.get("GH_TOKEN")  # Создадим позже в Secrets
REPO_NAME = "FLAT447/v2ray-lists"      # Твой репозиторий

CIDR_SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/RU-ipv4-Hackers.Zone.txt"
]

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/tg-proxy/all.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/SOCKS5.txt"
]

DOH_SERVERS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query"
]

TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TG_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID")

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ... (функции resolve_doh, check_proxy, send_telegram_msg остаются без изменений) ...

def update_github(white_content, black_content):
    """Обновляет файлы в GitHub репозитории через API."""
    if not GH_TOKEN:
        logger.error("GH_TOKEN not set, skipping GitHub update")
        return

    try:
        g = Github(GH_TOKEN)
        repo = g.get_repo(REPO_NAME)
        
        now = datetime.now(MSK_TZ).strftime('%Y-%m-%d %H:%M')
        commit_message = f"Update proxy lists: {now} (MSK)"

        # Обновляем whitelist.txt
        try:
            contents = repo.get_contents("whitelist.txt")
            repo.update_file(contents.path, commit_message, white_content, contents.sha)
        except:
            repo.create_file("whitelist.txt", commit_message, white_content)

        # Обновляем blacklist.txt
        try:
            contents = repo.get_contents("blacklist.txt")
            repo.update_file(contents.path, commit_message, black_content, contents.sha)
        except:
            repo.create_file("blacklist.txt", commit_message, black_content)

        logger.info("GitHub files updated successfully.")
    except Exception as e:
        logger.error(f"GitHub update failed: {e}")

def main():
    logger.info("Starting proxy update...")

    # 1. Загрузка CIDR
    networks = []
    for url in CIDR_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            networks.extend([ipaddress.ip_network(l.strip(), strict=False) 
                            for l in r.text.splitlines() if l.strip() and not l.startswith('#')])
        except Exception as e:
            logger.error(f"CIDR error: {e}")

    # 2. Сбор ссылок
    all_links = set()
    for url in PROXY_SOURCES:
        try:
            content = requests.get(url, timeout=10).text
            all_links.update(re.findall(r'(tg://(?:proxy|socks)\?\S+|https?://t\.me/(?:proxy|socks)\?\S+)', content))
        except Exception as e:
            logger.error(f"Fetch error: {e}")

    # 3. Проверка
    white_res, black_res = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, link, networks): link for link in all_links}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                if res["type"] == "white": white_res.append(res["link"])
                else: black_res.append(res["link"])

    # 4. Сохранение локально (для отладки) и в GitHub
    white_txt = "\n".join(white_res)
    black_txt = "\n".join(black_res)
    
    update_github(white_txt, black_txt)
    
    logger.info(f"Complete. White: {len(white_res)}, Black: {len(black_res)}")
    send_telegram_msg(white_res, black_res)

if __name__ == "__main__":
    main()
