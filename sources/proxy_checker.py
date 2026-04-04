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

# --- КОНФИГУРАЦИЯ ---
MY_CHANNEL = "@flat447"
TIMEOUT = 3
MAX_WORKERS = 100
# Указываем часовой пояс для Москвы
MSK_TZ = zoneinfo.ZoneInfo("Europe/Moscow")

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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def resolve_doh(hostname):
    """Преобразует домен в IP через DoH или обычный DNS."""
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
                        if ans["type"] == 1:
                            return ans["data"]
        except Exception:
            continue
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def check_proxy(link, networks):
    """
    Проверяет прокси:
    - извлекает server и port
    - резолвит IP
    - проверяет вхождение IP в CIDR-сети
    - возвращает ссылку с добавленным параметром channel и тип ('white' или 'black')
    """
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        server = params.get('server', [None])[0]
        port = params.get('port', [None])[0]
        if not server or not port:
            return None

        ip = resolve_doh(server)
        if not ip:
            return None

        # Проверяем соединение
        with socket.create_connection((ip, int(port)), timeout=TIMEOUT):
            # Определяем тип по CIDR
            is_in_cidr = any(ipaddress.ip_address(ip) in net for net in networks)
            final_mode = "white" if is_in_cidr else "black"

            # Добавляем канал в параметры ссылки
            query = parse_qs(parsed.query)
            query['channel'] = [MY_CHANNEL]
            new_query = urlencode(query, doseq=True, safe='@')
            final_link = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))

            return {"link": final_link, "type": final_mode}
    except Exception:
        return None


def send_telegram_msg(white_list, black_list):
    """Отправляет сообщение с топ-3 прокси каждого типа и ссылками на полные списки."""
    if not TG_BOT_TOKEN:
        logger.error("TG_BOT_TOKEN not set!")
        return

    recipients = [r for r in [TG_CHAT_ID, TG_CHANNEL_ID] if r]
    now = datetime.now(MSK_TZ)

    top_white = white_list[:3]
    top_black = black_list[:3]

    white_links_text = "\n".join([f"💎 {l}" for l in top_white]) if top_white else "<i>Список пуст</i>"
    black_links_text = "\n".join([f"🔌 {l}" for l in top_black]) if top_black else "<i>Список пуст</i>"

    text = (
        "<b>🔔 Списки прокси обновлены!</b>\n\n"
        f"🕒 <i>Время: {now.strftime('%H:%M')} | {now.strftime('%d.%m.%Y')}</i>\n\n"
        f"✅ <b>Топ Белых Прокси:</b>\n{white_links_text}\n\n"
        f"🌐 <b>Топ Чёрных Прокси:</b>\n{black_links_text}\n\n"
        "--- — -- — ---\n"
        f"📁 <b>Полные списки:</b>\n"
        f"🔹 <a href='https://github.com/FLAT447/v2ray-lists/blob/main/whitelist.txt'>whitelist.txt</a> ({len(white_list)} шт.)\n"
        f"🔸 <a href='https://github.com/FLAT447/v2ray-lists/blob/main/blacklist.txt'>blacklist.txt</a> ({len(black_list)} шт.)\n\n"
        f"📍 <i><a href='https://github.com/FLAT447/v2ray-lists'>Репозиторий проекта</a></i>"
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

    # 1. Загружаем CIDR-сети
    networks = []
    for url in CIDR_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        networks.append(ipaddress.ip_network(line, strict=False))
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"CIDR Load error from {url}: {e}")

    # 2. Собираем все прокси-ссылки из всех источников (без разделения на white/black)
    all_links = set()
    for url in PROXY_SOURCES:
        try:
            content = requests.get(url, timeout=10).text
            # Ищем ссылки формата tg://proxy?... или https://t.me/proxy?...
            links = re.findall(r'(tg://(?:proxy|socks)\?\S+|https?://t\.me/(?:proxy|socks)\?\S+)', content)
            all_links.update(links)
        except Exception as e:
            logger.error(f"Source fetch error from {url}: {e}")

    # 3. Параллельно проверяем все прокси
    white_res = []
    black_res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, link, networks): link for link in all_links}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                if res["type"] == "white":
                    white_res.append(res["link"])
                else:
                    black_res.append(res["link"])

    # 4. Сохраняем результаты в файлы
    with open("whitelist.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(white_res))
    with open("blacklist.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(black_res))

    logger.info(f"Complete. White: {len(white_res)}, Black: {len(black_res)}")
    send_telegram_msg(white_res, black_res)


if __name__ == "__main__":
    main()
