# =============================================================================
# parser.py - точка входа
# Генерирует 4 подписки (BLACK_FULL/BLACK_LTE/WHITE_FULL/WHITE_LITE)
# в форматах CLASH и BASE64, пишет stats.json и зеркалит в GitVerse.
# =============================================================================
import sys
import argparse
from pathlib import Path

from core import load_configs, safe_print, now_str
import pipeline


def main():
    parser = argparse.ArgumentParser(description="VPN Parser")
    parser.add_argument("--no-push", "--dry-run", dest="no_push", action="store_true",
                        help="сгенерировать файлы локально, но НЕ пушить в GitHub/GitVerse")
    args = parser.parse_args()

    load_configs()
    safe_print(f"=== VPN Parser v{pipeline.__dict__.get('__version__', '1.0')} ===")
    safe_print(f"[*] Старт: {now_str()}")

    black, white, black_mtproto, white_mtproto = pipeline.collect_configs()
    pipeline.health_check(black, white, black_mtproto, white_mtproto)
    pipeline.enrich_countries(black, white, black_mtproto, white_mtproto)
    pools = pipeline.build_pools(black, white)

    rule_urls = pipeline.download_rule_lists()

    safe_print("\n[*] Генерация подписок:")
    for name in pipeline.SUBSCRIPTIONS:
        meta = pipeline.SUB_META[name]
        pool = pools[name]
        list_key = meta["list_key"]
        list_url = rule_urls[list_key]
        pipeline.save_clash(name, pool, meta["mode"], list_url, list_key)
        pipeline.save_base64(name, pool)

    pipeline.save_mtproto_files(black_mtproto, white_mtproto)
    pipeline.write_stats(pools, black_mtproto, white_mtproto)

    if args.no_push:
        safe_print("[i] Пуш отключён флагом --no-push (файлы оставлены локально в output/)")
    else:
        pipeline.mirror_all()

    stats = {
        "black": len(pools["BLACK_FULL"]),
        "black_lte": len(pools["BLACK_LTE"]),
        "white_full": len(pools["WHITE_FULL"]),
        "white_lite": len(pools["WHITE_LITE"]),
    }
    summary = (
        f"🔄 VPN Parser обновлён\n"
        f"⏱ {now_str()}\n"
        f"BLACK_FULL: {stats['black']}\n"
        f"BLACK_LTE: {stats['black_lte']}\n"
        f"WHITE_FULL: {stats['white_full']}\n"
        f"WHITE_LITE: {stats['white_lite']}\n"
        f"mtproto: чёрн {len(black_mtproto)} / бел {len(white_mtproto)}"
    )
    pipeline.notify_telegram(summary)

    safe_print(f"[*] Готово: {now_str()}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        safe_print("\n[!] Прервано пользователем.")
        sys.exit(1)
