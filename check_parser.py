from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────
# НАСТРОЙКА
# ─────────────────────────────────────────────

# Укажи здесь ИМЯ основного Python-файла.
# Например: main.py
MAIN_SCRIPT = "main.py"

REPORT_FILENAME = "parser_report.md"


# ─────────────────────────────────────────────
# ЗАГРУЗКА ОСНОВНОГО СКРИПТА
# ─────────────────────────────────────────────

def load_main_module():
    script_path = Path(MAIN_SCRIPT)

    if not script_path.exists():
        raise FileNotFoundError(
            f"Не найден основной скрипт: {MAIN_SCRIPT}"
        )

    spec = importlib.util.spec_from_file_location(
        "main_blocklist",
        script_path,
    )

    if spec is None or spec.loader is None:
        raise ImportError(
            f"Не удалось загрузить {MAIN_SCRIPT}"
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules["main_blocklist"] = module
    spec.loader.exec_module(module)

    return module


main = load_main_module()


# ─────────────────────────────────────────────
# ПРОВЕРКА ОДНОГО ИСТОЧНИКА
# ─────────────────────────────────────────────

def check_source(url: str) -> dict:
    result = {
        "url": url,
        "name": source_name(url),
        "downloaded": False,
        "total_lines": 0,
        "empty_lines": 0,
        "comments": 0,
        "parsed": 0,
        "failed": 0,
        "excluded": 0,
        "duplicates": 0,
        "unique": 0,
        "error": "",
    }

    try:
        content = main.fetch_text(url)

        result["downloaded"] = True

        seen = set()

        for raw_line in content.splitlines():
            result["total_lines"] += 1

            line = main.strip_inline_noise(raw_line)

            if not line:
                result["empty_lines"] += 1
                continue

            if line.startswith(("#", "//", "!", ";")):
                result["comments"] += 1
                continue

            normalized = main.normalize_rule(line)

            if normalized is None:
                result["failed"] += 1

                # Проверяем, не был ли он отброшен
                # именно из-за EXCLUSIONS.
                if is_excluded_line(line):
                    result["failed"] -= 1
                    result["excluded"] += 1

                continue

            result["parsed"] += 1

            if normalized in seen:
                result["duplicates"] += 1
            else:
                seen.add(normalized)

        result["unique"] = len(seen)

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


# ─────────────────────────────────────────────
# ИМЯ ИСТОЧНИКА
# ─────────────────────────────────────────────

def source_name(url: str) -> str:
    u = url.lower()

    if "blackmatrix7" in u:
        if "advertising_domain" in u:
            return "blackmatrix7 — Advertising Domain"

        if "advertising" in u:
            return "blackmatrix7 — Advertising"

        if "privacy" in u:
            return "blackmatrix7 — Privacy"

        if "hijacking" in u:
            return "blackmatrix7 — Hijacking"

    if "oisd" in u:
        return "OISD Big"

    if "anti-ad" in u:
        return "anti-AD"

    if "awavenue" in u.lower():
        return "AWAvenue Ads"

    if "loyalsoldier" in u:
        return "Loyalsoldier — reject"

    if "1hosts" in u:
        return "1Hosts Lite"

    if "hagezi" in u:
        return "HaGeZi Ultimate"

    if "stevenblack" in u:
        return "StevenBlack Hosts"

    if "lexanewmsk" in u:
        return "misha-tgshv — RU AdBlock"

    if "misha-tgshv" in u:
        return "misha-tgshv — Geo Detect"

    if "malware.hosts" in u:
        return "notrack — Malware"

    if "trackers.hosts" in u:
        return "notrack — Trackers"

    if "hblock" in u:
        return "hBlock"

    return url.split("/")[-1] or url


# ─────────────────────────────────────────────
# ПРОВЕРКА EXCLUSIONS
# ─────────────────────────────────────────────

def is_excluded_line(line: str) -> bool:
    line = main.strip_inline_noise(line)

    if "," in line:
        prefix, value = line.split(",", 1)

        prefix = prefix.strip().upper()
        value = value.strip()

        if prefix in {
            "DOMAIN",
            "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD",
        }:
            return main.is_excluded_rule(prefix, value)

    parts = line.split()

    if len(parts) >= 2 and main.is_ip_address(parts[0]):
        host = main.extract_domain_token(parts[1])

        return bool(
            host and main.is_excluded_domain(host)
        )

    domain = main.extract_domain_token(line)

    return bool(
        domain and main.is_excluded_domain(domain)
    )


# ─────────────────────────────────────────────
# MARKDOWN
# ─────────────────────────────────────────────

def make_report(results: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    total_lines = sum(r["total_lines"] for r in results)
    total_parsed = sum(r["parsed"] for r in results)
    total_failed = sum(r["failed"] for r in results)
    total_excluded = sum(r["excluded"] for r in results)
    total_duplicates = sum(r["duplicates"] for r in results)

    successful = sum(
        1 for r in results if r["downloaded"]
    )

    failed_sources = len(results) - successful

    # Глобальные уникальные правила
    global_rules = set()

    for url in main.SOURCE_URLS:
        try:
            content = main.fetch_text(url)

            for raw_line in content.splitlines():
                normalized = main.normalize_rule(raw_line)

                if normalized:
                    global_rules.add(normalized)

        except Exception:
            pass

    lines = []

    lines.append("# Parser Report")
    lines.append("")
    lines.append(
        f"Последняя проверка: **{now}**"
    )
    lines.append("")

    lines.append("## Общий итог")
    lines.append("")
    lines.append(
        f"- Источников: **{successful}/{len(results)}** успешно"
    )
    lines.append(
        f"- Ошибок загрузки: **{failed_sources}**"
    )
    lines.append(
        f"- Всего строк: **{total_lines:,}**"
    )
    lines.append(
        f"- Успешно распарсено: **{total_parsed:,}**"
    )
    lines.append(
        f"- Отброшено при парсинге: **{total_failed:,}**"
    )
    lines.append(
        f"- Исключено через EXCLUSIONS: **{total_excluded:,}**"
    )
    lines.append(
        f"- Дубликатов: **{total_duplicates:,}**"
    )
    lines.append(
        f"- Глобально уникальных правил: **{len(global_rules):,}**"
    )
    lines.append("")

    lines.append("## Источники")
    lines.append("")

    lines.append(
        "| Источник | Строк | Распарсено | Отброшено | EXCLUSIONS | Дубли | Уникальных | Статус |"
    )
    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|---|"
    )

    for r in results:
        if r["downloaded"]:
            status = "✅ OK"
        else:
            status = f"❌ {r['error']}"

        lines.append(
            f"| {r['name']} "
            f"| {r['total_lines']:,} "
            f"| {r['parsed']:,} "
            f"| {r['failed']:,} "
            f"| {r['excluded']:,} "
            f"| {r['duplicates']:,} "
            f"| {r['unique']:,} "
            f"| {status} |"
        )

    lines.append("")

    lines.append("## Что означают столбцы")
    lines.append("")
    lines.append(
        "- **Строк** — сколько строк получено из источника."
    )
    lines.append(
        "- **Распарсено** — сколько строк превратилось в валидные правила."
    )
    lines.append(
        "- **Отброшено** — строки, которые парсер не смог преобразовать."
    )
    lines.append(
        "- **EXCLUSIONS** — правила, удалённые твоими исключениями."
    )
    lines.append(
        "- **Дубли** — повторяющиеся правила внутри конкретного источника."
    )
    lines.append(
        "- **Уникальных** — уникальные правила после дедупликации внутри источника."
    )
    lines.append("")

    lines.append(
        "> ⚠️ Дубликаты между разными источниками не считаются в колонке «Дубли»."
    )
    lines.append(
        "> Глобальный итог учитывает дедупликацию всех источников вместе."
    )

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main_check() -> None:
    print("Запуск проверки парсера...\n")

    results = []

    for index, url in enumerate(main.SOURCE_URLS, 1):
        print(
            f"[{index}/{len(main.SOURCE_URLS)}] "
            f"{source_name(url)}"
        )

        result = check_source(url)
        results.append(result)

        if result["downloaded"]:
            print(
                f"  ✅ строк: {result['total_lines']:,} | "
                f"parsed: {result['parsed']:,} | "
                f"failed: {result['failed']:,} | "
                f"duplicates: {result['duplicates']:,}"
            )
        else:
            print(
                f"  ❌ {result['error']}"
            )

    report = make_report(results)

    Path(REPORT_FILENAME).write_text(
        report,
        encoding="utf-8",
    )

    print("")
    print("════════════════════════════════════════")
    print(f"✅ Отчёт создан: {REPORT_FILENAME}")
    print("════════════════════════════════════════")


if __name__ == "__main__":
    main_check()
