from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────
# НАСТРОЙКИ
# ─────────────────────────────────────────────

# Основной скрипт
MAIN_SCRIPT = "update_list.py"

# Отчёт
REPORT_FILENAME = "reports/parser_report.md"

# Итоговый файл
OUTPUT_FILENAME = "my_custom_blocklist.list"


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

    if "awavenue" in u:
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

    if not line:
        return False

    # Shadowrocket / Surge
    if "," in line:

        prefix, value = line.split(",", 1)

        prefix = prefix.strip().upper()
        value = value.strip()

        if prefix in {
            "DOMAIN",
            "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD",
        }:
            return main.is_excluded_rule(
                prefix,
                value,
            )

    # HOSTS
    parts = line.split()

    if (
        len(parts) >= 2
        and main.is_ip_address(parts[0])
    ):
        host = main.extract_domain_token(parts[1])

        return bool(
            host
            and main.is_excluded_domain(host)
        )

    # Обычный домен
    domain = main.extract_domain_token(line)

    return bool(
        domain
        and main.is_excluded_domain(domain)
    )


# ─────────────────────────────────────────────
# ПРОВЕРКА ОДНОГО ИСТОЧНИКА
# ─────────────────────────────────────────────

def check_source(
    url: str,
    cumulative_rules: set[str],
) -> dict:

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

        "new_to_total": 0,

        "error": "",
    }

    try:

        content = main.fetch_text(url)

        result["downloaded"] = True

        source_rules: set[str] = set()

        for raw_line in content.splitlines():

            result["total_lines"] += 1

            line = main.strip_inline_noise(
                raw_line
            )

            if not line:
                result["empty_lines"] += 1
                continue

            if line.startswith(
                ("#", "//", "!", ";")
            ):
                result["comments"] += 1
                continue

            normalized = main.normalize_rule(
                line
            )

            if normalized is None:

                if is_excluded_line(line):
                    result["excluded"] += 1
                else:
                    result["failed"] += 1

                continue

            result["parsed"] += 1

            # Дубли внутри конкретной базы.
            if normalized in source_rules:
                result["duplicates"] += 1

            source_rules.add(normalized)

        result["unique"] = len(source_rules)

        # Сколько правил этой базы добавилось
        # поверх всех предыдущих источников.
        before = len(cumulative_rules)

        cumulative_rules.update(
            source_rules
        )

        after = len(cumulative_rules)

        result["new_to_total"] = (
            after - before
        )

    except Exception as e:

        result["error"] = (
            f"{type(e).__name__}: {e}"
        )

    return result


# ─────────────────────────────────────────────
# ЧТЕНИЕ ИТОГОВОГО ФАЙЛА
# ─────────────────────────────────────────────

def read_final_blocklist() -> set[str]:
    path = Path(OUTPUT_FILENAME)

    if not path.exists():
        return set()

    rules: set[str] = set()

    try:

        for raw_line in path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines():

            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            rules.add(line)

    except Exception:
        return set()

    return rules


# ─────────────────────────────────────────────
# ТОЧНОЕ СРАВНЕНИЕ ИТОГОВОГО ФАЙЛА
# ─────────────────────────────────────────────

def compare_final_file(
    cumulative_rules: set[str],
    final_file_rules: set[str],
) -> dict:

    missing_rules = (
        cumulative_rules - final_file_rules
    )

    extra_rules = (
        final_file_rules - cumulative_rules
    )

    return {
        "exact_match": (
            not missing_rules
            and not extra_rules
        ),

        "missing": missing_rules,

        "extra": extra_rules,
    }


# ─────────────────────────────────────────────
# MARKDOWN REPORT
# ─────────────────────────────────────────────

def make_report(
    results: list[dict],
    cumulative_rules: set[str],
    manual_rules: set[str],
) -> str:

    now = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    successful = sum(
        1
        for r in results
        if r["downloaded"]
    )

    failed_sources = (
        len(results) - successful
    )

    total_lines = sum(
        r["total_lines"]
        for r in results
    )

    total_parsed = sum(
        r["parsed"]
        for r in results
    )

    total_failed = sum(
        r["failed"]
        for r in results
    )

    total_excluded = sum(
        r["excluded"]
        for r in results
    )

    total_duplicates = sum(
        r["duplicates"]
        for r in results
    )

    total_unique_per_source = sum(
        r["unique"]
        for r in results
    )

    total_new_to_total = sum(
        r["new_to_total"]
        for r in results
    )

    final_file_rules = (
        read_final_blocklist()
    )

    comparison = compare_final_file(
        cumulative_rules,
        final_file_rules,
    )

    missing_rules = comparison["missing"]
    extra_rules = comparison["extra"]

    # ─────────────────────────────────────
    # REPORT
    # ─────────────────────────────────────

    lines: list[str] = []

    lines.append(
        "# 🔍 Parser Report"
    )

    lines.append("")

    lines.append(
        f"Последняя проверка: **{now}**"
    )

    lines.append("")

    # ─────────────────────────────────────
    # ОБЩИЙ ИТОГ
    # ─────────────────────────────────────

    lines.append(
        "## 📊 Общий итог"
    )

    lines.append("")

    lines.append(
        f"- Источников: **{successful}/{len(results)}** успешно"
    )

    lines.append(
        f"- Ошибок загрузки: **{failed_sources}**"
    )

    lines.append(
        f"- Всего строк во всех источниках: **{total_lines:,}**"
    )

    lines.append(
        f"- Успешно распарсено строк: **{total_parsed:,}**"
    )

    lines.append(
        f"- Не удалось распарсить: **{total_failed:,}**"
    )

    lines.append(
        f"- Удалено через EXCLUSIONS: **{total_excluded:,}**"
    )

    lines.append(
        f"- Дубликатов внутри источников: **{total_duplicates:,}**"
    )

    lines.append(
        f"- Сумма уникальных правил по источникам: **{total_unique_per_source:,}**"
    )

    lines.append(
        f"- Новых правил, добавленных источниками: **{total_new_to_total:,}**"
    )

    lines.append(
        f"- Ручных правил: **{len(manual_rules):,}**"
    )

    lines.append(
        f"- Уникальных правил после объединения источников: **{len(cumulative_rules):,}**"
    )

    lines.append(
        f"- Правил фактически в `{OUTPUT_FILENAME}`: **{len(final_file_rules):,}**"
    )

    # ─────────────────────────────────────
    # ТОЧНАЯ ПРОВЕРКА
    # ─────────────────────────────────────

    if comparison["exact_match"]:

        lines.append(
            "- Проверка итогового файла: **✅ точное совпадение**"
        )

        lines.append(
            "- Отсутствующих правил: **0**"
        )

        lines.append(
            "- Лишних правил: **0**"
        )

    else:

        lines.append(
            "- Проверка итогового файла: **❌ НЕ совпадает**"
        )

        lines.append(
            f"- Отсутствующих правил: **{len(missing_rules):,}**"
        )

        lines.append(
            f"- Лишних правил: **{len(extra_rules):,}**"
        )

        if missing_rules:

            lines.append("")

            lines.append(
                "### ❌ Примеры отсутствующих правил"
            )

            lines.append("")

            for rule in sorted(
                missing_rules
            )[:20]:

                lines.append(
                    f"- `{rule}`"
                )

        if extra_rules:

            lines.append("")

            lines.append(
                "### ⚠️ Примеры лишних правил"
            )

            lines.append("")

            for rule in sorted(
                extra_rules
            )[:20]:

                lines.append(
                    f"- `{rule}`"
                )

    lines.append("")

    # ─────────────────────────────────────
    # ТАБЛИЦА ИСТОЧНИКОВ
    # ─────────────────────────────────────

    lines.append(
        "## 📚 Источники"
    )

    lines.append("")

    lines.append(
        "| Источник | Строк | Распарсено | Отброшено | EXCLUSIONS | Дубли | Уникальных | Новых в итог | Статус |"
    )

    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|---:|---|"
    )

    for r in results:

        if r["downloaded"]:
            status = "✅ OK"

        else:
            status = (
                f"❌ {r['error']}"
            )

        lines.append(
            f"| {r['name']} "
            f"| {r['total_lines']:,} "
            f"| {r['parsed']:,} "
            f"| {r['failed']:,} "
            f"| {r['excluded']:,} "
            f"| {r['duplicates']:,} "
            f"| {r['unique']:,} "
            f"| {r['new_to_total']:,} "
            f"| {status} |"
        )

    lines.append("")

    # ─────────────────────────────────────
    # ПОЯСНЕНИЕ
    # ─────────────────────────────────────

    lines.append(
        "## ℹ️ Что означают столбцы"
    )

    lines.append("")

    lines.append(
        "- **Строк** — сколько строк получено от источника."
    )

    lines.append(
        "- **Распарсено** — сколько строк превратилось в валидные Shadowrocket/Surge-правила."
    )

    lines.append(
        "- **Отброшено** — строки, которые текущий парсер не смог преобразовать."
    )

    lines.append(
        "- **EXCLUSIONS** — строки, которые намеренно удалены твоими исключениями."
    )

    lines.append(
        "- **Дубли** — повторяющиеся правила внутри одной конкретной базы."
    )

    lines.append(
        "- **Уникальных** — уникальные правила внутри конкретной базы."
    )

    lines.append(
        "- **Новых в итог** — сколько уникальных правил эта база добавила сверх всех предыдущих баз."
    )

    lines.append("")

    lines.append(
        "> 💡 Именно столбец **«Новых в итог»** показывает реальную пользу каждой базы."
    )

    lines.append(
        "> Если база содержит 1 000 000 правил, но «Новых в итог» = 50 000, остальные уже были получены из других источников."
    )

    lines.append("")

    # ─────────────────────────────────────
    # ПРОВЕРЯЕМАЯ ЛОГИКА
    # ─────────────────────────────────────

    lines.append(
        "## 🛡️ Проверяемая логика"
    )

    lines.append("")

    lines.append(
        "- `update_list.py` — основной парсер."
    )

    lines.append(
        "- `DOMAIN-KEYWORD` разрешён без точки."
    )

    lines.append(
        "- Дубли внутри каждой базы определяются отдельно."
    )

    lines.append(
        "- Дубли между источниками удаляются через `set`."
    )

    lines.append(
        "- `EXCLUSIONS` учитываются."
    )

    lines.append(
        "- Итоговый файл сравнивается по точному содержимому, а не только по количеству правил."
    )

    lines.append(
        "- При несовпадении показываются примеры отсутствующих и лишних правил."
    )

    lines.append("")

    # ─────────────────────────────────────
    # ФАЙЛЫ
    # ─────────────────────────────────────

    lines.append(
        "## 📁 Файлы"
    )

    lines.append("")

    lines.append(
        f"- Основная база: `{OUTPUT_FILENAME}`"
    )

    lines.append(
        f"- Основной скрипт: `{MAIN_SCRIPT}`"
    )

    lines.append(
        f"- Этот отчёт: `{REPORT_FILENAME}`"
    )

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main_check() -> None:

    print(
        "🔍 Запуск проверки всех источников...\n"
    )

    results: list[dict] = []

    # Все правила источников.
    cumulative_rules: set[str] = set()

    # Ручные правила.
    manual_rules: set[str] = set()

    for rule in main.MANUAL_RULES:

        normalized = main.normalize_rule(
            rule
        )

        if normalized:
            manual_rules.add(normalized)

    cumulative_rules.update(
        manual_rules
    )

    print(
        f"Ручных правил: {len(manual_rules):,}"
    )

    print("")

    # ─────────────────────────────────────
    # ИСТОЧНИКИ
    # ─────────────────────────────────────

    for index, url in enumerate(
        main.SOURCE_URLS,
        1,
    ):

        print(
            f"[{index}/{len(main.SOURCE_URLS)}] "
            f"{source_name(url)}"
        )

        result = check_source(
            url,
            cumulative_rules,
        )

        results.append(result)

        if result["downloaded"]:

            print(
                f"  ✅ строк: "
                f"{result['total_lines']:,} | "
                f"parsed: "
                f"{result['parsed']:,} | "
                f"failed: "
                f"{result['failed']:,} | "
                f"duplicates: "
                f"{result['duplicates']:,} | "
                f"new: "
                f"{result['new_to_total']:,}"
            )

        else:

            print(
                f"  ❌ {result['error']}"
            )

    # ─────────────────────────────────────
    # СОЗДАНИЕ ОТЧЁТА
    # ─────────────────────────────────────

    report = make_report(
        results,
        cumulative_rules,
        manual_rules,
    )

    report_path = Path(
        REPORT_FILENAME
    )

    report_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_path.write_text(
        report,
        encoding="utf-8",
    )

    print("")

    print(
        "════════════════════════════════════════"
    )

    print(
        f"✅ Отчёт создан: {REPORT_FILENAME}"
    )

    print(
        f"📊 Уникальных правил: "
        f"{len(cumulative_rules):,}"
    )

    print(
        "════════════════════════════════════════"
    )


if __name__ == "__main__":
    main_check()
