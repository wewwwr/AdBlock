from __future__ import annotations

import ipaddress
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
#  ИСТОЧНИКИ
# ─────────────────────────────────────────────

SOURCE_URLS = [
    # ── blackmatrix7 ──────────────────────────────────────────────────────────
    # Реклама (полный список)
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Advertising/Advertising.list",
    # Реклама (только домены, DOMAIN-SET формат)
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Advertising/Advertising_Domain.list",
    # Трекеры и слежка
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Privacy/Privacy.list",
    # Угон трафика провайдерами
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Hijacking/Hijacking.list",

    # ── OISD Big (глобальный мировой список) ──────────────────────────────────
    # Блокирует рекламу, трекеры, фишинг, malware, spyware, cryptojacking
    "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_big.txt",

    # ── anti-AD ───────────────────────────────────────────────────────────────
    # Независимый проект, синхронизируется с несколькими источниками
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt",

    # ── AWAvenue (秋风) ────────────────────────────────────────────────────────
    # Блокирует 90%+ рекламных SDK, входит в официальный список AdGuard DNS
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Surge.list",

    # ── Loyalsoldier ──────────────────────────────────────────────────────────
    # Глобальный reject-список (v2ray community + GFWList + AdGuard)
    "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/reject.txt",

    # ── 1Hosts Lite ───────────────────────────────────────────────────────────
    # Лёгкий мировой список без агрессивной блокировки
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt",

    # ── HaGeZi Ultimate ───────────────────────────────────────────────────────
    # Самый полный мировой список: реклама, трекеры, malware, phishing
    # Источники: EasyList, EasyPrivacy, AdGuard, Peter Lowe, OISD и др.
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt",

    # ── StevenBlack hosts ─────────────────────────────────────────────────────
    # Классический объединённый hosts-файл: AdAway + hpHosts + Peter Lowe + MVP
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",

    # ── misha-tgshv ───────────────────────────────────────────────────────────
    # GeoIP-детект домены для RU региона
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/refs/heads/main/rules/domains_geo_detect.list",

    # ── notrack-blocklists (GitLab) ───────────────────────────────────────────
    # Malware-домены: вредоносные сайты, фишинг, ботнеты
    "https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/malware.hosts?ref_type=heads",
    # Трекеры: сбор данных, аналитика, слежка
    "https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/trackers.hosts?ref_type=heads",

    # ── hBlock ────────────────────────────────────────────────────────────────
    # Объединяет 100+ источников: реклама, трекеры, malware. Обновляется ежедневно.
    "https://hblock.molinero.dev/hosts",

   

    
]


# ─────────────────────────────────────────────
#  РУЧНЫЕ ПРАВИЛА
# ─────────────────────────────────────────────

MANUAL_RULES = {
    # Аналитика / трекеры
    "DOMAIN-SUFFIX,rudderstack.com",
    "DOMAIN-SUFFIX,pendo.io",
    "DOMAIN-SUFFIX,cryptoloot.org",
    "DOMAIN-SUFFIX,redditmedia.com",
    "DOMAIN-SUFFIX,launchdarkly.com",
    "DOMAIN-SUFFIX,split.io",
    "DOMAIN-SUFFIX,configcat.com",
    "DOMAIN-SUFFIX,flagsmith.com",
    "DOMAIN-SUFFIX,jwplayer.com",
    "DOMAIN-SUFFIX,bcovlive.io",
    "DOMAIN-SUFFIX,ngfts.lge.com",
    "DOMAIN-SUFFIX,cdn.privacy-mgmt.com",
    "DOMAIN-SUFFIX,s.youtube.com",
    "DOMAIN-SUFFIX,f.vimeocdn.com",
    "DOMAIN-SUFFIX,st-widget.s3.amazonaws.com",
    "DOMAIN-SUFFIX,f.vimeocdn.com",




    "DOMAIN-SUFFIX,cookies-data.onetrust.io",
    "DOMAIN-SUFFIX,gepush.com",
    # Реклама
    "DOMAIN-SUFFIX,kaspersky-labs.com",
    "DOMAIN-SUFFIX,widgets.pinterest.com",
    "DOMAIN-SUFFIX,qevents.quora.com",
    # Email-маркетинг / спам
    "DOMAIN-SUFFIX,click.mailchimp.com",
    "DOMAIN-SUFFIX,mailchimp.com",
    "DOMAIN-SUFFIX,open.convertkit.com",
    "DOMAIN-SUFFIX,app.convertkit.com",
    "DOMAIN-SUFFIX,email.mailgun.net",
    "DOMAIN-SUFFIX,clicks.aweber.com",
    "DOMAIN-SUFFIX,pi.pardot.com",
    "DOMAIN-SUFFIX,mandrillapp.com",
    "DOMAIN-SUFFIX,sendgrid.net",
    # Майнинг
    "DOMAIN-SUFFIX,cpu.js.org",
    "DOMAIN-SUFFIX,fastpool.xyz",
}


# ─────────────────────────────────────────────
#  ИСКЛЮЧЕНИЯ (не блокировать включая поддомены)
# ─────────────────────────────────────────────

EXCLUSIONS = {
    "keysforgamers.com",
    "updates.maxmind.com",
}


# ─────────────────────────────────────────────
#  НАСТРОЙКИ
# ─────────────────────────────────────────────

OUTPUT_FILENAME = "my_custom_blocklist.list"

USER_AGENT = "Mozilla/5.0 (compatible; ShadowrocketBlocklistBuilder/1.0)"

DOMAIN_RULE_PREFIXES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
    "USER-AGENT",
    "URL-REGEX",
    "GEOIP",
}


# ─────────────────────────────────────────────
#  УТИЛИТЫ
# ─────────────────────────────────────────────

def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    value = value.strip(".")
    value = value.lstrip("*.")
    value = value.lstrip(".")
    value = value.replace(" ", "")
    return value


def is_excluded_domain(domain: str) -> bool:
    domain = normalize_domain(domain)
    for exclusion in EXCLUSIONS:
        exclusion = normalize_domain(exclusion)
        if domain == exclusion or domain.endswith("." + exclusion):
            return True
    return False


def strip_inline_noise(text: str) -> str:
    return text.lstrip("\ufeff").strip()


def extract_host_from_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    return normalize_domain(host)


def extract_domain_token(text: str) -> str:
    text = strip_inline_noise(text)
    if not text:
        return ""

    if text.startswith("||"):
        text = text[2:]
    if text.startswith("|"):
        text = text.lstrip("|")

    text = text.strip().strip("^").strip()
    text = text.replace("\\", "/")

    if "://" in text:
        return extract_host_from_url(text)

    text = text.split("/", 1)[0]
    text = text.split("?", 1)[0]
    text = text.split("#", 1)[0]

    if ":" in text and not text.startswith("["):
        maybe_host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            text = maybe_host

    text = normalize_domain(text)

    if is_ip_address(text):
        return ""

    if "." not in text:
        return ""

    return text


def normalize_rule(line: str) -> Optional[str]:
    line = strip_inline_noise(line)
    if not line:
        return None

    if line.startswith(("#", "//", "!", ";")):
        return None

    # HOSTS-формат: 0.0.0.0 example.com
    parts = line.split()
    if len(parts) >= 2 and is_ip_address(parts[0]):
        host = extract_domain_token(parts[1])
        if host and not is_excluded_domain(host):
            return f"DOMAIN-SUFFIX,{host}"
        return None

    # Shadowrocket/Surge формат с префиксом
    if "," in line:
        prefix, value = line.split(",", 1)
        prefix = prefix.strip().upper()
        value = value.strip()

        if prefix in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
            domain = extract_domain_token(value)
            if not domain or is_excluded_domain(domain):
                return None
            return f"{prefix},{domain}"

        if prefix in {"IP-CIDR", "IP-CIDR6", "GEOIP", "PROCESS-NAME", "USER-AGENT", "URL-REGEX"}:
            return f"{prefix},{value}"

        domain = extract_domain_token(value)
        if domain and not is_excluded_domain(domain):
            return f"DOMAIN-SUFFIX,{domain}"
        return None

    # Adblock / raw домен
    domain = extract_domain_token(line)
    if domain and not is_excluded_domain(domain):
        return f"DOMAIN-SUFFIX,{domain}"

    return None


# ─────────────────────────────────────────────
#  ЗАГРУЗКА
# ─────────────────────────────────────────────

def fetch_text(url: str, timeout: int = 60, retries: int = 2) -> str:
    headers = {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=headers)
    context = ssl.create_default_context()

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
                raw = response.read()
            content_type = ""
            try:
                content_type = response.headers.get("Content-Type", "")
            except Exception:
                pass
            encoding = "utf-8"
            match = re.search(r"charset=([^\s;]+)", content_type, re.IGNORECASE)
            if match:
                encoding = match.group(1).strip('"').strip("'")
            return raw.decode(encoding, errors="replace")
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
            last_error = e
            if attempt < retries:
                continue
            raise last_error


# ─────────────────────────────────────────────
#  СБОРКА
# ─────────────────────────────────────────────

def build_blocklist() -> list[str]:
    combined_rules: set[str] = set()

    for rule in MANUAL_RULES:
        normalized = normalize_rule(rule)
        if normalized:
            combined_rules.add(normalized)

    print(f"Ручных правил добавлено: {len(combined_rules)}")
    print("Начинаю загрузку и обработку списков...\n")

    results = []
    failed = []

    for url in SOURCE_URLS:
        source_name = url.split("/")[-1]
        try:
            content = fetch_text(url)
            count_before = len(combined_rules)

            for raw_line in content.splitlines():
                normalized = normalize_rule(raw_line)
                if normalized:
                    combined_rules.add(normalized)

            added = len(combined_rules) - count_before
            results.append((source_name, added, True))
            print(f"✅ {source_name:<55} +{added}")

        except Exception as e:
            results.append((source_name, 0, False))
            failed.append((source_name, str(e)))
            print(f"❌ {source_name:<55} ОШИБКА: {e}")

    if failed:
        print(f"\n⚠️  Не удалось загрузить {len(failed)} источник(ов):")
        for name, err in failed:
            print(f"   • {name}: {err}")

    return sorted(combined_rules)


# ─────────────────────────────────────────────
#  ЗАПИСЬ
# ─────────────────────────────────────────────

def write_atomically(path: str, lines: list[str]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        "# ══════════════════════════════════════════════════════════════",
        "# Auto-generated Shadowrocket / Surge Blocklist",
        f"# Generated: {now}",
        f"# Total rules: {len(lines)}",
        "#",
        "# Sources:",
        *[f"#   {url}" for url in SOURCE_URLS],
        "# ══════════════════════════════════════════════════════════════",
        "",
    ]

    temp_dir = str(target.parent)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        delete=False,
        dir=temp_dir,
        prefix=target.name + ".",
        suffix=".tmp",
    ) as tmp:
        tmp_path = tmp.name
        for line in header:
            tmp.write(line + "\n")
        for rule in lines:
            tmp.write(rule + "\n")

    os.replace(tmp_path, target)


# ─────────────────────────────────────────────
#  ТОЧКА ВХОДА
# ─────────────────────────────────────────────

def main() -> None:
    rules = build_blocklist()

    if not rules:
        print("\nНе удалось собрать ни одного правила. Файл не перезаписан.")
        return

    write_atomically(OUTPUT_FILENAME, rules)

    print(f"\n{'─'*60}")
    print(f"✅ Готово! Всего уникальных правил: {len(rules)}")
    print(f"📄 Файл сохранён: {OUTPUT_FILENAME}")


if __name__ == "__main__":
    main()
