from __future__ import annotations

import ipaddress
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional


SOURCE_URLS = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Advertising/Advertising_Domain.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Advertising/Advertising.list",
    "https://dl.oisd.nl/oisd_big_surge.list",
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Privacy/Privacy.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Hijacking/Hijacking.list",
    "https://badmojr.github.io/1Hosts/Lite/domains.txt",
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/refs/heads/main/rules/domains_geo_detect.list",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/ultimate.txt",
]

# Ручные правила для блокировки
MANUAL_RULES = {
    "DOMAIN-SUFFIX,kaspersky-labs.com",
    "DOMAIN-SUFFIX,gepush.com",
    "DOMAIN-SUFFIX,rudderstack.com",
    "DOMAIN-SUFFIX,widgets.pinterest.com",
    "DOMAIN-SUFFIX,qevents.quora.com",
    "DOMAIN-SUFFIX,click.mailchimp.com",
    "DOMAIN-SUFFIX,cpu.js.org",
    "DOMAIN-SUFFIX,fastpool.xyz",
    "DOMAIN-SUFFIX,pendo.io",
    "DOMAIN-SUFFIX,cookies-data.onetrust.io",
    "DOMAIN-SUFFIX,mailchimp.com",
    "DOMAIN-SUFFIX,open.convertkit.com",
    "DOMAIN-SUFFIX,app.convertkit.com",
    "DOMAIN-SUFFIX,email.mailgun.net",
    "DOMAIN-SUFFIX,clicks.aweber.com",
    "DOMAIN-SUFFIX,pi.pardot.com",
    "DOMAIN-SUFFIX,mandrillapp.com",
    "DOMAIN-SUFFIX,sendgrid.net",
}

# Исключения: эти домены НЕ блокируются, включая поддомены
EXCLUSIONS = {
    "keysforgamers.com",
}

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


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_domain(value: str) -> str:
    """Приводит домен к каноничному виду."""
    value = value.strip().lower()
    value = value.strip(".")
    value = value.lstrip("*.")
    value = value.lstrip(".")
    value = value.replace(" ", "")
    return value


def is_excluded_domain(domain: str) -> bool:
    """Исключает домен и все его поддомены."""
    domain = normalize_domain(domain)
    for exclusion in EXCLUSIONS:
        exclusion = normalize_domain(exclusion)
        if domain == exclusion or domain.endswith("." + exclusion):
            return True
    return False


def strip_inline_noise(text: str) -> str:
    """Удаляет BOM и лишние пробелы."""
    return text.lstrip("\ufeff").strip()


def extract_host_from_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    return normalize_domain(host)


def extract_domain_token(text: str) -> str:
    """
    Пытается извлечь домен из:
    - raw domain
    - URL
    - ||adblock-rule^
    - *.example.com
    - example.com/path
    """
    text = strip_inline_noise(text)
    if not text:
        return ""

    # Убираем типичные оболочки adblock
    if text.startswith("||"):
        text = text[2:]
    if text.startswith("|"):
        text = text.lstrip("|")

    text = text.strip().strip("^").strip()
    text = text.replace("\\", "/")

    # Если это URL
    if "://" in text:
        host = extract_host_from_url(text)
        return host

    # Отрезаем путь / query / fragment
    text = text.split("/", 1)[0]
    text = text.split("?", 1)[0]
    text = text.split("#", 1)[0]

    # Убираем порт
    if ":" in text and not text.startswith("["):
        maybe_host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            text = maybe_host

    text = normalize_domain(text)

    # Отбрасываем IP
    if is_ip_address(text):
        return ""

    # Базовая валидация домена
    if "." not in text:
        return ""

    return text


def normalize_rule(line: str) -> Optional[str]:
    """
    Нормализует строку из списка в формат Shadowrocket.
    Возвращает None для пустых/неподходящих строк.
    """
    line = strip_inline_noise(line)
    if not line:
        return None

    if line.startswith(("#", "//", "!", ";")):
        return None

    # HOSTS-формат: 0.0.0.0 example.com / 127.0.0.1 example.com / ::1 example.com
    parts = line.split()
    if len(parts) >= 2 and is_ip_address(parts[0]):
        host = extract_domain_token(parts[1])
        if host and not is_excluded_domain(host):
            return f"DOMAIN-SUFFIX,{host}"
        return None

    # Shadowrocket-форматы с префиксом
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

        # Неизвестный формат с запятой — пробуем как домен
        domain = extract_domain_token(value)
        if domain and not is_excluded_domain(domain):
            return f"DOMAIN-SUFFIX,{domain}"
        return None

    # Adblock / raw домен / URL
    domain = extract_domain_token(line)
    if domain and not is_excluded_domain(domain):
        return f"DOMAIN-SUFFIX,{domain}"

    return None


def fetch_text(url: str, timeout: int = 60, retries: int = 2) -> str:
    """
    Загружает текст по URL с несколькими попытками.
    """
    headers = {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=headers)
    context = ssl.create_default_context()

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
                raw = response.read()

            # Пытаемся определить кодировку, если сервер её дал
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


def build_blocklist() -> list[str]:
    combined_rules = set()

    # Сначала добавляем ручные правила
    for rule in MANUAL_RULES:
        normalized = normalize_rule(rule)
        if normalized:
            combined_rules.add(normalized)

    print("Начинаю загрузку и обработку списков...")

    for url in SOURCE_URLS:
        try:
            content = fetch_text(url)

            count_before = len(combined_rules)
            added_from_source = 0

            for raw_line in content.splitlines():
                normalized = normalize_rule(raw_line)
                if not normalized:
                    continue

                if normalized not in combined_rules:
                    combined_rules.add(normalized)
                    added_from_source += 1

            added = len(combined_rules) - count_before
            print(f"✅ Обработан: {url.split('/')[-1]} (+{added} правил, новых {added_from_source})")

        except Exception as e:
            print(f"❌ Ошибка при загрузке {url}: {e}")

    return sorted(combined_rules)


def write_atomically(path: str, lines: list[str]) -> None:
    """
    Безопасная запись: сначала во временный файл, потом замена.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    header = [
        "# Auto-generated Shadowrocket Blocklist",
        "# Generated by Python script",
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


def main() -> None:
    rules = build_blocklist()

    if not rules:
        print("\nНе удалось собрать ни одного правила. Файл не перезаписан.")
        return

    write_atomically(OUTPUT_FILENAME, rules)

    print(f"\nГотово! Всего уникальных правил: {len(rules)}")
    print(f"Файл сохранён: {OUTPUT_FILENAME}")


if __name__ == "__main__":
    main()
