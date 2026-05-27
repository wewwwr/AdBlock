import urllib.request

# Твои исходные списки
urls = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Advertising/Advertising_Domain.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Advertising/Advertising.list",
    "https://dl.oisd.nl/oisd_big_surge.list",
    "https://badmojr.github.io/1Hosts/Lite/domains.txt",
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/refs/heads/main/rules/domains_geo_detect.list",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/ultimate.txt"
]

# Твои ручные правила для БЛОКИРОВКИ
combined_rules = {
    "DOMAIN-SUFFIX,kaspersky-labs.com",
    "DOMAIN-SUFFIX,gepush.com",
    "DOMAIN-SUFFIX,rudderstack.com",
    "DOMAIN-SUFFIX,i.instagram.com",
    "DOMAIN-SUFFIX,widgets.pinterest.com",
    "DOMAIN-SUFFIX,qevents.quora.com",
    "DOMAIN-SUFFIX,clientstream.launchdarkly.com",
    "DOMAIN-SUFFIX,click.mailchimp.com"
    
}

# 🟢 СПИСОК ИСКЛЮЧЕНИЙ: впиши сюда домены, которые НЕ НУЖНО блокировать
exclusions = {
    "keysforgamers.com",
    "keysforgamers.com"
}

print("Начинаю загрузку и обработку списков...")

for url in urls:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=20) as response:
            content = response.read().decode('utf-8')
            for line in content.splitlines():
                line = line.strip()
                
                # Игнорируем пустые строки и комментарии
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                
                # Вытаскиваем "чистый" домен для проверки (убираем DOMAIN-SUFFIX, если он есть)
                clean_domain = line.split(',')[-1] if ',' in line else line
                
                # Если сайт есть в списке исключений — пропускаем его и не добавляем в итоговый файл
                if clean_domain in exclusions:
                    continue
                
                # Если это чистый домен (без запятой), превращаем его в правило DOMAIN-SUFFIX
                if ',' not in line:
                    line = f"DOMAIN-SUFFIX,{line}"
                    
                combined_rules.add(line)
        print(f"Успешно обработан: {url}")
    except Exception as e:
        print(f"Ошибка при загрузке {url}: {e}")

# Сохраняем итоговый файл
output_filename = "my_custom_blocklist.list"
with open(output_filename, "w", encoding="utf-8") as f:
    f.write("# Auto-generated Shadowrocket Blocklist\n")
    for rule in sorted(combined_rules):
        f.write(f"{rule}\n")

print(f"Готово! Всего уникальных правил: {len(combined_rules)}")
