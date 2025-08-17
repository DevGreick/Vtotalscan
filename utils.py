import re
import ipaddress
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_targets(text):
    valid_ips = set()
    valid_urls = set()
    

    hostname_pattern = re.compile(
        r'^((([a-z0-9])|([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))\.)*(([a-z0-9])|([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))\.?$|'
        r'^([a-z0-9])|([a-z0-9][a-z0-9\-]{0,61}[a-z0-9])$'
    )

    for line in text.splitlines():
        line = line.strip().lower()
        if not line:
            continue

        try:
            ipaddress.ip_address(line)
            valid_ips.add(line)
        except ValueError:
           
            domain_part = re.sub(r'^[a-z]+://', '', line).split('/')[0]
            
            
            if domain_part and hostname_pattern.match(domain_part):
                line = line.rstrip('/')
                if not re.match(r'^[a-z]+://', line):
                    valid_urls.add('http://' + line)
                else:
                    valid_urls.add(line)
            else:
                logging.warning(f"Ignored entry (not a valid IP or domain): '{line}'")

    return sorted(list(valid_ips)), sorted(list(valid_urls))

def defang_ioc(ioc_string):
    if not ioc_string:
        return ""
    defanged = ioc_string.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
    return defanged.replace('.', '[.]')