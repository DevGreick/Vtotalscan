import re
import ipaddress
import logging
import hashlib
import sys
import os

def resource_path(relative_path):
    """ Obtém o caminho absoluto para o recurso, funciona para dev e para o executável PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

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
                logging.warning(f"Entrada ignorada (não é um IP ou domínio válido): '{line}'")

    return sorted(list(valid_ips)), sorted(list(valid_urls))

def calculate_sha256(filepath):
    """Calcula o hash SHA256 de um arquivo de forma eficiente."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError as e:
        logging.error(f"Erro ao ler o arquivo {filepath}: {e}")
        return None

def defang_ioc(ioc_string):
    if not ioc_string:
        return ""
    defanged = ioc_string.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
    return defanged.replace('.', '[.]')
