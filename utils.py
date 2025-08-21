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

def is_file_writable(filepath):
    """ Verifica se um arquivo pode ser escrito, tratando o caso de ele estar aberto. """
    if os.path.exists(filepath):
        try:
            with open(filepath, 'a'):
                pass
        except IOError:
            return False
    return True

def parse_repo_urls(text):
    """
    Analisa um bloco de texto, valida cada linha como uma URL de repositório
    e retorna listas de URLs válidas, linhas inválidas e linhas duplicadas.
    """
    seen_urls = set()
    valid_urls = []
    invalid_lines = []
    duplicate_lines = []
    
    pattern = re.compile(
        r'^(?:https?:\/\/)?'
        r'(?:www\.)?'
        r'(github\.com|gitlab\.com)\/'
        r'([\w.-]+(?:\/[\w.-]+)+)'
        r'(?:\.git)?\/?$',
        re.IGNORECASE
    )

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
            
        match = pattern.match(line)
        if match:
            normalized_url = f"https://{match.group(1)}/{match.group(2)}".lower()
            if normalized_url in seen_urls:
                duplicate_lines.append(line)
            else:
                valid_urls.append(normalized_url)
                seen_urls.add(normalized_url)
        else:
            invalid_lines.append(line)
            
    return sorted(valid_urls), invalid_lines, list(set(duplicate_lines))

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