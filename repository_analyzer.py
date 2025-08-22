import re
import json
import logging
import base64
import xml.etree.ElementTree as ET
import math
import time
from collections import Counter

IGNORE_PATTERNS = [
    '/node_modules/', '/dist/', '/build/', '.lock', '.min.js', 
    '/__tests__/', '/test/', '/tests/', '.spec.js', '.test.js', '/docs/'
]

SEVERITY_MAP = {
    "Malicious Dependency": "CRITICAL",
    "Private Key": "CRITICAL",
    "High Entropy String": "CRITICAL",
    "Suspicious JS Keyword": "HIGH",
    "GitHub Token": "CRITICAL",
    "GitLab PAT": "CRITICAL",
    "AWS Key": "HIGH",
    "NPM Dangerous Hook": "HIGH",
    "Remote Script Execution": "HIGH",
    "Generic API Key": "MEDIUM",
    "Suspicious Command": "MEDIUM",
    "Hidden IOC (Base64)": "MEDIUM",
    "Sensitive File": "MEDIUM",
    "PowerShell Encoded": "MEDIUM"
}

SECRET_PATTERNS = {
    "AWS Key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "GitHub Token": re.compile(r'(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}'),
    "GitLab PAT": re.compile(r'glpat-[0-9a-zA-Z\-\_]{20}'),
    "Generic API Key": re.compile(r'[aA][pP][iI]_?[kK][eE][yY].*[\'|"][0-9a-zA-Z]{32,}[\'|"]'),
    "Private Key": re.compile(r'-----BEGIN ((EC|RSA|OPENSSH) )?PRIVATE KEY-----'),
}

SUSPICIOUS_COMMAND_PATTERNS = {
    "NPM Force Install": ("Suspicious Command", re.compile(r'npm\s+(install|i)\s+--force')),
    "Remote Script Execution (curl | sh)": ("Remote Script Execution", re.compile(r'curl\s+[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)\s*\|\s*(bash|sh)')),
    "PowerShell Encoded Command": ("PowerShell Encoded", re.compile(r'powershell\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}', re.IGNORECASE)),
    "Invoke-Expression (IEX)": ("Suspicious Command", re.compile(r'iex\s*\(', re.IGNORECASE))
}

SUSPICIOUS_JS_KEYWORDS = [
    'eth_sendTransaction', 'personal_sign', 'wallet_requestPermissions', 
    '_sendTransaction', 'estimateGas', 'transferFrom', 'sendSignedTransaction',
    'drain', 'atob', 'eval'
]

BASE64_PATTERN = re.compile(r'["\']([A-Za-z0-9+/]{20,}=*)["\']')
LONG_STRING_PATTERN = re.compile(r'["\']([a-zA-Z0-9+/=,.\-_]{50,})["\']')

SUSPICIOUS_FILENAMES = [
    '.env', '.env.local', '.env.development', '.env.production', '.envrc',
    'credentials', 'credentials.json', 'credentials.yml', 'config.json', 
    'config.yml', 'settings.xml', 'database.yml', 'id_rsa', 'private.key', 
    'server.key', '.pem', '.npmrc', '.pypirc', '.git-credentials', '.boto',
    'terraform.tfstate', '.bash_history', '.zsh_history'
]

DEPENDENCY_FILES = ['package.json']


class RepositoryAnalyzer:
    def __init__(self, repo_url, api_client):
        self.repo_url = repo_url
        self.api_client = api_client
        self.results = {
            "url": repo_url, "risk_score": 0, "findings": [],
            "dependencies": {}, "extracted_iocs": []
        }

    def _add_finding(self, description, file_path, finding_type):
        severity = SEVERITY_MAP.get(finding_type, "LOW")
        finding = {"severity": severity, "description": description, "file": file_path}
        if finding not in self.results["findings"]:
            self.results["findings"].append(finding)

    def _calculate_entropy(self, s):
        if not s: return 0
        p, lns = Counter(s), float(len(s))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

    def _find_malicious_js_patterns(self, content, file_path):
        for keyword in SUSPICIOUS_JS_KEYWORDS:
            if keyword in content:
                self._add_finding(f"Palavra-chave suspeita '{keyword}' encontrada", file_path, "Suspicious JS Keyword")

        for match in LONG_STRING_PATTERN.finditer(content):
            long_string = match.group(1)
            entropy = self._calculate_entropy(long_string)
            if entropy > 4.5:
                self._add_finding(f"String de alta entropia ({entropy:.2f}) detectada, pode ser código ofuscado/dado embutido.", file_path, "High Entropy String")
                
    def _find_suspicious_files(self, file_list):
        for file_info in file_list:
            if file_info.get('name', '').lower() in SUSPICIOUS_FILENAMES:
                self._add_finding(f"Arquivo de configuração sensível: {file_info['name']}", file_info['path'], "Sensitive File")

    def _find_exposed_secrets(self, content, file_path):
        for key_type, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                self._add_finding(f"Possível segredo '{key_type}' exposto", file_path, key_type)

    def _find_suspicious_commands(self, content, file_path):
        for description, (finding_type, pattern) in SUSPICIOUS_COMMAND_PATTERNS.items():
            if pattern.search(content):
                self._add_finding(f"Comando suspeito: '{description}'", file_path, finding_type)
    
    def _find_and_decode_base64(self, content, file_path):
        for match in BASE64_PATTERN.finditer(content):
            b64_string = match.group(1)
            try:
                decoded_bytes = base64.b64decode(b64_string, validate=True)
                decoded_content = decoded_bytes.decode('utf-8', errors='ignore')
                url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*|www\.[^\s/$.?#].[^\s]*')
                
                for url_match in url_pattern.finditer(decoded_content):
                    ioc_url = url_match.group(0)
                    self._add_finding(f"URL ofuscada em Base64: {ioc_url[:50]}...", file_path, "Hidden IOC (Base64)")
                    self.results["extracted_iocs"].append({
                        "ioc": ioc_url,
                        "source_file": file_path,
                        "reputation": {}
                    })
            except (base64.binascii.Error, UnicodeDecodeError):
                continue

    def _analyze_npm_scripts(self, content, file_path):
        try:
            data = json.loads(content)
            scripts = data.get('scripts', {})
            for script_name in ['preinstall', 'postinstall', 'prepare']:
                if script_name in scripts:
                    self._add_finding(f"Hook de NPM perigoso ('{script_name}')", file_path, "NPM Dangerous Hook")
        except json.JSONDecodeError:
            logging.warning(f"Não foi possível analisar o JSON de {file_path}")

    def _parse_dependencies(self, content, file_name):
        try:
            if file_name == 'package.json':
                data = json.loads(content)
                deps = list(data.get('dependencies', {}).keys()) + list(data.get('devDependencies', {}).keys())
                if deps:
                    self.results["dependencies"].setdefault(file_name, []).extend(deps)
                self._analyze_npm_scripts(content, file_name)
        except Exception as e:
            logging.warning(f"Não foi possível analisar dependências de {file_name}: {e}")
    
    def _analyze_dependencies(self):
        npm_deps = self.results.get("dependencies", {}).get("package.json", [])
        if not npm_deps: return
        
        logging.info(f"Analisando {len(npm_deps)} dependências NPM contra a base de dados OSV...")
        for package_name in npm_deps:
            vulns = self.api_client.check_package_vulnerability(package_name, "npm")
            if vulns:
                vuln_ids = ", ".join([v.get('id', 'N/A') for v in vulns])
                self._add_finding(f"Dependência maliciosa/vulnerável encontrada: '{package_name}' (OSV IDs: {vuln_ids})", "package.json", "Malicious Dependency")
            time.sleep(0.6)

    def _calculate_risk_score(self):
        if not self.results["findings"]: return 0
        severities = [finding["severity"] for finding in self.results["findings"]]
        if "CRITICAL" in severities: return 95
        if "HIGH" in severities: return 75
        if "MEDIUM" in severities: return 50
        return 25

    def run_analysis(self):
        all_repo_files = self.api_client.list_repository_files(self.repo_url)
        if isinstance(all_repo_files, dict) and 'error' in all_repo_files:
            self._add_finding(f"Erro de API: {all_repo_files.get('error')}", self.repo_url, "CRITICAL")
            return self.results
        if not all_repo_files:
            self._add_finding("Repositório vazio ou inacessível", self.repo_url, "LOW")
            return self.results
            
        filtered_files = [f for f in all_repo_files if not any(p in f.get('path','') for p in IGNORE_PATTERNS)]
        self._find_suspicious_files(filtered_files)

        for item in filtered_files:
            file_name = item.get('name', '')
            file_path = item.get('path')
            content = self.api_client.get_repository_file_content(item)
            if not content: continue
            
            if file_name.endswith('.js'):
                self._find_malicious_js_patterns(content, file_path)
            
            if file_name in DEPENDENCY_FILES:
                self._parse_dependencies(content, file_name)
            
            self._find_exposed_secrets(content, file_path)
            self._find_suspicious_commands(content, file_path)
            self._find_and_decode_base64(content, file_path)

        self._analyze_dependencies()

        for file, deps_list in self.results["dependencies"].items():
            self.results["dependencies"][file] = sorted(list(set(deps_list)))

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.results["findings"].sort(key=lambda x: severity_order.get(x["severity"], 99))
        self.results["risk_score"] = self._calculate_risk_score()
        return self.results