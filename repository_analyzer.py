# repository_analyzer.py
import re
import json
import logging
import base64
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

SECRET_PATTERNS = {
    "AWS Key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "GitHub Token": re.compile(r'(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}'),
    "GitLab PAT": re.compile(r'glpat-[0-9a-zA-Z\-\_]{20}'),
    "Generic API Key": re.compile(r'[aA][pP][iI]_?[kK][eE][yY].*[\'|"][0-9a-zA-Z]{32,}[\'|"]'),
    "Private Key": re.compile(r'-----BEGIN ((EC|RSA|OPENSSH) )?PRIVATE KEY-----'),
}

SUSPICIOUS_FILENAMES = [
    
    '.env', '.env.local', '.env.development', '.env.production', '.envrc',
    
    
    'credentials', 'credentials.json', 'credentials.yml', 'config.json', 
    'config.yml', 'settings.xml', 'database.yml',
    
    
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 
    'private.key', 'server.key', '.pem', '.pfx', '.p12',
    
    
    '.npmrc', '.pypirc', '.git-credentials', '.boto',
    
    
    'terraform.tfstate',
    
    
    '.bash_history', '.zsh_history', '.history'
]

DEPENDENCY_FILES = [
    
    'requirements.txt', 'Pipfile', 'pyproject.toml',
    
    
    'package.json', 'package-lock.json', 'yarn.lock',
    
    
    'composer.json', 'composer.lock',
    
    
    'pom.xml',          
    'build.gradle',     
    'build.gradle.kts', 
    
    
    'Gemfile', 'Gemfile.lock',
    
    
    'go.mod', 'go.sum',
    
    
    'Cargo.toml', 'Cargo.lock',
    
    
    'packages.config', '.csproj',
    
    
    'Dockerfile'
]


class RepositoryAnalyzer:
    def __init__(self, repo_url, api_client):
        self.repo_url = repo_url
        self.api_client = api_client
        self.results = {
            "url": repo_url,
            "risk_score": 0,
            "summary": [],
            "suspicious_files": [],
            "exposed_secrets": [],
            "dependencies": {}
        }

    def _find_suspicious_files(self, file_list):
        for file_info in file_list:
            if file_info.get('name', '').lower() in SUSPICIOUS_FILENAMES:
                self.results["suspicious_files"].append(file_info['name'])
                self.results["summary"].append(f"Arquivo de configuração potencialmente sensível encontrado: {file_info['name']}")
                self.results["risk_score"] += 20

    def _find_exposed_secrets(self, content, file_path):
        for key_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                secret_info = {
                    "file": file_path,
                    "type": key_type,
                    "snippet": match.group(0).strip()
                }
                if secret_info not in self.results["exposed_secrets"]:
                    self.results["exposed_secrets"].append(secret_info)
                    self.results["summary"].append(f"Possível segredo '{key_type}' exposto em: {file_path}")
                    self.results["risk_score"] += 50

    def _parse_dependencies(self, content, file_name):
        deps = []
        try:
            if file_name == 'requirements.txt':
                deps = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
            
            elif file_name == 'package.json':
                data = json.loads(content)
                deps.extend(list(data.get('dependencies', {}).keys()))
                deps.extend(list(data.get('devDependencies', {}).keys()))

            elif file_name == 'composer.json':
                data = json.loads(content)
                deps.extend(list(data.get('require', {}).keys()))
                deps.extend(list(data.get('require-dev', {}).keys()))

            elif file_name == 'pom.xml':
                root = ET.fromstring(content)
                ns_pattern = re.compile(r'\{.*?\}')
                for dependency in root.findall('.//dependencies/dependency'):
                    groupId = dependency.find(f'.//{ns_pattern.sub("", "groupId")}')
                    artifactId = dependency.find(f'.//{ns_pattern.sub("", "artifactId")}')
                    if groupId is not None and artifactId is not None:
                        deps.append(f"{groupId.text}:{artifactId.text}")

        except Exception as e:
            logging.warning(f"Não foi possível analisar dependências de {file_name}: {e}")

        if deps:
            if self.results["dependencies"].get(file_name):
                self.results["dependencies"][file_name].extend(deps)
            else:
                self.results["dependencies"][file_name] = deps

    def run_analysis(self):
        root_contents = self.api_client.list_repository_files(self.repo_url)
        
        if not root_contents or (isinstance(root_contents, dict) and 'error' in root_contents):
            self.results["summary"].append(f"Não foi possível acessar o conteúdo do repositório: {root_contents.get('error', 'Erro desconhecido')}")
            return self.results
            
        self._find_suspicious_files(root_contents)

        for item in root_contents:
            if item.get('type') in ['file', 'blob']: 
                file_name = item.get('name', '')
                
                content = self.api_client.get_repository_file_content(item)

                if content:
                    if file_name in DEPENDENCY_FILES:
                        self._parse_dependencies(content, file_name)

                    
                    if any(file_name.endswith(ext) for ext in ['.txt', '.json', '.py', '.js', '.sh', '.yml', '.yaml', '.xml']) or file_name in SUSPICIOUS_FILENAMES:
                        self._find_exposed_secrets(content, item.get('path'))
        
       
        for file, deps_list in self.results["dependencies"].items():
            self.results["dependencies"][file] = sorted(list(set(deps_list)))

        if not self.results["summary"]:
             self.results["summary"].append("Nenhum indicador de alto risco encontrado na análise estática inicial.")

        self.results["risk_score"] = min(self.results["risk_score"], 100)
        return self.results