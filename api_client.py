import requests
import configparser
import urllib3
import time
import keyring
import logging
import base64
from urllib.parse import urlparse, quote_plus

class ApiClient:
    def __init__(self):
        self.vt_api_key = keyring.get_password("vtotalscan", "virustotal_api_key")
        self.abuseipdb_api_key = keyring.get_password("vtotalscan", "abuseipdb_api_key")
        self.urlhaus_api_key = keyring.get_password("vtotalscan", "urlhaus_api_key")
        self.shodan_api_key = keyring.get_password("vtotalscan", "shodan_api_key")
        self.mb_api_key = keyring.get_password("vtotalscan", "malwarebazaar_api_key")
        self.github_api_key = keyring.get_password("vtotalscan", "github_api_key")
        self.gitlab_api_key = keyring.get_password("vtotalscan", "gitlab_api_key")
        self.ai_endpoint = self._read_config('AI', 'endpoint')
        
        self.session = requests.Session()
        self.session.headers.update({ "User-Agent": "ThreatSpy/1.2" })
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _read_config(self, section, key):
        try:
            config = configparser.ConfigParser()
            config.read('API_KEY.ini')
            return config.get(section, key, fallback=None)
        except Exception as e:
            logging.error(f"Erro ao ler o arquivo de configuração API_KEY.ini: {e}")
            return None

    def _make_request(self, method, url, max_retries=3, **kwargs):
        retries = 0
        backoff_factor = 2 
        while retries < max_retries:
            try:
                response = self.session.request(method, url, timeout=20, **kwargs)
                response.raise_for_status() 
                return response.json()
            except requests.exceptions.HTTPError as e:
                if 400 <= e.response.status_code < 500:
                    if e.response.status_code in [429, 403]: 
                        logging.warning(f"Limite/bloqueio da API atingido ({e.response.status_code}). Aguardando para tentar novamente...")
                        time.sleep((backoff_factor ** retries))
                        retries += 1
                        if retries == max_retries:
                            logging.error(f"Máximo de retentativas para limite de API atingido em {url}.")
                            return {"error": "Rate Limit"}
                        continue
                    if e.response.status_code == 404:
                        logging.info(f"Recurso não encontrado na API (404): {url}")
                        return {"error": "Not Found"}
                    
                    logging.error(f"Erro de Cliente HTTP (4xx) em '{url}': {e}")
                    return None 
                
                logging.warning(f"Erro de Servidor HTTP (5xx) em '{url}': {e}. Tentando novamente...")
                time.sleep((backoff_factor ** retries))
                retries += 1

            except requests.exceptions.RequestException as e:
                logging.warning(f"Erro de requisição em '{url}': {e}. Tentando novamente...")
                time.sleep((backoff_factor ** retries))
                retries += 1
        
        logging.error(f"Máximo de tentativas atingido para a URL: {url}")
        return None

    def _get_platform_from_url(self, repo_url):
        hostname = urlparse(repo_url).hostname
        if hostname and 'github.com' in hostname:
            return 'github'
        if hostname and 'gitlab.com' in hostname:
            return 'gitlab'
        return None
        
    def _get_gitlab_project_id(self, project_path, gitlab_host):
        project_path_encoded = quote_plus(project_path)
        url = f"https://{gitlab_host}/api/v4/projects/{project_path_encoded}"
        headers = {}
        if self.gitlab_api_key:
            headers["PRIVATE-TOKEN"] = self.gitlab_api_key
            
        project_data = self._make_request('GET', url, headers=headers)
        if project_data and isinstance(project_data, dict) and 'id' in project_data:
            return project_data['id']
        logging.error(f"Não foi possível encontrar o ID do projeto GitLab para: {project_path}")
        return None

    def list_repository_files(self, repo_url):
        platform = self._get_platform_from_url(repo_url)
        parsed_url = urlparse(repo_url)
        path_parts = parsed_url.path.strip('/').split('/')
        
        if platform == 'github':
            owner, repo = path_parts[0], path_parts[1]
            api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/"
            headers = {"Accept": "application/vnd.github.v3+json"}
            if self.github_api_key:
                headers["Authorization"] = f"token {self.github_api_key}"
            
            files = self._make_request('GET', api_url, headers=headers)
            if isinstance(files, list):
                return [{'name': f.get('name'), 'path': f.get('path'), 'type': f.get('type'), 'platform': 'github', 'item_url': f.get('url')} for f in files]
            return files

        elif platform == 'gitlab':
            project_path = "/".join(path_parts)
            project_id = self._get_gitlab_project_id(project_path, parsed_url.hostname)
            if not project_id:
                return {"error": "GitLab Project Not Found"}

            api_url = f"https://{parsed_url.hostname}/api/v4/projects/{project_id}/repository/tree"
            headers = {}
            if self.gitlab_api_key:
                headers["PRIVATE-TOKEN"] = self.gitlab_api_key

            files = self._make_request('GET', api_url, headers=headers)
            if isinstance(files, list):
                return [{'name': f.get('name'), 'path': f.get('path'), 'type': f.get('type'), 'platform': 'gitlab', 'project_id': project_id} for f in files]
            return files
        
        return {"error": "Platform not supported"}

    def get_repository_file_content(self, file_info):
        platform = file_info.get('platform')

        if platform == 'github':
            headers = {"Accept": "application/vnd.github.v3+json"}
            if self.github_api_key:
                headers["Authorization"] = f"token {self.github_api_key}"
            
            response = self._make_request('GET', file_info['item_url'], headers=headers)
            if response and 'content' in response:
                return base64.b64decode(response['content']).decode('utf-8', errors='ignore')

        elif platform == 'gitlab':
            project_id = file_info['project_id']
            file_path_encoded = quote_plus(file_info['path'])
            api_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/{file_path_encoded}?ref=main"
            headers = {}
            if self.gitlab_api_key:
                headers["PRIVATE-TOKEN"] = self.gitlab_api_key

            response = self._make_request('GET', api_url, headers=headers)
            if response and 'content' in response:
                return base64.b64decode(response['content']).decode('utf-8', errors='ignore')

        return None

    def check_ip(self, ip):
        if not self.vt_api_key: return None
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_api_key}
        return self._make_request('GET', url, headers=headers)

    def check_url(self, url_to_check):
        if not self.vt_api_key: return None
        post_url = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": url_to_check}
        headers = {"x-apikey": self.vt_api_key}
        
        post_response = self._make_request('POST', post_url, headers=headers, data=payload)
        if not post_response or 'data' not in post_response:
            return None
        
        analysis_id = post_response['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        for _ in range(10): 
            analysis_report = self._make_request('GET', analysis_url, headers=headers)
            if analysis_report and analysis_report.get('data', {}).get('attributes', {}).get('status') == 'completed':
                return analysis_report
            time.sleep(15)
        return None

    def check_file(self, file_hash):
        if not self.vt_api_key: return None
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_api_key}
        return self._make_request('GET', url, headers=headers)

    def check_hash_malwarebazaar(self, file_hash):
        if not self.mb_api_key: return None
        url = "https://mb-api.abuse.ch/api/v1/"
        headers = { 'Auth-Key': self.mb_api_key }
        data = { 'query': 'get_info', 'hash': file_hash }
        return self._make_request('POST', url, headers=headers, data=data)

    def check_ip_abuseipdb(self, ip):
        if not self.abuseipdb_api_key: return None
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': self.abuseipdb_api_key}
        return self._make_request('GET', url, headers=headers, params=params)

    def check_url_urlhaus(self, url_to_check):
        if not self.urlhaus_api_key:
            logging.warning("Chave de API do URLhaus não configurada. Pulando consulta.")
            return None
        url = 'https://urlhaus-api.abuse.ch/v1/url/'
        data = {'url': url_to_check}
        headers = {'Auth-Key': self.urlhaus_api_key}
        return self._make_request('POST', url, data=data, headers=headers)

    def check_ip_shodan(self, ip):
        if not self.shodan_api_key: return None
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {'key': self.shodan_api_key}
        return self._make_request('GET', url, params=params)

    def check_ip_multi(self, ip):
        return {
            'virustotal': self.check_ip(ip),
            'abuseipdb': self.check_ip_abuseipdb(ip),
            'shodan': self.check_ip_shodan(ip)
        }

    def check_url_multi(self, url):
        return {
            'virustotal': self.check_url(url),
            'urlhaus': self.check_url_urlhaus(url)
        }

    def check_file_multi(self, file_hash, filename):
        return {
            'virustotal': self.check_file(file_hash),
            'malwarebazaar': self.check_hash_malwarebazaar(file_hash),
            'filename': filename
        }
            
    def get_local_models(self):
        if not self.ai_endpoint: return ["Erro: Endpoint não configurado"]
        try:
            base_url = "/".join(self.ai_endpoint.split('/')[:3])
            tags_url = f"{base_url}/api/tags"
            response = self.session.get(tags_url, timeout=5)
            response.raise_for_status()
            models = response.json().get("models", [])
            model_names = [model['name'] for model in models]
            return model_names if model_names else ["Nenhum modelo local encontrado"]
        except requests.exceptions.ConnectionError:
            return ["Ollama não encontrado (Verifique Endpoint)"]
        except Exception as e:
            logging.error(f"Erro ao buscar modelos de IA: {e}")
            return ["Erro ao buscar modelos"]
            
    def get_ai_summary(self, model, prompt):
        if not self.ai_endpoint or not model:
            raise ValueError("Endpoint ou modelo da IA inválido/não selecionado.")
        try:
            payload = {"model": model, "prompt": prompt, "stream": False}
            response = self.session.post(self.ai_endpoint, json=payload, timeout=180)
            response.raise_for_status()
            return response.json().get("response", "Nenhuma resposta recebida do modelo.").strip()
        except requests.exceptions.ConnectionError:
            return f"Erro de Conexão: Não foi possível conectar ao Ollama em {self.ai_endpoint}."
        except Exception as e:
            logging.error(f"Falha ao contatar a IA: {e}", exc_info=True)
            return f"Falha ao contatar a IA. Veja threatspy.log para detalhes."