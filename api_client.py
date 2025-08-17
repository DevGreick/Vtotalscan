import requests
import configparser
import urllib3
import time
import keyring

class ApiClient:
    def __init__(self):
        
        self.vt_api_key = keyring.get_password("vtotalscan", "virustotal_api_key")
        self.abuseipdb_api_key = keyring.get_password("vtotalscan", "abuseipdb_api_key")
        self.urlhaus_api_key = keyring.get_password("vtotalscan", "urlhaus_api_key")
        self.shodan_api_key = keyring.get_password("vtotalscan", "shodan_api_key")
        self.ai_endpoint = self._read_config('AI', 'endpoint')
        
        self.session = requests.Session()
        self.session.headers.update({ "User-Agent": "Vtotalscan/1.0" })
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _read_config(self, section, key):
       
        try:
            config = configparser.ConfigParser()
            config.read('API_KEY.ini')
            return config.get(section, key, fallback=None)
        except Exception:
            return None

    def _make_request(self, method, url, max_retries=3, **kwargs):
        """
        Função central para fazer requisições, com lógica de rate limit inteligente.
        """
        retries = 0
        while retries < max_retries:
            try:
                response = self.session.request(method, url, timeout=20, **kwargs)
                
                
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    print(f"Limite da API atingido. Aguardando {retry_after} segundos...")
                    time.sleep(retry_after)
                    retries += 1
                    continue 
                
                response.raise_for_status() 
                return response.json()

            except requests.exceptions.HTTPError as e:
                
                if "shodan" in url and e.response.status_code == 404:
                    print(f"Recurso não encontrado no Shodan: {url}")
                    return {"error": "Not found"}
                print(f"Erro HTTP em '{url}': {e}")
                return None
            except requests.exceptions.RequestException as e:
                print(f"Erro de requisição em '{url}': {e}")
                return None
        
        print(f"Máximo de tentativas atingido para a URL: {url}")
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

    def check_ip_abuseipdb(self, ip):
        if not self.abuseipdb_api_key: return None
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': self.abuseipdb_api_key}
        return self._make_request('GET', url, headers=headers, params=params)

    def check_url_urlhaus(self, url_to_check):
        if not self.urlhaus_api_key: return None
        url = 'https://urlhaus-api.abuse.ch/v1/url/'
        data = {'url': url_to_check}
        headers = {'Auth-Key': self.urlhaus_api_key}
        return self._make_request('POST', url, headers=headers, data=data)

    def check_ip_shodan(self, ip):
        if not self.shodan_api_key: return None
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {'key': self.shodan_api_key}
        return self._make_request('GET', url, params=params)
            
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
            return ["Erro ao buscar modelos"]
            
    def get_ai_summary(self, model, prompt):
        # (sem alterações)
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
            return f"Falha ao contatar a IA: {e}"