import sys
import os
import time
import threading
import configparser
import keyring
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                                   QPushButton, QTextEdit, QLabel, QTabWidget, QComboBox,
                                   QFileDialog, QMessageBox, QProgressDialog, QDialog, QLineEdit, QFormLayout)
from PySide6.QtGui import QIcon, QFont, QPixmap, QPalette, QColor
from PySide6.QtCore import Qt, QThread, Signal

from api_client import ApiClient
from report_generator import ReportGenerator
from utils import parse_targets, calculate_sha256, resource_path, defang_ioc

def setup_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(message)s')
    file_handler = logging.FileHandler('threatspy.log', mode='a', encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

class AnalysisWorker(QThread):
    finished = Signal(bool, str)
    log_message = Signal(str)
    progress_update = Signal(int, int)
    
    def __init__(self, text_to_analyze, filepath):
        super().__init__()
        self.text_to_analyze = text_to_analyze
        self.filepath = filepath
        self.results = None

    def run(self):
        try:
            api_client = ApiClient()
            ips, urls = parse_targets(self.text_to_analyze)
            if not ips and not urls:
                self.finished.emit(False, "NO_TARGETS")
                return

            all_ip_results, all_url_results = {}, {}
            total_targets = len(ips) + len(urls)
            processed_count = 0
            self.progress_update.emit(0, total_targets)

            with ThreadPoolExecutor(max_workers=10) as executor:
                self.log_message.emit(f"Enviando {len(ips)} IPs para análise paralela...")
                future_to_ip = {executor.submit(api_client.check_ip_multi, ip): ip for ip in ips}
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        all_ip_results[ip] = future.result()
                        self.log_message.emit(f"Resultados para o IP {ip} recebidos.")
                    except Exception as exc:
                        logging.error(f"Erro ao processar o IP {ip}: {exc}", exc_info=True)
                        all_ip_results[ip] = {}
                    processed_count += 1
                    self.progress_update.emit(processed_count, total_targets)

                self.log_message.emit(f"Enviando {len(urls)} URLs para análise paralela...")
                future_to_url = {executor.submit(api_client.check_url_multi, url): url for url in urls}
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        all_url_results[url] = future.result()
                        self.log_message.emit(f"Resultados para a URL {url} recebidos.")
                    except Exception as exc:
                        logging.error(f"Erro ao processar a URL {url}: {exc}", exc_info=True)
                        all_url_results[url] = {}
                    processed_count += 1
                    self.progress_update.emit(processed_count, total_targets)

            self.results = {'ips': all_ip_results, 'urls': all_url_results, 'files': {}}
            reporter = ReportGenerator(all_ip_results, all_url_results)
            reporter.generate_excel(self.filepath)
            self.finished.emit(True, self.filepath)
        except Exception as e:
            logging.error(f"ERRO CRÍTICO NA THREAD DE ANÁLISE DE IOCs: {e}", exc_info=True)
            self.log_message.emit(f"ERRO CRÍTICO NA THREAD. Veja threatspy.log para detalhes.")
            self.finished.emit(False, "")

class FileAnalysisWorker(QThread):
    finished = Signal(bool, str)
    log_message = Signal(str)
    progress_update = Signal(int, int)
    
    def __init__(self, filepaths, save_path):
        super().__init__()
        self.filepaths = filepaths
        self.save_path = save_path
        self.results = None

    def run(self):
        try:
            api_client = ApiClient()
            total_files = len(self.filepaths)
            processed_count = 0
            all_file_results = {}
            self.progress_update.emit(0, total_files)

            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_hash = {}
                for fpath in self.filepaths:
                    if self.isInterruptionRequested(): return
                    filename = os.path.basename(fpath)
                    self.log_message.emit(f"Enfileirando: {filename}")
                    file_hash = calculate_sha256(fpath)
                    if file_hash:
                        future = executor.submit(api_client.check_file_multi, file_hash, filename)
                        future_to_hash[future] = file_hash
                    else:
                        processed_count += 1
                        self.progress_update.emit(processed_count, total_files)

                self.log_message.emit(f"Enviando {len(future_to_hash)} arquivos para análise paralela...")
                for future in as_completed(future_to_hash):
                    file_hash = future_to_hash[future]
                    try:
                        result_data = future.result()
                        all_file_results[file_hash] = result_data
                        filename = result_data.get('filename', 'arquivo')
                        self.log_message.emit(f"Resultados para {filename} recebidos.")
                    except Exception as exc:
                        logging.error(f"Erro ao processar o hash {file_hash}: {exc}", exc_info=True)
                    processed_count += 1
                    self.progress_update.emit(processed_count, total_files)

            self.results = {'ips': {}, 'urls': {}, 'files': all_file_results}
            reporter = ReportGenerator({}, {}, all_file_results)
            reporter.generate_excel(self.save_path)
            self.finished.emit(True, self.save_path)
        except Exception as e:
            logging.error(f"ERRO CRÍTICO NA THREAD DE ANÁLISE DE ARQUIVOS: {e}", exc_info=True)
            self.log_message.emit(f"ERRO CRÍTICO NA ANÁLISE DE ARQUIVOS. Veja threatspy.log para detalhes.")
            self.finished.emit(False, "")

class AISummaryWorker(QThread):
    finished = Signal(str)
    log_message = Signal(str)
    
    def __init__(self, analysis_data, model):
        super().__init__()
        self.analysis_data = analysis_data
        self.model = model
    
    def run(self):
        self.log_message.emit("Preparando dossiê para análise da IA...")
        if not self.analysis_data or (not self.analysis_data.get('ips') and not self.analysis_data.get('urls') and not self.analysis_data.get('files')):
            self.finished.emit("Erro: Nenhuma análise foi realizada ainda.")
            return

        facts = "Dossiê de Análise de Ameaças:\n\n"
        malicious_indicators_exist = False
        
        # Estruturas para armazenar falhas por serviço
        rate_limited_by_service = defaultdict(list)

        files_data = self.analysis_data.get('files', {})
        if files_data:
            malicious_files, not_found_files, failed_files = [], [], []
            for f_hash, res in files_data.items():
                filename = res.get('filename', f_hash[:12])
                vt_res, mb_res = res.get('virustotal'), res.get('malwarebazaar')
                
                is_malicious = (vt_res and not vt_res.get('error') and (vt_res.get('data',{}).get('attributes',{}).get('last_analysis_stats',{}).get('malicious',0) > 0)) or \
                               (mb_res and mb_res.get('query_status') == 'ok' and (mb_res.get('data', [{}]) or [{}])[0].get('signature'))
                is_not_found = (vt_res and vt_res.get('error') == 'Not Found') and (mb_res and mb_res.get('query_status') == 'hash_not_found')
                
                if is_malicious: malicious_files.append(filename)
                elif is_not_found: not_found_files.append(filename)
                elif not (vt_res and mb_res): failed_files.append(filename)
                
                if vt_res and vt_res.get('error') == 'Rate Limit': rate_limited_by_service['VirusTotal'].append(filename)
                if mb_res and mb_res.get('error') == 'Rate Limit': rate_limited_by_service['MalwareBazaar'].append(filename)

            facts += f"**Análise de Arquivos ({len(files_data)} total):**\n"
            if malicious_files: facts += f"- Maliciosos: {len(malicious_files)} ({', '.join(malicious_files)})\n"; malicious_indicators_exist = True
            if not_found_files: facts += f"- Desconhecidos: {len(not_found_files)}\n"
            if failed_files: facts += f"- Falhas (Outros Erros): {len(failed_files)}\n"

        ips_data = self.analysis_data.get('ips', {})
        if ips_data:
            malicious_ips = []
            for ip, res in ips_data.items():
                vt_res = res.get('virustotal')
                if (vt_res and not vt_res.get('error') and (vt_res.get('data',{}).get('attributes',{}).get('last_analysis_stats',{}).get('malicious',0) > 0)):
                    malicious_ips.append(ip)
                if vt_res and vt_res.get('error') == 'Rate Limit': rate_limited_by_service['VirusTotal'].append(ip)
                # Adicionar checagens de rate limit para abuseipdb e shodan se necessário
            
            facts += f"**Análise de IPs ({len(ips_data)} total):**\n"
            if malicious_ips: facts += f"- Maliciosos: {len(malicious_ips)} ({', '.join(malicious_ips)})\n"; malicious_indicators_exist = True
        
        urls_data = self.analysis_data.get('urls', {})
        if urls_data:
            malicious_urls = []
            for url, res in urls_data.items():
                vt_res = res.get('virustotal')
                is_mal_vt = vt_res and not vt_res.get('error') and (vt_res.get('data',{}).get('attributes',{}).get('stats',{}).get('malicious',0) > 0)
                uh_res = res.get('urlhaus')
                is_mal_uh = uh_res and uh_res.get('query_status') == 'ok' and uh_res.get('url_status') == 'online'
                if is_mal_vt or is_mal_uh: malicious_urls.append(url)
                if vt_res and vt_res.get('error') == 'Rate Limit': rate_limited_by_service['VirusTotal'].append(defang_ioc(url))
            
            facts += f"**Análise de URLs ({len(urls_data)} total):**\n"
            if malicious_urls: facts += f"- Maliciosas: {len(malicious_urls)} ({', '.join(defang_ioc(u) for u in malicious_urls)})\n"; malicious_indicators_exist = True

        if rate_limited_by_service:
            facts += "\n**Falhas por Limite de API:**\n"
            for service, items in rate_limited_by_service.items():
                facts += f"- {service}: {len(items)} indicadores afetados ({', '.join(items[:3])}{'...' if len(items) > 3 else ''})\n"

        prompt = (f"Você é um analista de cibersegurança. Sua tarefa é gerar um relatório estruturado com base no dossiê abaixo.\n\n"
                  f"ESTRUTURA OBRIGATÓRIA DO RELATÓRIO:\n"
                  f"### Análise Geral\n"
                  f"(Um parágrafo resumindo os achados de TODAS as categorias: IPs, URLs e Arquivos).\n\n"
                  f"### Recomendações para Indicadores Maliciosos\n"
                  f"(Crie subseções APENAS para as categorias com indicadores maliciosos e liste as recomendações).\n\n"
                  f"### Recomendações para Falhas de Análise\n"
                  f"(Se houverem 'Falhas por Limite de API', explique que a cota da API para o serviço específico (ex: VirusTotal) foi atingida. Recomende aguardar um período antes de reanalisar os itens afetados por aquele serviço).\n\n"
                  f"### Conclusão e Próximos Passos\n"
                  f"(Um parágrafo final com as ações mais importantes, incluindo o que fazer com indicadores 'Desconhecidos').\n\n"
                  f"IMPORTANTE: Não adicione assinaturas, cargos ou data.\n\n"
                  f"--- INÍCIO DO DOSSIÊ ---\n{facts}\n--- FIM DO DOSSIÊ ---")
        
        self.log_message.emit(f"Enviando dossiê para o modelo {self.model}...")
        summary = ApiClient().get_ai_summary(self.model, prompt)
        self.finished.emit(summary)

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configurações de APIs")
        self.setModal(True)
        self.setMinimumWidth(450)
        
        main_layout = QVBoxLayout(self)
        
        tab_widget = QTabWidget()
        link_style = "color:#5698f5; text-decoration: none;"

        self.vt_key_entry = QLineEdit()
        self.abuse_key_entry = QLineEdit()
        self.urlhaus_key_entry = QLineEdit()
        self.shodan_key_entry = QLineEdit()
        self.mb_key_entry = QLineEdit()
        self.ollama_endpoint_entry = QLineEdit()

        tab_widget.addTab(self.create_ollama_tab(), "Ollama")
        tab_widget.addTab(self.create_api_tab("VirusTotal", "https://www.virustotal.com/gui/join-us", self.vt_key_entry, link_style), "VirusTotal")
        tab_widget.addTab(self.create_api_tab("AbuseIPDB", "https://www.abuseipdb.com/register", self.abuse_key_entry, link_style), "AbuseIPDB")
        tab_widget.addTab(self.create_api_tab("URLHaus", "https://urlhaus.abuse.ch/api/", self.urlhaus_key_entry, link_style), "URLHaus")
        tab_widget.addTab(self.create_api_tab("Shodan", "https://account.shodan.io/register", self.shodan_key_entry, link_style), "Shodan")
        tab_widget.addTab(self.create_api_tab("MalwareBazaar", "https://bazaar.abuse.ch/account/", self.mb_key_entry, link_style), "MalwareBazaar")
        
        main_layout.addWidget(tab_widget)
        
        save_btn = QPushButton("Salvar Configurações")
        save_btn.setFixedHeight(35)
        save_btn.clicked.connect(self.save_settings)
        main_layout.addWidget(save_btn)
        
        self.load_settings()

    def create_api_tab(self, title, url, line_edit_widget, link_style):
        tab_widget = QWidget()
        layout = QFormLayout(tab_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        link = QLabel(f"<a href='{url}' style='{link_style}'>Obter Chave de API</a>")
        link.setOpenExternalLinks(True)
        line_edit_widget.setEchoMode(QLineEdit.Password)
        layout.addRow(link)
        layout.addRow("Chave da API:", line_edit_widget)
        return tab_widget

    def create_ollama_tab(self):
        tab_widget = QWidget()
        layout = QFormLayout(tab_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        ollama_layout = QHBoxLayout()
        test_btn = QPushButton("Testar Conexão")
        test_btn.clicked.connect(self.test_ollama_connection)
        ollama_layout.addWidget(self.ollama_endpoint_entry)
        ollama_layout.addWidget(test_btn)
        layout.addRow("Endpoint:", ollama_layout)
        return tab_widget

    def test_ollama_connection(self):
        endpoint = self.ollama_endpoint_entry.text().strip()
        if not endpoint:
            QMessageBox.warning(self, "Teste de Conexão", "O campo de endpoint está vazio.")
            return
        api_client = ApiClient()
        api_client.ai_endpoint = endpoint
        models = api_client.get_local_models()
        if models and "não encontrado" not in models[0].lower() and "erro" not in models[0].lower():
            QMessageBox.information(self, "Teste de Conexão", "Sucesso! Conexão com Ollama estabelecida.")
        else:
            QMessageBox.critical(self, "Teste de Conexão", f"Falha na conexão com o Ollama em '{endpoint}'.\n\n{models[0] if models else 'Verifique o endpoint.'}")

    def load_settings(self):
        if key := keyring.get_password("vtotalscan", "virustotal_api_key"): self.vt_key_entry.setText(key)
        if key := keyring.get_password("vtotalscan", "abuseipdb_api_key"): self.abuse_key_entry.setText(key)
        if key := keyring.get_password("vtotalscan", "urlhaus_api_key"): self.urlhaus_key_entry.setText(key)
        if key := keyring.get_password("vtotalscan", "shodan_api_key"): self.shodan_key_entry.setText(key)
        if key := keyring.get_password("vtotalscan", "malwarebazaar_api_key"): self.mb_key_entry.setText(key)
        
        config = configparser.ConfigParser()
        config.read('API_KEY.ini')
        self.ollama_endpoint_entry.setText(config.get('AI', 'endpoint', fallback="http://localhost:11434/api/generate"))

    def save_settings(self):
        try:
            if key := self.vt_key_entry.text().strip(): keyring.set_password("vtotalscan", "virustotal_api_key", key)
            if key := self.abuse_key_entry.text().strip(): keyring.set_password("vtotalscan", "abuseipdb_api_key", key)
            if key := self.urlhaus_key_entry.text().strip(): keyring.set_password("vtotalscan", "urlhaus_api_key", key)
            if key := self.shodan_key_entry.text().strip(): keyring.set_password("vtotalscan", "shodan_api_key", key)
            if key := self.mb_key_entry.text().strip(): keyring.set_password("vtotalscan", "malwarebazaar_api_key", key)
            
            config = configparser.ConfigParser()
            config.read('API_KEY.ini')
            if not config.has_section('AI'): config.add_section('AI')
            config.set('AI', 'endpoint', self.ollama_endpoint_entry.text().strip())
            with open('API_KEY.ini', 'w') as configfile: config.write(configfile)
            
            QMessageBox.information(self, "Sucesso", "Configurações salvas!")
            self.accept()
        except Exception as e:
            logging.error(f"Não foi possível salvar as configurações: {e}", exc_info=True)
            QMessageBox.critical(self, "Erro ao Salvar", f"Não foi possível salvar as configurações:\n{e}")

class VtotalscanGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.last_ioc_results = None
        self.last_file_results = None
        self.setWindowTitle("ThreatSpy v1.0 by SecZeroR")
        self.setFixedSize(700, 950)
        try:
            self.setWindowIcon(QIcon(resource_path("spy2.ico")))
        except Exception as e:
            logging.error(f"Erro ao carregar ícone da janela principal: {e}")
        central_widget = QWidget(); self.setCentralWidget(central_widget); main_layout = QVBoxLayout(central_widget); header_layout = QHBoxLayout()
        logo_label = QLabel(); pixmap = QPixmap(resource_path("spy2-1.png")).scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation); logo_label.setPixmap(pixmap)
        title_label = QLabel("ThreatSpy"); title_label.setFont(QFont("Segoe UI", 20, QFont.Bold))
        btn_config = QPushButton("Configurações"); btn_config.setIcon(QIcon(resource_path("gear.png"))); btn_config.clicked.connect(self.open_settings_window)
        header_layout.addWidget(logo_label); header_layout.addWidget(title_label); header_layout.addStretch(); header_layout.addWidget(btn_config)
        input_label = QLabel("Insira os Alvos (IPs ou URLs, um por linha)"); input_label.setFont(QFont("Segoe UI", 10, QFont.Bold)); self.text_area = QTextEdit()
        
        action_bar_layout = QHBoxLayout()
        btn_load = QPushButton("Importar Alvos de Arquivo")
        btn_load.clicked.connect(self.select_file)
        btn_scan_files = QPushButton("Verificar Reputação de Arquivos")
        btn_scan_files.clicked.connect(self.start_file_analysis)
        btn_clear = QPushButton("Limpar Alvos")
        btn_clear.clicked.connect(self.clear_text)
        action_bar_layout.addWidget(btn_load)
        action_bar_layout.addWidget(btn_scan_files)
        action_bar_layout.addWidget(btn_clear)
        
        self.btn_scan_iocs = QPushButton("Analisar Alvos")
        self.btn_scan_iocs.setStyleSheet("background-color: #03A062; color: white; font-weight: bold;")
        self.btn_scan_iocs.setFixedHeight(40)
        self.btn_scan_iocs.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_scan_iocs.clicked.connect(self.start_ioc_analysis)
        
        main_layout.addLayout(header_layout)
        main_layout.addWidget(input_label)
        main_layout.addWidget(self.text_area, 1)
        main_layout.addLayout(action_bar_layout)
        main_layout.addWidget(self.btn_scan_iocs)
        
        self.tab_view = QTabWidget(); self.log_console = QTextEdit(); self.log_console.setReadOnly(True); self.ai_summary_box = QTextEdit(); self.ai_summary_box.setReadOnly(True)
        self.tab_view.addTab(self.log_console, "Console de Atividade"); self.tab_view.addTab(self.ai_summary_box, "Resumo Gerado por IA")
        ai_controls_layout = QHBoxLayout(); ai_label = QLabel("Modelo IA:"); ai_label.setFont(QFont("Segoe UI", 10, QFont.Bold)); self.selected_model = QComboBox(); self.selected_model.addItem("Carregando..."); self.selected_model.setEnabled(False)
        self.btn_ai_summary = QPushButton("Gerar Resumo em Texto"); self.btn_ai_summary.setStyleSheet("background-color: #7f8c8d; color: white;"); self.btn_ai_summary.setEnabled(False); self.btn_ai_summary.clicked.connect(self.start_ai_task)
        self.btn_ai_summary_pdf = QPushButton("Gerar Resumo em PDF"); self.btn_ai_summary_pdf.setStyleSheet("background-color: #7f8c8d; color: white;"); self.btn_ai_summary_pdf.setEnabled(False); self.btn_ai_summary_pdf.clicked.connect(self.start_ai_task_pdf)
        ai_controls_layout.addWidget(ai_label); ai_controls_layout.addWidget(self.selected_model, 1); ai_controls_layout.addWidget(self.btn_ai_summary); ai_controls_layout.addWidget(self.btn_ai_summary_pdf)
        main_layout.addWidget(self.tab_view, 2); main_layout.addLayout(ai_controls_layout)
        self.load_models_async(); self.check_api_key_on_startup()
    
    def open_settings_window(self):
        if SettingsDialog(self).exec():
            self.api_client = ApiClient()
            self.load_models_async()

    def check_api_key_on_startup(self):
        if not keyring.get_password("vtotalscan", "virustotal_api_key"):
            self.log("Nenhuma chave de API do VirusTotal encontrada."); QMessageBox.warning(self, "Configuração Necessária", "A chave da API do VirusTotal não foi encontrada. Configure-a para continuar."); self.open_settings_window()
    
    def load_models_async(self):
        threading.Thread(target=self.populate_model_menu, daemon=True).start()
    
    def populate_model_menu(self):
        models = ApiClient().get_local_models()
        self.selected_model.clear()
        if models and "não encontrado" not in models[0].lower() and "erro" not in models[0].lower():
            self.selected_model.addItems(models); self.selected_model.setEnabled(True)
        else:
            self.selected_model.addItem(models[0] if models else "Nenhum modelo"); self.selected_model.setEnabled(False)
    
    def select_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Selecionar arquivo de texto com alvos", "", "Arquivos de Texto (*.txt);;Todos os Arquivos (*)")
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f: self.text_area.setPlainText(f.read())
                self.log(f"Conteúdo de '{os.path.basename(filepath)}' carregado.")
            except Exception as e:
                logging.error(f"Não foi possível ler o arquivo: {filepath} - {e}", exc_info=True)
                QMessageBox.critical(self, "Erro", f"Não foi possível ler o arquivo:\n{e}")
    
    def clear_text(self):
        self.text_area.clear()
        self.log_console.clear()
        self.log("Área de alvos e console limpos.")
    
    def log(self, message):
        timestamp = time.strftime('%H:%M:%S')
        self.log_console.append(f"[{timestamp}] >> {message}")
    
    def start_ioc_analysis(self):
        filepath, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório Excel", "Analise_IOCs.xlsx", "Arquivos Excel (*.xlsx)")
        if not filepath:
            self.log("Operação de salvar cancelada.")
            return

        try:
            with open(filepath, 'a'): pass
        except PermissionError:
            QMessageBox.warning(self, "Arquivo em Uso", f"Não foi possível obter permissão para salvar o relatório em '{os.path.basename(filepath)}'.\n\nVerifique se o arquivo não está aberto e tente novamente.")
            self.log(f"Análise cancelada. O arquivo de relatório '{filepath}' está em uso.")
            return

        self.progress_dialog = QProgressDialog("Análise em progresso...", "Cancelar", 0, 100, self)
        self.progress_dialog.setWindowTitle("Aguarde"); self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.analysis_thread = AnalysisWorker(self.text_area.toPlainText(), filepath)
        self.progress_dialog.canceled.connect(self.analysis_thread.requestInterruption)
        self.analysis_thread.log_message.connect(self.log); self.analysis_thread.progress_update.connect(self.update_progress_dialog); self.analysis_thread.finished.connect(self.on_analysis_finished)
        self.analysis_thread.start()
        self.progress_dialog.show()
    
    def start_file_analysis(self):
        filepaths, _ = QFileDialog.getOpenFileNames(self, "Selecionar Arquivos para Análise", "", "Todos os Arquivos (*)")
        if not filepaths:
            self.log("Nenhum arquivo selecionado.")
            return

        locked_files = []
        for fpath in filepaths:
            try:
                with open(fpath, 'rb') as f: pass 
            except (IOError, PermissionError):
                locked_files.append(os.path.basename(fpath))

        if locked_files:
            files_str = "\n".join(locked_files)
            QMessageBox.warning(self, "Arquivos Bloqueados",
                                f"Não foi possível acessar os seguintes arquivos de entrada:\n\n{files_str}\n\nPor favor, feche os programas que os estão utilizando e tente novamente.")
            self.log(f"Análise cancelada. Arquivos de entrada bloqueados: {', '.join(locked_files)}")
            return

        save_path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório de Arquivos", "Analise_Arquivos.xlsx", "Arquivos Excel (*.xlsx)")
        if not save_path:
            self.log("Operação de salvar cancelada.")
            return
        
        try:
            with open(save_path, 'a'): pass
        except PermissionError:
            QMessageBox.warning(self, "Arquivo em Uso", f"Não foi possível obter permissão para salvar o relatório em '{os.path.basename(save_path)}'.\n\nVerifique se o arquivo não está aberto no Excel e tente novamente.")
            self.log(f"Análise cancelada. O arquivo de relatório '{save_path}' está em uso.")
            return

        self.progress_dialog = QProgressDialog("Análise de arquivos...", "Cancelar", 0, 100, self)
        self.progress_dialog.setWindowTitle("Aguarde"); self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.file_thread = FileAnalysisWorker(filepaths, save_path)
        self.progress_dialog.canceled.connect(self.file_thread.requestInterruption)
        self.file_thread.log_message.connect(self.log); self.file_thread.progress_update.connect(self.update_progress_dialog); self.file_thread.finished.connect(self.on_analysis_finished)
        self.file_thread.start()
        self.progress_dialog.show()

    def update_progress_dialog(self, current, total):
        self.progress_dialog.setMaximum(total); self.progress_dialog.setValue(current); self.progress_dialog.setLabelText(f"Analisando {current} de {total}...")
    
    def on_analysis_finished(self, success, filepath):
        self.progress_dialog.close()
        sender_thread = self.sender()
        if filepath == "NO_TARGETS":
            QMessageBox.warning(self, "Aviso", "Nenhum IP ou URL válido foi encontrado."); self.log("Nenhum alvo válido.")
        elif success and filepath:
            if isinstance(sender_thread, AnalysisWorker): self.last_ioc_results = sender_thread.results
            elif isinstance(sender_thread, FileAnalysisWorker): self.last_file_results = sender_thread.results
            
            if self.last_ioc_results or self.last_file_results: self.btn_ai_summary.setEnabled(True); self.btn_ai_summary_pdf.setEnabled(True)

            self.log(f"Relatório salvo em: {filepath}")
            msg_box = QMessageBox(self); msg_box.setWindowTitle("Concluído"); msg_box.setTextFormat(Qt.RichText); msg_box.setText(f"<p>Análise concluída!</p><p>Relatório salvo em:</p><p><a href='{Path(filepath).as_uri()}'>{filepath}</a></p>"); msg_box.exec()
        else:
            self.log("A análise falhou ou foi cancelada.")
    
    def start_ai_task(self):
        if not ApiClient().ai_endpoint:
            QMessageBox.warning(self, "Configuração Necessária", "O endpoint da IA não foi configurado. Por favor, vá em 'Configurações' para adicioná-lo.")
            return
        if not self.last_ioc_results and not self.last_file_results:
            QMessageBox.warning(self, "Aviso", "Realize uma análise primeiro."); return
        
        combined_results = {
            "ips": self.last_ioc_results.get('ips', {}) if self.last_ioc_results else {},
            "urls": self.last_ioc_results.get('urls', {}) if self.last_ioc_results else {},
            "files": self.last_file_results.get('files', {}) if self.last_file_results else {}
        }
        
        self.btn_ai_summary.setEnabled(False); self.btn_ai_summary_pdf.setEnabled(False); self.ai_summary_box.setPlainText("Analisando com IA...")
        self.ai_thread = AISummaryWorker(combined_results, self.selected_model.currentText()); self.ai_thread.log_message.connect(self.log); self.ai_thread.finished.connect(self.on_ai_finished); self.ai_thread.start()
    
    def start_ai_task_pdf(self):
        if not ApiClient().ai_endpoint:
            QMessageBox.warning(self, "Configuração Necessária", "O endpoint da IA não foi configurado. Por favor, vá em 'Configurações' para adicioná-lo.")
            return
        if not self.last_ioc_results and not self.last_file_results:
            QMessageBox.warning(self, "Aviso", "Realize uma análise primeiro para gerar o PDF."); return
            
        filepath, _ = QFileDialog.getSaveFileName(self, "Salvar Resumo em PDF", "Resumo_IA.pdf", "Arquivos PDF (*.pdf)")
        if not filepath: self.log("Operação cancelada."); return
        
        combined_results = {
            "ips": self.last_ioc_results.get('ips', {}) if self.last_ioc_results else {}, "urls": self.last_ioc_results.get('urls', {}) if self.last_ioc_results else {},
            "files": self.last_file_results.get('files', {}) if self.last_file_results else {}
        }

        self.btn_ai_summary.setEnabled(False); self.btn_ai_summary_pdf.setEnabled(False); self.ai_summary_box.setPlainText("Gerando PDF com IA...")
        self.ai_thread = AISummaryWorker(combined_results, self.selected_model.currentText()); self.ai_thread.log_message.connect(self.log)
        self.ai_thread.finished.connect(lambda summary: self.on_ai_finished_pdf(summary, filepath)); self.ai_thread.start()
    
    def on_ai_finished(self, summary):
        self.ai_summary_box.setPlainText(summary); self.tab_view.setCurrentIndex(1); self.btn_ai_summary.setEnabled(True); self.btn_ai_summary_pdf.setEnabled(True)
    
    def on_ai_finished_pdf(self, summary, filepath):
        try:
            ips_data = self.last_ioc_results.get('ips', {}) if self.last_ioc_results else {}
            urls_data = self.last_ioc_results.get('urls', {}) if self.last_ioc_results else {}
            files_data = self.last_file_results.get('files', {}) if self.last_file_results else {}
            reporter = ReportGenerator(ips_data, urls_data, files_data)
            reporter.generate_pdf_summary(filepath, summary)

            self.log(f"Resumo PDF salvo em: {filepath}")
            msg_box = QMessageBox(self); msg_box.setWindowTitle("Concluído"); msg_box.setTextFormat(Qt.RichText); msg_box.setText(f"<p>PDF gerado!</p><p>Salvo em:</p><p><a href='{Path(filepath).as_uri()}'>{filepath}</a></p>"); msg_box.exec()
            self.ai_summary_box.setPlainText(summary); self.tab_view.setCurrentIndex(1)
        except Exception as e:
            logging.error(f"Falha ao gerar o relatório em PDF: {e}", exc_info=True)
            QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao gerar o relatório em PDF:\n{e}")
        finally:
            self.btn_ai_summary.setEnabled(True); self.btn_ai_summary_pdf.setEnabled(True)

if __name__ == "__main__":
    setup_logging()
    logging.info("Aplicação ThreatSpy iniciada.")
    
    app = QApplication(sys.argv)
    
    app.setStyle("Fusion")
    palette = QPalette(); palette.setColor(QPalette.Window, QColor(45, 45, 45)); palette.setColor(QPalette.WindowText, Qt.white); palette.setColor(QPalette.Base, QColor(25, 25, 25)); palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53)); palette.setColor(QPalette.ToolTipBase, Qt.white); palette.setColor(QPalette.ToolTipText, Qt.white); palette.setColor(QPalette.Text, Qt.white); palette.setColor(QPalette.Button, QColor(53, 53, 53)); palette.setColor(QPalette.ButtonText, Qt.white); palette.setColor(QPalette.BrightText, Qt.red); palette.setColor(QPalette.Link, QColor(42, 130, 218)); palette.setColor(QPalette.Highlight, QColor(42, 130, 218)); palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)

    GUI = VtotalscanGUI()
    GUI.show()
    sys.exit(app.exec())