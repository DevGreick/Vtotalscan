import sys
import os
import time
import threading
import configparser
import keyring
from pathlib import Path
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                                   QPushButton, QTextEdit, QLabel, QTabWidget, QComboBox,
                                   QFileDialog, QMessageBox, QProgressDialog, QDialog, QLineEdit, QFormLayout)
from PySide6.QtGui import QIcon, QFont, QPixmap, QPalette, QColor
from PySide6.QtCore import Qt, QThread, Signal

from api_client import ApiClient
from report_generator import ReportGenerator
from utils import parse_targets

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

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
            vt_client = ApiClient()
            ips, urls = parse_targets(self.text_to_analyze)

            if not ips and not urls:
                self.finished.emit(False, "NO_TARGETS")
                return

            all_ip_results = {}
            all_url_results = {}
            total_targets = len(ips) + len(urls)
            processed_count = 0
            
            self.progress_update.emit(0, total_targets)

            for ip in ips:
                if self.isInterruptionRequested(): return
                self.log_message.emit(f"Analisando IP: {ip} (Multi-API)")
                
                vt_result = vt_client.check_ip(ip)
                abuse_result = vt_client.check_ip_abuseipdb(ip)
                shodan_result = vt_client.check_ip_shodan(ip)
                
                all_ip_results[ip] = {
                    'virustotal': vt_result,
                    'abuseipdb': abuse_result,
                    'shodan': shodan_result
                }

                processed_count += 1
                self.progress_update.emit(processed_count, total_targets)

            for url in urls:
                if self.isInterruptionRequested(): return

                self.log_message.emit(f"Analisando URL: {url} (Multi-API)")
                vt_result = vt_client.check_url(url)
                urlhaus_result = vt_client.check_url_urlhaus(url)

                all_url_results[url] = {
                    'virustotal': vt_result,
                    'urlhaus': urlhaus_result
                }

                processed_count += 1
                self.progress_update.emit(processed_count, total_targets)

            self.results = {'ips': all_ip_results, 'urls': all_url_results}
            reporter = ReportGenerator(all_ip_results, all_url_results)
            reporter.generate_excel(self.filepath)
            self.finished.emit(True, self.filepath)

        except Exception as e:
            error_message = f"ERRO CRÍTICO NA THREAD DE ANÁLISE: {e}"
            print(error_message)
            self.log_message.emit(error_message)
            self.finished.emit(False, "")

class AISummaryWorker(QThread):
    finished = Signal(str)
    log_message = Signal(str)
    
    def __init__(self, analysis_data, model):
        super().__init__()
        self.analysis_data = analysis_data
        self.model = model
    
    def run(self):
        self.log_message.emit("Preparando dados para análise da IA...")
        if not self.analysis_data or (not self.analysis_data.get('ips') and not self.analysis_data.get('urls')):
            self.finished.emit("Erro: Realize uma análise primeiro para gerar o resumo.")
            return
        
        malicious_ips_vt = [
            ip for ip, results in self.analysis_data.get('ips', {}).items()
            if results.get('virustotal') and not results['virustotal'].get('error')
            and results['virustotal'].get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0
        ]
        
        malicious_urls_vt = [
            url for url, results in self.analysis_data.get('urls', {}).items()
            if results.get('virustotal') and not results['virustotal'].get('error')
            and results['virustotal'].get('data', {}).get('attributes', {}).get('stats', {}).get('malicious', 0) > 0
        ]

        prompt = ""
        if not malicious_ips_vt and not malicious_urls_vt:
            total_ips = len(self.analysis_data.get('ips', []))
            total_urls = len(self.analysis_data.get('urls', []))
            prompt = f"Com base nos seguintes dados de uma análise, escreva um resumo conciso (em português) informando que a verificação foi concluída e que nenhum indicador malicioso foi detectado.\n\nDADOS: {total_ips} IPs e {total_urls} URLs analisados sem detecções."
        else:
            summary_facts = f"- Total de IPs analisados: {len(self.analysis_data.get('ips', []))}\n"
            if malicious_ips_vt: summary_facts += f"- IPs maliciosos (VirusTotal): {len(malicious_ips_vt)} ({', '.join(malicious_ips_vt)})\n"
            summary_facts += f"- Total de URLs analisadas: {len(self.analysis_data.get('urls', []))}\n"
            if malicious_urls_vt: summary_facts += f"- URLs maliciosas (VirusTotal): {len(malicious_urls_vt)}\n"
            prompt = f"Com base nos seguintes dados de uma análise multi-API, gere uma análise técnica concisa (em português). O resumo deve destacar as ameaças críticas, mencionar os indicadores de maior risco encontrados e listar recomendações ou próximos passos para uma investigação.\n\nDADOS DA ANÁLISE:\n{summary_facts}\n\nANÁLISE GERADA PELA IA:"
        
        self.log_message.emit(f"Enviando prompt para o modelo {self.model}...")
        api_client = ApiClient()
        summary = api_client.get_ai_summary(self.model, prompt)
        self.finished.emit(summary)

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configurações de APIs")
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        link_style = "color:#5698f5; text-decoration: none;"

        # --- VirusTotal ---
        vt_label = QLabel("VirusTotal")
        vt_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        vt_link = QLabel(f"<a href='https://www.virustotal.com/gui/join-us' style='{link_style}'>Obter Chave de API</a>")
        vt_link.setOpenExternalLinks(True)
        self.vt_key_entry = QLineEdit()
        self.vt_key_entry.setEchoMode(QLineEdit.Password)
        form_layout.addRow(vt_label)
        form_layout.addRow(vt_link)
        form_layout.addRow("Chave da API:", self.vt_key_entry)

        # --- AbuseIPDB ---
        abuse_label = QLabel("AbuseIPDB")
        abuse_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        abuse_link = QLabel(f"<a href='https://www.abuseipdb.com/register' style='{link_style}'>Obter Chave de API</a>")
        abuse_link.setOpenExternalLinks(True)
        self.abuse_key_entry = QLineEdit()
        self.abuse_key_entry.setEchoMode(QLineEdit.Password)
        form_layout.addRow(abuse_label)
        form_layout.addRow(abuse_link)
        form_layout.addRow("Chave da API:", self.abuse_key_entry)

        # --- URLHaus ---
        urlhaus_label = QLabel("URLHaus")
        urlhaus_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        urlhaus_link = QLabel(f"<a href='https://urlhaus.abuse.ch/api/' style='{link_style}'>Obter Chave de API</a>")
        urlhaus_link.setOpenExternalLinks(True)
        self.urlhaus_key_entry = QLineEdit()
        self.urlhaus_key_entry.setEchoMode(QLineEdit.Password)
        form_layout.addRow(urlhaus_label)
        form_layout.addRow(urlhaus_link)
        form_layout.addRow("Chave da API:", self.urlhaus_key_entry)

        # --- Shodan ---
        shodan_label = QLabel("Shodan")
        shodan_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        shodan_link = QLabel(f"<a href='https://account.shodan.io/register' style='{link_style}'>Obter Chave de API</a>")
        shodan_link.setOpenExternalLinks(True)
        self.shodan_key_entry = QLineEdit()
        self.shodan_key_entry.setEchoMode(QLineEdit.Password)
        form_layout.addRow(shodan_label)
        form_layout.addRow(shodan_link)
        form_layout.addRow("Chave da API:", self.shodan_key_entry)

        # --- Ollama ---
        ollama_label = QLabel("Ollama")
        ollama_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        ollama_layout = QHBoxLayout()
        self.ollama_endpoint_entry = QLineEdit()
        test_btn = QPushButton("Testar Conexão")
        test_btn.clicked.connect(self.test_ollama_connection)
        ollama_layout.addWidget(self.ollama_endpoint_entry)
        ollama_layout.addWidget(test_btn)
        form_layout.addRow(ollama_label)
        form_layout.addRow("Endpoint:", ollama_layout)
        
        layout.addLayout(form_layout)
        
        save_btn = QPushButton("Salvar Configurações")
        save_btn.setFixedHeight(35)
        save_btn.clicked.connect(self.save_settings)
        layout.addStretch()
        layout.addWidget(save_btn)
        
        self.load_settings()

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
            QMessageBox.critical(self, "Teste de Conexão", f"Falha na conexão com o Ollama em '{endpoint}'.\n\n{models[0] if models else 'Verifique o endpoint e se o Ollama está em execução.'}")

    def load_settings(self):
        vt_key = keyring.get_password("vtotalscan", "virustotal_api_key")
        if vt_key: self.vt_key_entry.setText(vt_key)
        
        abuse_key = keyring.get_password("vtotalscan", "abuseipdb_api_key")
        if abuse_key: self.abuse_key_entry.setText(abuse_key)

        urlhaus_key = keyring.get_password("vtotalscan", "urlhaus_api_key")
        if urlhaus_key: self.urlhaus_key_entry.setText(urlhaus_key)

        shodan_key = keyring.get_password("vtotalscan", "shodan_api_key")
        if shodan_key: self.shodan_key_entry.setText(shodan_key)

        config = configparser.ConfigParser()
        config.read('API_KEY.ini')
        endpoint = config.get('AI', 'endpoint', fallback="http://localhost:11434/api/generate")
        self.ollama_endpoint_entry.setText(endpoint)

    def save_settings(self):
        try:
            if self.vt_key_entry.text():
                keyring.set_password("vtotalscan", "virustotal_api_key", self.vt_key_entry.text().strip())
            if self.abuse_key_entry.text():
                keyring.set_password("vtotalscan", "abuseipdb_api_key", self.abuse_key_entry.text().strip())
            
            if self.urlhaus_key_entry.text():
                keyring.set_password("vtotalscan", "urlhaus_api_key", self.urlhaus_key_entry.text().strip())

            if self.shodan_key_entry.text():
                keyring.set_password("vtotalscan", "shodan_api_key", self.shodan_key_entry.text().strip())

            config = configparser.ConfigParser()
            config.read('API_KEY.ini')
            if not config.has_section('AI'): config.add_section('AI')
            config.set('AI', 'endpoint', self.ollama_endpoint_entry.text().strip())
            with open('API_KEY.ini', 'w') as configfile:
                config.write(configfile)

            QMessageBox.information(self, "Sucesso", "Configurações salvas!")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Erro ao Salvar", f"Não foi possível salvar as configurações:\n{e}")

class VtotalscanGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.last_analysis_results = None
        self.setWindowTitle("ThreatSpy v1.0 by SecZeroR")
        self.setFixedSize(700, 950)
        try:
            self.setWindowIcon(QIcon(resource_path("spy2.ico")))
        except Exception as e:
            print(f"Erro ao carregar ícone da janela principal: {e}")
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        header_layout = QHBoxLayout()
        logo_label = QLabel()
        try:
            pixmap = QPixmap(resource_path("spy2-1.png")).scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(pixmap)
        except Exception as e:
            print(f"Erro ao carregar logo: {e}")
        title_label = QLabel("ThreatSpy")
        title_label.setFont(QFont("Segoe UI", 20, QFont.Bold))
        btn_config = QPushButton("Configurações")
        try:
            btn_config.setIcon(QIcon(resource_path("gear.png")))
        except Exception as e:
            print(f"Erro ao carregar ícone de configurações: {e}")
        btn_config.clicked.connect(self.open_settings_window)
        header_layout.addWidget(logo_label)
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(btn_config)
        input_label = QLabel("Insira os Alvos (IPs ou URLs, um por linha)")
        input_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.text_area = QTextEdit()
        action_bar_layout = QHBoxLayout()
        btn_load = QPushButton("Carregar de Arquivo")
        btn_load.clicked.connect(self.select_file)
        btn_clear = QPushButton("Limpar Alvos")
        btn_clear.clicked.connect(self.clear_text)
        action_bar_layout.addWidget(btn_load)
        action_bar_layout.addWidget(btn_clear)
        self.btn_scan_all = QPushButton("ANALISAR ALVOS")
        self.btn_scan_all.setStyleSheet("background-color: #03A062; color: white; font-weight: bold;")
        self.btn_scan_all.setFixedHeight(40)
        self.btn_scan_all.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_scan_all.clicked.connect(self.start_analysis)
        self.tab_view = QTabWidget()
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.ai_summary_box = QTextEdit()
        self.ai_summary_box.setReadOnly(True)
        self.tab_view.addTab(self.log_console, "Console de Atividade")
        self.tab_view.addTab(self.ai_summary_box, "Resumo Gerado por IA")
        ai_controls_layout = QHBoxLayout()
        ai_label = QLabel("Modelo IA:")
        ai_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.selected_model = QComboBox()
        self.selected_model.addItem("Carregando modelos...")
        self.selected_model.setEnabled(False)
        self.btn_ai_summary = QPushButton("Gerar Resumo em Texto")
        self.btn_ai_summary.setStyleSheet("background-color: #7f8c8d; color: white;")
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.clicked.connect(self.start_ai_task)
        self.btn_ai_summary_pdf = QPushButton("Gerar Resumo em PDF")
        self.btn_ai_summary_pdf.setStyleSheet("background-color: #7f8c8d; color: white;")
        self.btn_ai_summary_pdf.setEnabled(False)
        self.btn_ai_summary_pdf.clicked.connect(self.start_ai_task_pdf)
        ai_controls_layout.addWidget(ai_label)
        ai_controls_layout.addWidget(self.selected_model, 1)
        ai_controls_layout.addWidget(self.btn_ai_summary)
        ai_controls_layout.addWidget(self.btn_ai_summary_pdf)
        main_layout.addLayout(header_layout)
        main_layout.addWidget(input_label)
        main_layout.addWidget(self.text_area, 1)
        main_layout.addLayout(action_bar_layout)
        main_layout.addWidget(self.btn_scan_all)
        main_layout.addWidget(self.tab_view, 2)
        main_layout.addLayout(ai_controls_layout)
        self.load_models_async()
        self.check_api_key_on_startup()

    def open_settings_window(self):
        dialog = SettingsDialog(self)
        if dialog.exec():
            self.api_client = ApiClient() 
            self.load_models_async()

    def check_api_key_on_startup(self):
        api_key = keyring.get_password("vtotalscan", "virustotal_api_key")
        if not api_key:
            config = configparser.ConfigParser()
            config.read('API_KEY.ini')
            if not config.has_option('Auth', 'virustotal_api_key') or 'SUA_CHAVE' in config.get('Auth', 'virustotal_api_key', fallback=''):
                 self.log("Nenhuma chave de API do VirusTotal encontrada.")
                 QMessageBox.warning(self, "Configuração Necessária", "A chave da API do VirusTotal não foi encontrada. Por favor, configure-a para continuar.")
                 self.open_settings_window()

    def load_models_async(self):
        thread = threading.Thread(target=self.populate_model_menu, daemon=True)
        thread.start()

    def populate_model_menu(self):
        api_client = ApiClient()
        models = api_client.get_local_models()
        self.selected_model.clear()
        if models and "não encontrado" not in models[0].lower() and "erro" not in models[0].lower():
            self.selected_model.addItems(models)
            self.selected_model.setEnabled(True)
        else:
            self.selected_model.addItem(models[0] if models else "Nenhum modelo")
            self.selected_model.setEnabled(False)

    def select_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Selecionar arquivo de texto", "", "Arquivos de Texto (*.txt)")
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    self.text_area.setPlainText(f.read())
                self.log(f"Conteúdo do arquivo '{os.path.basename(filepath)}' carregado.")
            except Exception as e:
                QMessageBox.critical(self, "Erro de Leitura", f"Não foi possível ler o arquivo:\n{e}")

    def clear_text(self):
        self.text_area.clear()
        self.log_console.clear()
        self.log("Área de alvos e console limpos.")

    def log(self, message):
        timestamp = time.strftime('%H:%M:%S')
        self.log_console.append(f"[{timestamp}] >> {message}")
        
    def start_analysis(self):
        filepath, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório Excel", "Analise_Completa.xlsx", "Arquivos Excel (*.xlsx)")
        if not filepath:
            self.log("Operação de salvar cancelada pelo usuário.")
            return
            
        self.progress_dialog = QProgressDialog("Análise em progresso...", "Cancelar", 0, 100, self)
        self.progress_dialog.setWindowTitle("Aguarde")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.canceled.connect(self.cancel_analysis)
        self.progress_dialog.show()
        
        self.analysis_thread = AnalysisWorker(self.text_area.toPlainText(), filepath)
        self.analysis_thread.log_message.connect(self.log)
        self.analysis_thread.progress_update.connect(self.update_progress_dialog)
        self.analysis_thread.finished.connect(self.on_analysis_finished)
        self.analysis_thread.start()
    
    def update_progress_dialog(self, current, total):
        if self.progress_dialog:
            self.progress_dialog.setMaximum(total)
            self.progress_dialog.setValue(current)
            self.progress_dialog.setLabelText(f"Analisando {current} de {total} alvos...")

    def cancel_analysis(self):
        if self.analysis_thread and self.analysis_thread.isRunning():
            self.analysis_thread.requestInterruption()
            self.log("Solicitando o cancelamento da análise...")

    def on_analysis_finished(self, success, filepath):
        time.sleep(0.1)
        self.progress_dialog.close()
        
        if filepath == "NO_TARGETS":
            self.log("Nenhum alvo válido encontrado.")
            QMessageBox.warning(self, "Aviso", "Nenhum IP ou URL válido foi encontrado no texto.")
        elif success and filepath:
            self.last_analysis_results = self.analysis_thread.results
            self.log(f"Relatório salvo em: {filepath}")

            file_uri = Path(filepath).as_uri()
            completion_message = f"""
            <p>Análise concluída!</p>
            <p>Relatório salvo em:</p>
            <p><a href="{file_uri}">{filepath}</a></p>
            """
            
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Concluído")
            msg_box.setTextFormat(Qt.RichText)
            msg_box.setText(completion_message)
            msg_box.exec()

            self.btn_ai_summary.setEnabled(True)
            self.btn_ai_summary_pdf.setEnabled(True)
        else:
            self.log("A análise falhou ou foi cancelada.")

    def start_ai_task(self):
        if not self.last_analysis_results:
            QMessageBox.warning(self, "Aviso", "É preciso realizar uma análise primeiro.")
            return
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary_pdf.setEnabled(False)
        self.ai_summary_box.setPlainText("Analisando dados com IA... Por favor, aguarde.")
        self.ai_thread = AISummaryWorker(self.last_analysis_results, self.selected_model.currentText())
        self.ai_thread.log_message.connect(self.log)
        self.ai_thread.finished.connect(self.on_ai_finished)
        self.ai_thread.start()

    def start_ai_task_pdf(self):
        if not self.last_analysis_results:
            QMessageBox.warning(self, "Aviso", "É preciso realizar uma análise primeiro.")
            return
        
        filepath, _ = QFileDialog.getSaveFileName(self, "Salvar Resumo em PDF", "Resumo_IA.pdf", "Arquivos PDF (*.pdf)")
        if not filepath:
            self.log("Operação de salvar cancelada pelo usuário.")
            return

        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary_pdf.setEnabled(False)
        self.ai_summary_box.setPlainText("Gerando resumo em PDF com IA... Por favor, aguarde.")
        
        self.ai_thread = AISummaryWorker(self.last_analysis_results, self.selected_model.currentText())
        self.ai_thread.log_message.connect(self.log)
        self.ai_thread.finished.connect(lambda summary: self.on_ai_finished_pdf(summary, filepath))
        self.ai_thread.start()
        
    def on_ai_finished(self, summary):
        self.ai_summary_box.setPlainText(summary)
        self.tab_view.setCurrentIndex(1)
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary_pdf.setEnabled(True)

    def on_ai_finished_pdf(self, summary, filepath):
        try:
            reporter = ReportGenerator(self.last_analysis_results['ips'], self.last_analysis_results['urls'])
            reporter.generate_pdf_summary(filepath, summary)
            self.log(f"Resumo em PDF salvo em: {filepath}")

            file_uri = Path(filepath).as_uri()
            completion_message = f"""
            <p>Resumo em PDF gerado com sucesso!</p>
            <p>Salvo em:</p>
            <p><a href="{file_uri}">{filepath}</a></p>
            """
            
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Concluído")
            msg_box.setTextFormat(Qt.RichText)
            msg_box.setText(completion_message)
            msg_box.exec()
            
            self.tab_view.setCurrentIndex(1)
            self.ai_summary_box.setPlainText(summary)

        except Exception as e:
            self.log(f"Erro ao gerar o PDF: {e}")
            QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao gerar o relatório em PDF:\n{e}")
        finally:
            self.btn_ai_summary.setEnabled(True)
            self.btn_ai_summary_pdf.setEnabled(True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(45, 45, 45))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)

    GUI = VtotalscanGUI()
    GUI.show()
    sys.exit(app.exec())
