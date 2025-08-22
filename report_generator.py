import xlsxwriter
import hashlib
import re
import logging
import datetime
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.colors import navy, red, black, lightgrey, whitesmoke, grey, blue, white
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from utils import defang_ioc, resource_path

class ReportGenerator:
    def __init__(self, ip_results_dict, url_results_dict, file_results_dict=None, repo_results_dict=None):
        self.ip_results_dict = ip_results_dict if ip_results_dict is not None else {}
        self.url_results_dict = url_results_dict if url_results_dict is not None else {}
        self.file_results_dict = file_results_dict if file_results_dict is not None else {}
        self.repo_results_dict = repo_results_dict if repo_results_dict is not None else []
        self.generation_time = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    def _draw_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(grey)
        
        canvas.line(doc.leftMargin, 0.7 * inch, doc.width + doc.leftMargin, 0.7 * inch)
        
        left_text = "Relatório ThreatSpy - CONFIDENCIAL"
        canvas.drawString(doc.leftMargin, 0.5 * inch, left_text)
        
        right_text = f"Página {canvas.getPageNumber()} | Gerado em: {self.generation_time}"
        canvas.drawRightString(doc.width + doc.leftMargin, 0.5 * inch, right_text)
        
        canvas.restoreState()

    def generate_excel(self, filepath):
        try:
            with xlsxwriter.Workbook(filepath) as workbook:
                header_format = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#004B8B', 'border': 1, 'align': 'center', 'valign': 'vcenter'})
                cell_format = workbook.add_format({'border': 1, 'valign': 'top'})
                wrap_format = workbook.add_format({'border': 1, 'valign': 'top', 'text_wrap': True})
                error_format = workbook.add_format({'font_color': 'red', 'border': 1, 'valign': 'top'})
                warning_format = workbook.add_format({'font_color': '#FFC000', 'border': 1, 'valign': 'top'})
                hyperlink_format = workbook.add_format({'font_color': 'blue', 'underline': 1, 'border': 1, 'valign': 'top'})
                score_high = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'border': 1, 'valign': 'top'})
                score_med = workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500', 'border': 1, 'valign': 'top'})

                if self.repo_results_dict:
                    ws_repo = workbook.add_worksheet("Relatório de Repositório")
                    headers_repo = ["Repositório URL", "Risco Estático", "Resumo", "Segredos Expostos", "Arquivos Suspeitos", "Dependências", "IOCs Extraídos"]
                    ws_repo.write_row('A1', headers_repo, header_format)
                    ws_repo.set_column('A:A', 50); ws_repo.set_column('B:B', 15); ws_repo.set_column('C:G', 40)
                    
                    row_num = 1
                    for res in self.repo_results_dict:
                        row_num += 1
                        score = res.get('risk_score', 0)
                        score_format = score_high if score >= 50 else (score_med if score >= 20 else cell_format)
                        
                        secrets_str = "\n".join([f"- {s['type']} em {s['file']}" for s in res.get('exposed_secrets', [])])
                        deps_str = "\n".join([f"{file}: {', '.join(pkgs)}" for file, pkgs in res.get('dependencies', {}).items()])
                        
                        iocs_list = []
                        for ioc_info in res.get('extracted_iocs', []):
                            ioc = ioc_info.get('ioc', 'N/A')
                            rep = ioc_info.get('reputation', {})
                            vt_malicious = rep.get('virustotal', {}).get('data', {}).get('attributes', {}).get('stats', {}).get('malicious', 0)
                            uh_status = rep.get('urlhaus', {}).get('url_status', 'N/A')
                            iocs_list.append(f"- {defang_ioc(ioc)} (VT: {vt_malicious}, URLHaus: {uh_status})")
                        iocs_str = "\n".join(iocs_list)

                        ws_repo.write(f'A{row_num}', res.get('url'), cell_format)
                        ws_repo.write(f'B{row_num}', f"{score}/100", score_format)
                        ws_repo.write(f'C{row_num}', "\n".join(f"- {s}" for s in res.get('summary', [])), wrap_format)
                        ws_repo.write(f'D{row_num}', secrets_str if secrets_str else "Nenhum", wrap_format)
                        ws_repo.write(f'E{row_num}', "\n".join(res.get('suspicious_files', [])), wrap_format)
                        ws_repo.write(f'F{row_num}', deps_str if deps_str else "Nenhuma", wrap_format)
                        ws_repo.write(f'G{row_num}', iocs_str if iocs_str else "Nenhum", wrap_format)

                if self.ip_results_dict:
                    ws_ips = workbook.add_worksheet("Relatório de IPs")
                    headers_ip = ["IP", "VT Link", "AbuseIPDB Link", "VT Detecções", "AbuseIPDB Score", "País (AbuseIPDB)", "Provedor (VT)", "Shodan Portas", "Shodan Organização", "Shodan Hostnames", "Shodan CVEs"]
                    ws_ips.write_row('A1', headers_ip, header_format)
                    ws_ips.set_column('A:A', 20); ws_ips.set_column('B:C', 15); ws_ips.set_column('D:F', 15); ws_ips.set_column('G:G', 30); ws_ips.set_column('H:H', 20); ws_ips.set_column('I:K', 35)
                    row_num = 1
                    for ip, results in self.ip_results_dict.items():
                        row_num += 1
                        ws_ips.write(f'A{row_num}', defang_ioc(ip), cell_format)
                        ws_ips.write_url(f'B{row_num}', f'https://www.virustotal.com/gui/ip-address/{ip}', hyperlink_format, "VT Link")
                        ws_ips.write_url(f'C{row_num}', f'https://www.abuseipdb.com/check/{ip}', hyperlink_format, "AbuseIPDB Link")
                        vt_res = results.get('virustotal'); abuse_res = results.get('abuseipdb'); shodan_res = results.get('shodan')
                        
                        if vt_res and not vt_res.get('error'):
                            attrs = vt_res.get("data", {}).get("attributes", {}); malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                            ws_ips.write(f'D{row_num}', malicious, score_high if malicious > 0 else cell_format); ws_ips.write(f'G{row_num}', attrs.get('as_owner', 'N/A'), cell_format)
                        elif vt_res and vt_res.get('error') == 'Rate Limit':
                            ws_ips.write(f'D{row_num}', 'Limite Atingido', warning_format)
                            ws_ips.write(f'G{row_num}', 'N/A', cell_format)
                        else: 
                            ws_ips.write(f'D{row_num}', 'Falha', error_format); ws_ips.write(f'G{row_num}', 'N/A', error_format)
                        
                        if abuse_res and abuse_res.get('data'):
                            data = abuse_res['data']; score = data.get('abuseConfidenceScore', 0)
                            score_format = score_high if score >= 90 else (score_med if score >= 50 else cell_format)
                            ws_ips.write(f'E{row_num}', score, score_format); ws_ips.write(f'F{row_num}', data.get('countryCode', 'N/A'), cell_format)
                        else: ws_ips.write_row(f'E{row_num}', ['Falha', 'N/A'], error_format)
                        
                        if shodan_res and not shodan_res.get('error'):
                            ws_ips.write(f'H{row_num}', ", ".join(map(str, shodan_res.get('ports', []))), wrap_format); ws_ips.write(f'I{row_num}', shodan_res.get('org', 'N/A'), wrap_format)
                            ws_ips.write(f'J{row_num}', ", ".join(defang_ioc(h) for h in shodan_res.get('hostnames', [])), wrap_format); ws_ips.write(f'K{row_num}', ", ".join(shodan_res.get('vulns', [])) if shodan_res.get('vulns') else "Nenhuma", wrap_format)
                        elif shodan_res and shodan_res.get('error') == 'Not Found': ws_ips.write_row(f'H{row_num}', ['Não encontrado', 'N/A', 'N/A', 'N/A'], cell_format)
                        else: ws_ips.write_row(f'H{row_num}', ['Falha', 'N/A', 'N/A', 'N/A'], error_format)

                if self.url_results_dict:
                    ws_urls = workbook.add_worksheet("Relatório de URLs")
                    headers_url = ["URL", "VT Link", "VT Detecções", "URLHaus Status", "URLHaus Tags"]
                    ws_urls.write_row('A1', headers_url, header_format)
                    ws_urls.set_column('A:A', 60); ws_urls.set_column('B:C', 15); ws_urls.set_column('D:E', 25)
                    row_num = 1
                    for url, results in self.url_results_dict.items():
                        row_num += 1
                        ws_urls.write(f'A{row_num}', defang_ioc(url), wrap_format)
                        vt_res = results.get('virustotal'); uh_res = results.get('urlhaus')
                        
                        if vt_res and not vt_res.get('error'):
                            final_url = vt_res.get("meta", {}).get("url_info", {}).get("url", url); url_hash = hashlib.sha256(final_url.encode('utf-8')).hexdigest()
                            malicious = vt_res.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)
                            ws_urls.write_url(f'B{row_num}', f"https://www.virustotal.com/gui/url/{url_hash}", hyperlink_format, "Link"); ws_urls.write(f'C{row_num}', malicious, score_high if malicious > 0 else cell_format)
                        elif vt_res and vt_res.get('error') == 'Rate Limit':
                            ws_urls.write_url(f'B{row_num}', f"https://www.virustotal.com/gui/search/{url}", hyperlink_format, "Link")
                            ws_urls.write(f'C{row_num}', 'Limite Atingido', warning_format)
                        else: 
                            ws_urls.write_url(f'B{row_num}', f"https://www.virustotal.com/gui/search/{url}", hyperlink_format, "Link")
                            ws_urls.write(f'C{row_num}', 'Falha', error_format)
                        
                        if uh_res and uh_res.get('query_status') == 'ok' and uh_res.get('url_status'):
                            status = uh_res.get('url_status', 'not_found'); tags = ", ".join(uh_res.get('tags', []))
                            ws_urls.write(f'D{row_num}', status, score_high if status == 'online' else cell_format); ws_urls.write(f'E{row_num}', tags if tags else "N/A", cell_format)
                        elif uh_res and uh_res.get('query_status') == 'no_results': 
                            ws_urls.write_row(f'D{row_num}', ['Não encontrado', 'N/A'], cell_format)
                        else: 
                            ws_urls.write_row(f'D{row_num}', ['Falha', 'N/A'], error_format)

                if self.file_results_dict:
                    ws_files = workbook.add_worksheet("Relatório de Arquivos")
                    headers_file = ["Arquivo Original", "SHA256", "VT Link", "VT Detecções", "MB Nome da Ameaça", "Tipo (TrID)", "Tamanho (Bytes)"]
                    ws_files.write_row('A1', headers_file, header_format)
                    ws_files.set_column('A:A', 30); ws_files.set_column('B:B', 65); ws_files.set_column('C:D', 15); ws_files.set_column('E:E', 25); ws_files.set_column('F:G', 20)
                    row_num = 1
                    for f_hash, results in self.file_results_dict.items():
                        row_num += 1
                        ws_files.write(f'A{row_num}', results.get('filename', 'N/A'), cell_format)
                        ws_files.write(f'B{row_num}', f_hash, cell_format)
                        ws_files.write_url(f'C{row_num}', f'https://www.virustotal.com/gui/file/{f_hash}', hyperlink_format, "VT Link")
                        
                        vt_res = results.get('virustotal')
                        if vt_res and not vt_res.get('error'):
                            attrs = vt_res.get("data", {}).get("attributes", {}); malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                            trid = attrs.get('trid', [{}])[0].get('file_type', 'N/A'); size = attrs.get('size', 0)
                            ws_files.write(f'D{row_num}', malicious, score_high if malicious > 0 else cell_format)
                            ws_files.write_row(f'F{row_num}', [trid, size], wrap_format)
                        elif vt_res and vt_res.get('error') == 'Not Found':
                            ws_files.write(f'D{row_num}', 'Não encontrado', cell_format)
                            ws_files.write_row(f'F{row_num}', ['N/A', 'N/A'], cell_format)
                        elif vt_res and vt_res.get('error') == 'Rate Limit':
                            ws_files.write(f'D{row_num}', 'Limite Atingido', warning_format)
                            ws_files.write_row(f'F{row_num}', ['N/A', 'N/A'], cell_format)
                        else:
                            ws_files.write(f'D{row_num}', 'Falha', error_format)
                            ws_files.write_row(f'F{row_num}', ['N/A', 'N/A'], error_format)

                        mb_res = results.get('malwarebazaar')
                        if mb_res and mb_res.get('query_status') == 'ok':
                            threat_name = (mb_res.get('data', [{}]) or [{}])[0].get('signature')
                            ws_files.write(f'E{row_num}', threat_name, score_high if threat_name else cell_format)
                        elif mb_res and mb_res.get('query_status') == 'hash_not_found':
                            ws_files.write(f'E{row_num}', 'Não encontrado', cell_format)
                        elif mb_res and mb_res.get('error') == 'Rate Limit':
                            ws_files.write(f'E{row_num}', 'Limite Atingido', warning_format)
                        else:
                            ws_files.write(f'E{row_num}', 'Falha', error_format)
        except Exception as e:
            logging.error(f"Falha ao escrever o arquivo XLSX: {e}", exc_info=True)
            raise e

    def generate_pdf_summary(self, filepath, summary_text):
        try:
            try:
                pdfmetrics.registerFont(TTFont('DejaVuSans', resource_path('DejaVuSans.ttf')))
                pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', resource_path('DejaVuSans-Bold.ttf')))
                pdfmetrics.registerFontFamily('DejaVuSans', normal='DejaVuSans', bold='DejaVuSans-Bold')
                font_name, font_name_bold = 'DejaVuSans', 'DejaVuSans-Bold'
            except Exception:
                logging.warning("Fontes DejaVuSans não encontradas. Usando Helvetica como fallback.")
                font_name, font_name_bold = 'Helvetica', 'Helvetica-Bold'
                
            doc = SimpleDocTemplate(filepath, topMargin=0.5*inch, bottomMargin=0.8*inch)
            
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(name='Justify', fontName=font_name, alignment=TA_JUSTIFY, fontSize=10, leading=12))
            styles.add(ParagraphStyle(name='TableCell', fontName=font_name, fontSize=8, leading=10, alignment=TA_LEFT))
            styles.add(ParagraphStyle(name='TableCellBold', fontName=font_name_bold, fontSize=8, leading=10, alignment=TA_LEFT, textColor=white))
            styles['h1'].fontName = font_name_bold; styles['h2'].fontName = font_name_bold; styles['h3'].fontName = font_name_bold; styles['Normal'].fontName = font_name
            story = []
            
            title = Paragraph("<b>Análise Técnica Resumida – Multi-API</b>", styles['h1']); title.alignment = TA_CENTER
            story.append(title); story.append(Spacer(1, 0.2*inch))
            
            malicious_ips_vt = [ip for ip, res in self.ip_results_dict.items() if (res.get('virustotal') or {}).get('data',{}).get('attributes',{}).get('last_analysis_stats',{}).get('malicious',0) > 0]
            malicious_urls_vt = [url for url, res in self.url_results_dict.items() if (res.get('virustotal') or {}).get('data',{}).get('attributes',{}).get('stats',{}).get('malicious',0) > 0]
            malicious_files_vt = [(res.get('filename', f_hash[:15]), f_hash) for f_hash, res in self.file_results_dict.items() if (res.get('virustotal') or {}).get('data',{}).get('attributes',{}).get('last_analysis_stats',{}).get('malicious',0) > 0]
            
            malicious_iocs_from_repos = []
            for repo in self.repo_results_dict:
                for ioc_info in repo.get('extracted_iocs', []):
                    rep = ioc_info.get('reputation', {})
                    vt_malicious = rep.get('virustotal', {}).get('data', {}).get('attributes', {}).get('stats', {}).get('malicious', 0)
                    if vt_malicious > 0:
                        malicious_iocs_from_repos.append(ioc_info.get('ioc'))

            summary_data = [['Item', 'Resultado']]
            if self.repo_results_dict:
                summary_data.extend([['Total de Repositórios analisados', str(len(self.repo_results_dict))]])
                highest_risk_repo = max(self.repo_results_dict, key=lambda r: r.get('risk_score', 0), default=None)
                if highest_risk_repo:
                    repo_url = highest_risk_repo.get("url", "N/A")
                    wrapped_url = Paragraph(f'<a href="{repo_url}" color="blue">{repo_url}</a>', styles['TableCell'])
                    summary_data.extend([
                        ['Repositório com Maior Risco', wrapped_url],
                        ['Maior Risco Encontrado', f"{highest_risk_repo.get('risk_score', 0)}/100"]
                    ])
                if malicious_iocs_from_repos:
                    summary_data.append(['IOCs maliciosos (de Repos)', str(len(malicious_iocs_from_repos))])

            if self.ip_results_dict: summary_data.extend([['Total de IPs analisados', str(len(self.ip_results_dict))], ['IPs maliciosos (VT)', str(len(malicious_ips_vt))]])
            if self.url_results_dict: summary_data.extend([['Total de URLs analisadas', str(len(self.url_results_dict))], ['URLs maliciosas (VT)', str(len(malicious_urls_vt))]])
            if self.file_results_dict: summary_data.extend([['Total de arquivos analisados', str(len(self.file_results_dict))], ['Arquivos maliciosos (VT)', str(len(malicious_files_vt))]])
            
            summary_table = Table(summary_data, colWidths=[2.5*inch, 4.5*inch]); summary_table.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), navy), ('TEXTCOLOR',(0,0),(-1,0), white), ('ALIGN', (0,0), (-1,-1), 'CENTER'), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'), ('FONTNAME', (0,0), (-1,0), font_name_bold), ('BOTTOMPADDING', (0,0), (-1,0), 12), ('BACKGROUND', (0,1), (-1,-1), (0.9, 0.9, 0.9)), ('GRID', (0,0), (-1,-1), 1, (0.7,0.7,0.7))]))
            story.append(summary_table); story.append(Spacer(1, 0.2*inch))

            if malicious_ips_vt or malicious_urls_vt or malicious_files_vt or malicious_iocs_from_repos:
                story.append(Paragraph("<b>Indicadores Maliciosos Encontrados (Destaque)</b>", styles['h2'])); story.append(Spacer(1, 0.1*inch))
                if malicious_iocs_from_repos:
                    story.append(Paragraph("<b>IOCs Maliciosos (de Repositórios):</b>", styles['h3']))
                    for url in set(malicious_iocs_from_repos): story.append(Paragraph(f'<a href="https://www.virustotal.com/gui/search/{url}" color="blue">{defang_ioc(url)}</a>', styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
                if malicious_ips_vt:
                    story.append(Paragraph("<b>IPs Maliciosos:</b>", styles['h3']))
                    for ip in malicious_ips_vt: story.append(Paragraph(f'<a href="https://www.virustotal.com/gui/ip-address/{ip}" color="blue">{defang_ioc(ip)}</a>', styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
                if malicious_urls_vt:
                    story.append(Paragraph("<b>URLs Maliciosas:</b>", styles['h3']))
                    for url in malicious_urls_vt:
                        vt_res = self.url_results_dict.get(url, {}); final_url = (vt_res.get('virustotal') or {}).get("meta", {}).get("url_info", {}).get("url", url)
                        url_hash = hashlib.sha256(final_url.encode('utf-8')).hexdigest()
                        story.append(Paragraph(f'<a href="https://www.virustotal.com/gui/url/{url_hash}" color="blue">{defang_ioc(url)}</a>', styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
                if malicious_files_vt:
                    story.append(Paragraph("<b>Arquivos Maliciosos:</b>", styles['h3']))
                    for filename, f_hash in malicious_files_vt: story.append(Paragraph(f'<a href="https://www.virustotal.com/gui/file/{f_hash}" color="blue">{defang_ioc(filename)}</a>', styles['Normal']))
                    story.append(Spacer(1, 0.2*inch))
            
            story.append(Paragraph("<b>Resumo da Análise (IA)</b>", styles['h2'])); story.append(Spacer(1, 0.1*inch))
            summary_text = summary_text.replace('<br>', '<br/>')
            lines = summary_text.split('\n'); i = 0
            while i < len(lines):
                line = lines[i].strip()
                if line.startswith('|') and line.endswith('|'):
                    table_data = []; table_lines = []
                    while i < len(lines) and lines[i].strip().startswith('|'): table_lines.append(lines[i].strip()); i += 1
                    for idx, table_line in enumerate(table_lines):
                        if re.match(r'^[|: -]+$', table_line): continue
                        style = styles['TableCellBold'] if idx == 0 else styles['TableCell']
                        cells = [Paragraph(re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', cell.strip()), style) for cell in table_line.strip('|').split('|')]
                        table_data.append(cells)
                    if table_data:
                        pdf_table = Table(table_data, hAlign='LEFT', repeatRows=1)
                        pdf_table.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), lightgrey), ('TEXTCOLOR',(0,0),(-1,0), black),('ALIGN', (0,0), (-1,-1), 'LEFT'), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),('GRID', (0,0), (-1,-1), 1, black)]))
                        story.append(pdf_table); story.append(Spacer(1,0.2*inch))
                    continue
                if not line.strip(): story.append(Spacer(1, 0.1 * inch))
                else:
                    line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
                    if line.strip().startswith('### '): story.append(Paragraph(line.strip().lstrip('# ').strip(), styles['h3']))
                    elif line.strip().startswith('## '): story.append(Paragraph(line.strip().lstrip('# ').strip(), styles['h2']))
                    elif line.strip().startswith('# '): story.append(Paragraph(line.strip().lstrip('# ').strip(), styles['h1']))
                    elif line.strip().startswith(('-', '•')) or (line.strip().startswith(('1', '2', '3', '4', '5', '6', '7', '8', '9')) and line[1:3] in ('. ', ' ')):
                        cleaned_line = re.sub(r'^[0-9-•.]+\s*', '', line.strip())
                        p_text = f"&nbsp;&nbsp;&nbsp;•&nbsp;{cleaned_line}"
                        story.append(Paragraph(p_text, styles['Normal']))
                    else: story.append(Paragraph(line, styles['Justify']))
                i += 1
            story.append(Spacer(1, 0.2*inch))

            story.append(Paragraph("<b>Relatório Detalhado de Indicadores Analisados</b>", styles['h2']))
            story.append(Spacer(1, 0.1*inch))
            
            other_tables_style = TableStyle([('BACKGROUND', (0,0), (-1,0), navy), ('TEXTCOLOR',(0,0),(-1,0), white), ('ALIGN', (0,0), (-1,-1), 'LEFT'), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'), ('FONTNAME', (0,0), (-1,0), font_name_bold), ('FONTSIZE', (0,0), (-1,0), 9), ('BOTTOMPADDING', (0,0), (-1,0), 10), ('BACKGROUND', (0,1), (-1,-1), whitesmoke), ('GRID', (0,0), (-1,-1), 1, lightgrey), ('ROWBACKGROUNDS', (0,1), (-1,-1), [whitesmoke, (0.9,0.9,0.9)])])

            if self.repo_results_dict:
                story.append(Paragraph("<b>Repositórios Analisados</b>", styles['h3']))
                for res in self.repo_results_dict:
                    secrets_str = "<br/>".join([f"• {s['type']} em {s['file']}" for s in res.get('exposed_secrets', [])]) or "Nenhum"
                    files_str = "<br/>".join([f"• {f}" for f in res.get('suspicious_files', [])]) or "Nenhum"
                    iocs_list = []
                    for ioc_info in res.get('extracted_iocs', []):
                        ioc = ioc_info.get('ioc', 'N/A')
                        rep = ioc_info.get('reputation', {})
                        vt_malicious = rep.get('virustotal', {}).get('data', {}).get('attributes', {}).get('stats', {}).get('malicious', 0)
                        iocs_list.append(f"• {defang_ioc(ioc)} (VT: {vt_malicious})")
                    iocs_str = "<br/>".join(iocs_list) or "Nenhum"

                    repo_table_data = [
                        [Paragraph('<b>URL</b>', styles['TableCellBold']), Paragraph(f'<a href="{res.get("url")}" color="blue">{res.get("url")}</a>', styles['TableCell'])],
                        [Paragraph('<b>Risco Estático</b>', styles['TableCellBold']), Paragraph(f'{res.get("risk_score", 0)}/100', styles['TableCell'])],
                        [Paragraph('<b>Arquivos Suspeitos</b>', styles['TableCellBold']), Paragraph(files_str, styles['TableCell'])],
                        [Paragraph('<b>Segredos Expostos</b>', styles['TableCellBold']), Paragraph(secrets_str, styles['TableCell'])],
                        [Paragraph('<b>IOCs Extraídos</b>', styles['TableCellBold']), Paragraph(iocs_str, styles['TableCell'])]
                    ]
                    
                    repo_table = Table(repo_table_data, colWidths=[1.5*inch, 5.5*inch])
                    repo_table_style = TableStyle([('BACKGROUND', (0,0), (0,-1), navy),('TEXTCOLOR', (0,0), (0,-1), white), ('BACKGROUND', (1,0), (1,-1), whitesmoke),('TEXTCOLOR', (1,0), (1,-1), black), ('GRID', (0,0), (-1,-1), 1, lightgrey),('VALIGN', (0,0), (-1,-1), 'MIDDLE'),('FONTNAME', (0,0), (0,-1), font_name_bold)])
                    repo_table.setStyle(repo_table_style)
                    story.append(repo_table)
                    story.append(Spacer(1, 0.2*inch))

            if self.ip_results_dict:
                story.append(Paragraph("<b>IPs Analisados</b>", styles['h3']))
                ip_table_data = [['IP', 'VT Det.', 'Abuse Score', 'País', 'Provedor']]
                for ip, res in self.ip_results_dict.items():
                    vt_res = res.get('virustotal') or {}; abuse_res = res.get('abuseipdb') or {}
                    vt_mal = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A')
                    abuse_score = abuse_res.get('data', {}).get('abuseConfidenceScore', 'N/A')
                    country = abuse_res.get('data', {}).get('countryCode', 'N/A')
                    owner = vt_res.get('data', {}).get('attributes', {}).get('as_owner', 'N/A')
                    row_text = [Paragraph(f'<a href="https://www.virustotal.com/gui/ip-address/{ip}" color="blue">{defang_ioc(ip)}</a>', styles['TableCell']), Paragraph(str(vt_mal), styles['TableCell']), Paragraph(str(abuse_score), styles['TableCell']), Paragraph(country, styles['TableCell']), Paragraph(owner, styles['TableCell'])]
                    ip_table_data.append(row_text)
                
                ip_table = Table(ip_table_data, colWidths=[1.2*inch, 0.6*inch, 0.8*inch, 0.5*inch, 3*inch])
                ip_table.setStyle(other_tables_style)
                story.append(ip_table)
                story.append(Spacer(1, 0.2*inch))

            if self.url_results_dict:
                story.append(Paragraph("<b>URLs Analisadas</b>", styles['h3']))
                url_table_data = [['URL', 'VT Det.', 'URLHaus']]
                for url, res in self.url_results_dict.items():
                    vt_res = res.get('virustotal') or {}; uh_res = res.get('urlhaus') or {}
                    vt_mal = vt_res.get('data', {}).get('attributes', {}).get('stats', {}).get('malicious', 'N/A')
                    uh_status = uh_res.get('url_status', 'N/A')
                    final_url = vt_res.get("meta", {}).get("url_info", {}).get("url", url); url_hash = hashlib.sha256(final_url.encode('utf-8')).hexdigest()
                    row_text = [Paragraph(f'<a href="https://www.virustotal.com/gui/url/{url_hash}" color="blue">{defang_ioc(url)}</a>', styles['TableCell']), Paragraph(str(vt_mal), styles['TableCell']), Paragraph(uh_status, styles['TableCell'])]
                    url_table_data.append(row_text)

                url_table = Table(url_table_data, colWidths=[5.4*inch, 0.7*inch, 0.9*inch])
                url_table.setStyle(other_tables_style)
                story.append(url_table)
                story.append(Spacer(1, 0.2*inch))

            if self.file_results_dict:
                story.append(Paragraph("<b>Arquivos Analisados</b>", styles['h3']))
                file_table_data = [['Arquivo', 'SHA256', 'VT Det.', 'Ameaça (MB)']]
                for f_hash, res in self.file_results_dict.items():
                    filename = res.get('filename', 'N/A')
                    vt_res = res.get('virustotal') or {}
                    vt_mal = 'N/A'
                    if vt_res.get('error') == 'Not Found': vt_mal = 'Não encontrado'
                    elif vt_res.get('error') == 'Rate Limit': vt_mal = 'Limite Atingido'
                    else: vt_mal = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A')
                    
                    mb_res = res.get('malwarebazaar') or {}
                    threat_name = 'N/A'
                    if mb_res.get('query_status') == 'ok':
                        threat_name = (mb_res.get('data', [{}]) or [{}])[0].get('signature')
                    elif mb_res.get('query_status') == 'hash_not_found':
                        threat_name = 'Não encontrado'
                    elif mb_res.get('error') == 'Rate Limit':
                        threat_name = 'Limite Atingido'
                    
                    row_text = [Paragraph(defang_ioc(filename), styles['TableCell']), Paragraph(f'<a href="https://www.virustotal.com/gui/file/{f_hash}" color="blue">{f_hash[:20]}...</a>', styles['TableCell']), Paragraph(str(vt_mal), styles['TableCell']), Paragraph(threat_name or 'N/A', styles['TableCell'])]
                    file_table_data.append(row_text)
                file_table = Table(file_table_data, colWidths=[2.3*inch, 2.3*inch, 0.7*inch, 1.7*inch])
                file_table.setStyle(other_tables_style)
                story.append(file_table)
                story.append(Spacer(1, 0.2*inch))

            doc.build(story, onFirstPage=self._draw_footer, onLaterPages=self._draw_footer)
        except Exception as e:
            logging.error(f"Falha ao gerar o relatório em PDF: {e}", exc_info=True)
            raise e