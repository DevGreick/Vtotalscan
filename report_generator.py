import xlsxwriter
import hashlib
import re
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.colors import navy, red, black
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from utils import defang_ioc

class ReportGenerator:
    def __init__(self, ip_results_dict, url_results_dict):
        self.ip_results_dict = ip_results_dict
        self.url_results_dict = url_results_dict

    def generate_excel(self, filepath):
        try:
            with xlsxwriter.Workbook(filepath) as workbook:
                header_format = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#004B8B', 'border': 1, 'align': 'center', 'valign': 'vcenter'})
                cell_format = workbook.add_format({'border': 1, 'valign': 'top'})
                wrap_format = workbook.add_format({'border': 1, 'valign': 'top', 'text_wrap': True})
                error_format = workbook.add_format({'font_color': 'red', 'border': 1, 'valign': 'top'})
                hyperlink_format = workbook.add_format({'font_color': 'blue', 'underline': 1, 'border': 1, 'valign': 'top'})
                score_high = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'border': 1, 'valign': 'top'})
                score_med = workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500', 'border': 1, 'valign': 'top'})

                ws_ips = workbook.add_worksheet("Relatório de IPs")
                headers_ip = [
                    "IP", "VT Link", "AbuseIPDB Link", "VT Detecções", 
                    "AbuseIPDB Score", "País (AbuseIPDB)", "Provedor (VT)", "Shodan Portas",
                    "Shodan Organização", "Shodan Hostnames", "Shodan CVEs"
                ]
                ws_ips.write_row('A1', headers_ip, header_format)
                ws_ips.set_column('A:A', 20)
                ws_ips.set_column('B:C', 15)
                ws_ips.set_column('D:F', 15)
                ws_ips.set_column('G:G', 30)
                ws_ips.set_column('H:H', 20)
                ws_ips.set_column('I:K', 35)


                row_num = 1
                for ip, results in self.ip_results_dict.items():
                    row_num += 1
                    ws_ips.write(f'A{row_num}', defang_ioc(ip), cell_format)
                    ws_ips.write_url(f'B{row_num}', f'https://www.virustotal.com/gui/ip-address/{ip}', hyperlink_format, "VT Link")
                    ws_ips.write_url(f'C{row_num}', f'https://www.abuseipdb.com/check/{ip}', hyperlink_format, "AbuseIPDB Link")

                    vt_res = results.get('virustotal')
                    if vt_res and not vt_res.get('error'):
                        attrs = vt_res.get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        ws_ips.write(f'D{row_num}', malicious, score_high if malicious > 0 else cell_format)
                        ws_ips.write(f'G{row_num}', attrs.get('as_owner', 'N/A'), cell_format)
                    else:
                        ws_ips.write(f'D{row_num}', 'Falha', error_format)
                        ws_ips.write(f'G{row_num}', 'N/A', error_format)

                    abuse_res = results.get('abuseipdb')
                    if abuse_res and abuse_res.get('data'):
                        data = abuse_res['data']
                        score = data.get('abuseConfidenceScore', 0)
                        score_format = cell_format
                        if score >= 90: score_format = score_high
                        elif score >= 50: score_format = score_med
                        ws_ips.write(f'E{row_num}', score, score_format)
                        ws_ips.write(f'F{row_num}', data.get('countryCode', 'N/A'), cell_format)
                    else:
                        ws_ips.write_row(f'E{row_num}', ['Falha', 'N/A'], error_format)

                    shodan_res = results.get('shodan')
                    if shodan_res and not shodan_res.get('error'):
                        ports = shodan_res.get('ports', [])
                        ws_ips.write(f'H{row_num}', ", ".join(map(str, ports)), wrap_format)
                        ws_ips.write(f'I{row_num}', shodan_res.get('org', 'N/A'), wrap_format)
                        hostnames = shodan_res.get('hostnames', [])
                        ws_ips.write(f'J{row_num}', ", ".join(defang_ioc(h) for h in hostnames), wrap_format)
                        vulns = shodan_res.get('vulns', [])
                        ws_ips.write(f'K{row_num}', ", ".join(vulns) if vulns else "Nenhuma", wrap_format)
                    elif shodan_res and shodan_res.get('error') == 'Not found':
                        ws_ips.write_row(f'H{row_num}', ['Não encontrado', 'N/A', 'N/A', 'N/A'], cell_format)
                    else:
                        ws_ips.write_row(f'H{row_num}', ['Falha', 'N/A', 'N/A', 'N/A'], error_format)
                
                ws_urls = workbook.add_worksheet("Relatório de URLs")
                headers_url = ["URL", "VT Link", "VT Detecções", "URLHaus Status", "URLHaus Tags"]
                ws_urls.write_row('A1', headers_url, header_format)
                ws_urls.set_column('A:A', 60)
                ws_urls.set_column('B:C', 15)
                ws_urls.set_column('D:E', 25)

                row_num = 1
                for url, results in self.url_results_dict.items():
                    row_num += 1
                    ws_urls.write(f'A{row_num}', defang_ioc(url), wrap_format)
                    vt_res = results.get('virustotal')
                    if vt_res and not vt_res.get('error'):
                        meta_info = vt_res.get("meta", {}).get("url_info", {})
                        final_url_analyzed = meta_info.get("url", url)
                        url_hash = hashlib.sha256(final_url_analyzed.encode('utf-8')).hexdigest()
                        stats = vt_res.get("data", {}).get("attributes", {}).get("stats", {})
                        malicious = stats.get("malicious", 0)
                        ws_urls.write_url(f'B{row_num}', f"https://www.virustotal.com/gui/url/{url_hash}", hyperlink_format, "Link")
                        ws_urls.write(f'C{row_num}', malicious, score_high if malicious > 0 else cell_format)
                    else:
                        ws_urls.write_row(f'B{row_num}', ['Falha', 'N/A'], error_format)

                    uh_res = results.get('urlhaus')
                    if uh_res and uh_res.get('query_status') == 'ok' and uh_res.get('url_status'):
                        info = uh_res.get('url_status', 'not_found')
                        info_format = score_high if info == 'online' else cell_format
                        ws_urls.write(f'D{row_num}', info, info_format)
                        tags = ", ".join(uh_res.get('tags', []))
                        ws_urls.write(f'E{row_num}', tags if tags else "N/A", cell_format)
                    elif uh_res and uh_res.get('query_status') == 'no_results':
                         ws_urls.write_row(f'D{row_num}', ['Não encontrado', 'N/A'], cell_format)
                    else:
                        ws_urls.write_row(f'D{row_num}', ['Falha', 'N/A'], error_format)

        except Exception as e:
            print(f"Falha ao escrever o arquivo XLSX com XlsxWriter: {e}")
            raise e

    def generate_pdf_summary(self, filepath, summary_text):
        try:
            try:
                pdfmetrics.registerFont(TTFont('DejaVuSans', 'DejaVuSans.ttf'))
                pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', 'DejaVuSans-Bold.ttf'))
                pdfmetrics.registerFontFamily('DejaVuSans', normal='DejaVuSans', bold='DejaVuSans-Bold')
                font_name = 'DejaVuSans'
                font_name_bold = 'DejaVuSans-Bold'
            except Exception as e:
                print(f"AVISO: Fontes DejaVu não encontradas. Usando fontes padrão. Erro: {e}")
                font_name = 'Helvetica'
                font_name_bold = 'Helvetica-Bold'

            doc = SimpleDocTemplate(filepath)
            styles = getSampleStyleSheet()
            
            styles.add(ParagraphStyle(name='Justify', fontName=font_name, alignment=TA_JUSTIFY, fontSize=10, leading=12))
            styles.add(ParagraphStyle(name='Center', fontName=font_name, alignment=TA_CENTER))
            styles['h1'].fontName = font_name_bold
            styles['h2'].fontName = font_name_bold
            styles['h3'].fontName = font_name_bold
            styles['Normal'].fontName = font_name
            
            story = []
            
            title = Paragraph("<b>Análise Técnica Resumida – Multi-API</b>", styles['h1'])
            title.alignment = TA_CENTER
            story.append(title)
            story.append(Spacer(1, 0.2*inch))
            
            malicious_urls_vt = [
                url for url, results in self.url_results_dict.items()
                if results.get('virustotal') and not results['virustotal'].get('error')
                and results['virustotal'].get('data',{}).get('attributes',{}).get('stats',{}).get('malicious',0) > 0
            ]
            malicious_ips_vt = [
                ip for ip, results in self.ip_results_dict.items()
                if results.get('virustotal') and not results['virustotal'].get('error')
                and results['virustotal'].get('data',{}).get('attributes',{}).get('last_analysis_stats',{}).get('malicious',0) > 0
            ]
            
            summary_data = [['Item', 'Resultado'], ['Total de IPs analisados', str(len(self.ip_results_dict))], ['Total de URLs analisadas', str(len(self.url_results_dict))], ['IPs maliciosos (VT)', str(len(malicious_ips_vt))], ['URLs maliciosas (VT)', str(len(malicious_urls_vt))]]
            summary_table = Table(summary_data, colWidths=[2.5*inch, 2.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), navy),
                ('TEXTCOLOR',(0,0),(-1,0), (1,1,1)),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('FONTNAME', (0,0), (-1,0), font_name_bold),
                ('BOTTOMPADDING', (0,0), (-1,0), 12),
                ('BACKGROUND', (0,1), (-1,-1), (0.9, 0.9, 0.9)),
                ('GRID', (0,0), (-1,-1), 1, (0.7,0.7,0.7))
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.2*inch))

            if malicious_ips_vt or malicious_urls_vt:
                story.append(Paragraph("<b>Indicadores Maliciosos Encontrados (VirusTotal)</b>", styles['h2']))
                story.append(Spacer(1, 0.1*inch))
                if malicious_ips_vt:
                    story.append(Paragraph("<b>IPs Maliciosos:</b>", styles['h3']))
                    for ip in malicious_ips_vt:
                        link = f'<a href="https://www.virustotal.com/gui/ip-address/{ip}" color="blue">{defang_ioc(ip)}</a>'
                        p = Paragraph(link, styles['Normal'])
                        story.append(p)
                    story.append(Spacer(1, 0.1*inch))
                if malicious_urls_vt:
                    story.append(Paragraph("<b>URLs Maliciosas:</b>", styles['h3']))
                    for url in malicious_urls_vt:
                        vt_res = self.url_results_dict.get(url, {}).get('virustotal')
                        final_url_analyzed = url
                        if vt_res and not vt_res.get('error'):
                            final_url_analyzed = vt_res.get("meta", {}).get("url_info", {}).get("url", url)
                        url_hash = hashlib.sha256(final_url_analyzed.encode('utf-8')).hexdigest()
                        link = f'<a href="https://www.virustotal.com/gui/url/{url_hash}" color="blue">{defang_ioc(url)}</a>'
                        p = Paragraph(link, styles['Normal'])
                        story.append(p)
                    story.append(Spacer(1, 0.2*inch))

            story.append(Paragraph("<b>Resumo da Análise (IA)</b>", styles['h2']))
            story.append(Spacer(1, 0.1*inch))
            
            lines = summary_text.split('\n')
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                
                if line.startswith('|') and line.endswith('|'):
                    table_data = []
                    table_lines = []
                    
                    while i < len(lines) and lines[i].strip().startswith('|'):
                        table_lines.append(lines[i].strip())
                        i += 1
                    
                    for table_line in table_lines:
                        if re.match(r'^[|: -]+$', table_line):
                            continue
                        
                        cells = [cell.strip() for cell in table_line.strip('|').split('|')]
                        
                        parsed_cells = []
                        for cell in cells:
                            cell_text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', cell)
                            p_cell = Paragraph(cell_text, styles['Normal'])
                            parsed_cells.append(p_cell)
                        table_data.append(parsed_cells)
                    
                    if table_data:
                        pdf_table = Table(table_data, hAlign='LEFT')
                        pdf_table.setStyle(TableStyle([
                           ('BACKGROUND', (0,0), (-1,0), navy),
                           ('TEXTCOLOR',(0,0),(-1,0), (1,1,1)),
                           ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                           ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                           ('FONTNAME', (0,0), (-1,0), font_name_bold),
                           ('BOTTOMPADDING', (0,0), (-1,0), 12),
                           ('BACKGROUND', (0,1), (-1,-1), (0.9,0.9,0.9)),
                           ('GRID', (0,0), (-1,-1), 1, black),
                        ]))
                        story.append(pdf_table)
                        story.append(Spacer(1, 0.2*inch))
                    continue
                
                if not line.strip():
                    story.append(Spacer(1, 0.1 * inch))
                else:
                    line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
                    
                    if line.strip().startswith('### '):
                        p = Paragraph(line.strip().lstrip('# ').strip(), styles['h3'])
                        story.append(p)
                    elif line.strip().startswith('## '):
                        p = Paragraph(line.strip().lstrip('# ').strip(), styles['h2'])
                        story.append(p)
                    elif line.strip().startswith('# '):
                        p = Paragraph(line.strip().lstrip('# ').strip(), styles['h1'])
                        story.append(p)
                    elif line.strip().startswith('- '):
                        p_text = f"&nbsp;&nbsp;&nbsp;•&nbsp;{line.strip().lstrip('- ').strip()}"
                        p = Paragraph(p_text, styles['Normal'])
                        story.append(p)
                    else:
                        p = Paragraph(line, styles['Justify'])
                        story.append(p)
                
                i += 1

            doc.build(story)
        except Exception as e:
            print(f"Falha ao gerar o relatório em PDF: {e}")
            raise e