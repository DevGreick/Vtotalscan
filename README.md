<div align="center">
<img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/spy2-1.png" alt="Logo do ThreatSpy" width="150"/>
<h1 align="center">🔎 ThreatSpy</h1>
</div>

<div align="center">
<strong>Uma ferramenta de análise de ameaças que automatiza a consulta de IOCs e repositórios em múltiplas fontes, gera relatórios e cria resumos com IA local.</strong>
</div>

<br>

<div align="center">
⭐ Dê uma estrela se o projeto te ajudou! | <a href="https://github.com/DevGreick/ThreatSpy/releases"><strong>Baixar a Última Versão »</strong></a>
</div>

<br>

<div align="center">
<!-- Badges Clicáveis -->
<a href="https://www.python.org/downloads/release/python-380/"><img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python Version"></a>
<a href="https://github.com/DevGreick/ThreatSpy/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
<img src="https://img.shields.io/badge/status-active-success.svg" alt="Project Status">
<a href="https://doc.qt.io/qtforpython/"><img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI Framework"></a>
<a href="https://www.google.com/search?q=%23-contribui%C3%A7%C3%A3o"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions Welcome"></a>
</div>

<br>

  
<div align="center">
<img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/ThreatsSy.png" alt="Screenshot da interface do ThreatSpy" width="700"/>
</div>

## Requisitos

- **Python 3.8+** instalado no sistema. Baixe em: https://www.python.org/downloads/
- **Ollama** instalado (opcional) para usar os resumos por IA local. Baixe em: https://ollama.com/
- **Chaves de API** dos serviços que você pretende usar:
  - VirusTotal (essencial)
  - AbuseIPDB
  - URLHaus
  - Shodan
  - MalwareBazaar
  - Github (recomendado)
  - Gitlab (recomendado)
- **Fonts DejaVu** (opcional, recomendadas para PDF): `DejaVuSans.ttf` e `DejaVuSans-Bold.ttf` na pasta do projeto.
> [!TIP]
> Abra o Sumário abaixo para navegar rápido.

<details>
<summary><strong>Sumário</strong> <sub>(clique para expandir)</sub></summary>
<br/>

- [Comece a Usar em 30 Segundos](#start)
- [Instalação](#instalacao)
- [Configuração Essencial](#config)
- [Como Usar (Exemplos Práticos)](#uso)
- [Funcionalidades Principais](#features)
- [Uso Responsável e Limites](#responsavel)
- [Tecnologias Utilizadas](#tech)
- [Contribuição](#contribuicao)
- [Apoie o Projeto](#apoie)
- [Licença](#licenca)

</details>

<a id="start"></a>
## ⚡ Comece a Usar em 30 Segundos

### Windows
1. Acesse a página de <a href="https://github.com/DevGreick/ThreatSpy/releases"><strong> **Releases**</strong></a>
2. Baixe o arquivo `ThreatSpyWindows.zip`.
3. Descompacte o arquivo e execute `ThreatSpy.exe`.

### macOS
1. Acesse a página de <a href="https://github.com/DevGreick/ThreatSpy/releases"><strong> **Releases**</strong></a>
2. Baixe o arquivo `ThreatSpy.app.zip`.
3. Descompacte e execute o `ThreatSpy.app`.
4. **Nota**: o macOS pode exibir um aviso de segurança. Se isso ocorrer, clique com o botão direito, selecione **Abrir** e confirme na caixa de diálogo para permitir a execução.

### Linux
1. Acesse a página de <a href="https://github.com/DevGreick/ThreatSpy/releases"><strong> **Releases**</strong></a>
2. Baixe o arquivo `ThreatSpyLinux.zip`.
3. Descompacte e, no terminal, torne o arquivo executável:
```bash
chmod +x ThreatSpy
```
4. Execute o programa:
```bash
./ThreatSpy
```

<a id="instalacao-codigo"></a>
### A partir do Código-Fonte
Pré-requisitos: Python 3.8+ e Git. Para a função de IA, o **Ollama** deve estar instalado e rodando.

<a id="instalacao-codigo"></a>
### A partir do Código-Fonte
Pré-requisitos: Python 3.8+ e Git. Para a função de IA, o **Ollama** deve estar instalado e rodando.

```bash
# Clone o repositório
git clone https://github.com/DevGreick/ThreatSpy.git
cd ThreatSpy

# Crie e ative um ambiente virtual
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

# Instale as dependências
pip install -r requirements.txt

# (Opcional) Configure o Ollama para IA local
ollama pull llama3
ollama run llama3 "Hello ThreatSpy"

# Execute o programa
python main_gui.py

```




<a id="config"></a>
## Configuração Essencial

Após instalar, a etapa mais importante é configurar as chaves de API. **Apenas a chave do VirusTotal é obrigatória.**

| Serviço        | Necessidade | O que habilita?                                   |
| :------------- | :---------- | :------------------------------------------------ |
| VirusTotal     | Obrigatória | Análise de reputação de IPs, URLs e Arquivos.    |
| GitHub/GitLab  | Recomendada | Análise de Repositórios, evita bloqueios de API. |
| AbuseIPDB      | Opcional    | Score de abuso de IPs.                            |
| Shodan         | Opcional    | Portas e serviços para IPs.                       |
| URLHaus        | Opcional    | Verifica distribuição ativa de malware em URLs.   |
| MalwareBazaar  | Opcional    | Nome da ameaça por hash de arquivo.               |
| Ollama (IA)    | Opcional    | Resumos automáticos com IA local.                 |

**Onde as chaves são salvas?**  

O ThreatSpy usa a biblioteca `keyring`, que armazena as chaves no cofre de credenciais nativo:

- Windows: Gerenciador de Credenciais do Windows  
- macOS: Keychain  
- Linux: Secret Service API / KWallet  

<a id="uso"></a>
## 🛠️ Como Usar (Exemplos Práticos)

### Exemplo 1: Analisando IOCs
1. Abra a aba **Análise de IOCs**.
2. Cole os seguintes indicadores:
```
185.172.128.150
https://some-random-domain.net/path
8.8.8.8
```
3. Clique em **Analisar Alvos**. O ThreatSpy consulta as APIs em paralelo e gera um relatório em Excel com os resultados.

### Exemplo 2: Analisando um Repositório Suspeito
1. Abra a aba **Análise de Repositório**.
2. Cole a URL do repositório de teste:
```
https://github.com/DevGreick/threatspy-test-env
```
3. Clique em **Analisar Repositórios**. A ferramenta detecta segredos expostos, IOC em Base64 no `.env` e gera relatório de risco sem clonar.

<a id="features"></a>
## Funcionalidades Principais

- Análise massivamente paralela de indicadores.  
- Análise de repositórios GitHub e GitLab sem clonar, buscando segredos, arquivos sensíveis, IOCs em Base64 e scripts maliciosos.  
- Interface gráfica moderna em PySide6 com tema escuro e abas.  
- Relatórios em Excel (.xlsx) e PDF.  
- Resumos com IA contextual via Ollama.  
- Gestão segura de chaves por `keyring`.

<a id="responsavel"></a>
## ⚖️ Use com Responsabilidade

- A ferramenta deve ser utilizada apenas para fins educacionais e de pesquisa em segurança.  
- Siga sempre os Termos de Serviço das APIs utilizadas.  
- Nunca analise dados ou sistemas de terceiros sem autorização explícita.  


<a id="tech"></a>
## Tecnologias Utilizadas

| Tecnologia          | Propósito                                  |
| ------------------- | ------------------------------------------ |
| Python              | Linguagem principal do projeto             |
| PySide6 (Qt)        | Interface gráfica multiplataforma          |
| Ollama              | Execução de modelos de IA locais           |
| Requests            | Comunicação com APIs de Threat Intelligence|
| Keyring             | Armazenamento seguro das chaves de API     |
| XlsxWriter/ReportLab| Geração de relatórios em Excel e PDF       |
| PyInstaller         | Empacotamento em executáveis               |

<a id="contribuicao"></a>
## 🤝 Contribuição

Contribuições são muito bem-vindas.

1. Faça um **fork** do projeto.  
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`).  
3. Commit das alterações (`git commit -m 'Adiciona nova feature'`).  
4. Push para a branch (`git push origin feature/nova-feature`).  
5. Abra um **Pull Request**.

<a id="apoie"></a>
## ☕ Apoie o Projeto

Se você achou esta ferramenta útil, considere apoiar meu trabalho. Isso ajuda a manter o projeto ativo e a desenvolver novas funcionalidades.

<div align="center">
<a href="https://buymeacoffee.com/devgreick" target="_blank">
<img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
</a>
</div>

<a id="licenca"></a>
## 📜 Licença

Distribuído sob a licença **MIT**. Veja o arquivo `LICENSE` para mais informações.
