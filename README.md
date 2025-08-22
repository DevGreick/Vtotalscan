<div align="center">
  <img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/spy2-1.png" alt="Logo do ThreatSpy" width="150"/>
  <h1 align="center">🔎 ThreatSpy</h1>
</div>

<div align="center">
  <strong>Uma ferramenta de análise de ameaças que automatiza a consulta de IOCs e repositórios em múltiplas fontes, gera relatórios e cria resumos com IA local.</strong>
  
</div>

<br>

<div align="center">
  <!-- Badges -->
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/status-active-success.svg" alt="Project Status">
  <img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI Framework">
  <img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions Welcome">
</div>

<br>

<div align="center">
  <a href="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/ThreatsSy.png">
    <img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/ThreatsSy.png" alt="Screenshot da interface do ThreatSpy" width="700"/>
  </a>
</div>

> [!TIP]
> Abra o Sumário abaixo para navegar rápido.

<details>
<summary><strong>Sumário</strong> <sub>(clique para expandir)</sub></summary>
<br/>

- [Comece a Usar em 30 Segundos](#comece)
- [Instalação](#instalacao)
  - [Windows](#windows)
  - [macOS](#macos)
  - [Linux](#linux)
  - [A partir do Código-Fonte](#codigo-fonte)
- [Configuração Essencial](#configuracao)
- [Como Usar](#como-usar)
- [Funcionalidades Principais](#funcionalidades)
- [Tecnologias Utilizadas](#tecnologias)
- [Contribuição](#contribuicao)
- [Apoie o Projeto](#apoie)
- [Licença](#licenca)

</details>

<a id="comece"></a>
## ⚡ Comece a Usar em 30 Segundos

A maneira mais rápida de começar é baixando a versão mais recente para o seu sistema operacional.

1. Baixe o executável na página de **[Releases](https://github.com/DevGreick/ThreatSpy/releases)**.
2. Descompacte e execute o arquivo.
3. Na primeira vez, vá em **Configurações** e adicione sua chave de API do **VirusTotal**. É a única obrigatória.

<a id="instalacao"></a>
## 📦 Instalação

<a id="windows"></a>
### Windows

1. Acesse a página de Releases.
2. Baixe o arquivo `.zip` para Windows.
3. Descompacte em uma pasta.
4. Execute `ThreatSpy.exe`.

<a id="macos"></a>
### macOS

1. Acesse a página de Releases.
2. Baixe o arquivo `.zip` para macOS.
3. Descompacte e abra `ThreatSpy.app`.
4. Se o macOS avisar sobre segurança, clique com o botão direito em **Abrir** e confirme.

<a id="linux"></a>
### Linux

1. Acesse a página de Releases.
2. Baixe o `.zip` para Linux e extraia.
3. Torne o binário executável e rode:
   ```bash
   chmod +x ./ThreatSpy
   ./ThreatSpy
   ```

<a id="codigo-fonte"></a>
### A partir do Código-Fonte

Pré-requisitos: Python 3.8+ e Git. Para IA, o **Ollama** deve estar instalado e rodando.

```bash
# Clone o repositório
git clone https://github.com/DevGreick/ThreatSpy.git
cd ThreatSpy

# Crie e ative um ambiente virtual
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

# Instale as dependências
pip install -r requirements.txt

# Execute o programa
python main_gui.py
```

<a id="configuracao"></a>
## ⚙️ Configuração Essencial

Após instalar, clique em **Configurações** no canto superior direito e adicione as chaves.

- **Chave principal (essencial)**: **VirusTotal**. Necessária para análise de IPs, URLs e arquivos.
- **Chaves opcionais (recomendadas)**:
  - **AbuseIPDB**. Score de abuso e localização de IPs.
  - **Shodan**. Portas, serviços e possíveis CVEs.
  - **URLHaus**. URLs ativamente maliciosas.
  - **MalwareBazaar**. Identificação de malware por hash.
  - **GitHub/GitLab**. Essenciais para análise de repositórios sem bloqueios de API.
  - **Ollama**. Resumos por IA local (endpoint padrão já configurado).
- As chaves são salvas via **keyring** do sistema.

<a id="como-usar"></a>
## 🛠️ Como Usar

A ferramenta possui dois fluxos de análise principais.

| Tipo de Análise        | Como Fazer |
|------------------------|------------|
| IPs e URLs             | Na aba **Análise de IOCs**, cole os indicadores e clique em **Analisar Alvos**. |
| Arquivos               | Em **Análise de IOCs**, clique em **Verificar Reputação de Arquivos** e selecione um ou mais arquivos. |
| Repositórios           | Na aba **Análise de Repositório**, cole as URLs do GitHub/GitLab e clique em **Analisar Repositórios**. |
| Relatórios e Resumos   | Após a análise, use **Resumo Gerado por IA** para exportar texto ou PDF. |

<a id="funcionalidades"></a>
## ✨ Funcionalidades Principais

- Análise paralela de indicadores.
- Análise remota de repositórios: segredos, arquivos sensíveis, IOCs em Base64 e scripts maliciosos.
- GUI em **PySide6** com tema escuro e abas.
- Relatórios em **Excel (.xlsx)** e **PDF**, com *defang* automático.
- Resumos com IA local via **Ollama**.
- Chaves salvas com **keyring**. Retentativas e logs para lidar com limites de API.

<a id="tecnologias"></a>
## 🛠️ Tecnologias Utilizadas

| Tecnologia              | Propósito                            |
|-------------------------|--------------------------------------|
| Python                  | Linguagem principal do projeto       |
| PySide6 (Qt)            | Interface gráfica multiplataforma    |
| Ollama                  | Execução de modelos de IA locais     |
| Requests                | Comunicação com APIs de TI           |
| Keyring                 | Armazenamento seguro de chaves       |
| XlsxWriter / ReportLab  | Relatórios em Excel e PDF            |
| PyInstaller             | Empacotamento em executáveis         |

<a id="contribuicao"></a>
## 🤝 Contribuição

Projeto aberto a contribuições. Encontrou um bug, tem ideia ou quer enviar uma feature? Abra uma **Issue** ou **Pull Request**.

<a id="apoie"></a>
## ☕ Apoie o Projeto

<div align="center">
  <a href="https://buymeacoffee.com/devgreick" target="_blank">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
  </a>
</div>

<a id="licenca"></a>
## 📜 Licença

Distribuído sob a licença **MIT**. Veja o arquivo `LICENSE` para mais informações.
