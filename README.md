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

- [Sobre o Projeto](#sobre)
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

<a id="sobre"></a>
## Sobre o Projeto

O projeto começou como um script simples para um colega e evoluiu para esta suíte de análise completa. A ferramenta automatiza consultas a múltiplas fontes (VirusTotal, AbuseIPDB, Shodan, etc.), gera relatórios detalhados em Excel e PDF, e utiliza um modelo de IA local (via Ollama) para criar resumos executivos das análises.

<a id="comece"></a>
## Comece a Usar em 30 Segundos

A maneira mais rápida de começar é baixando a versão mais recente para o seu sistema operacional.

1. Baixe o executável na página de **[Releases](https://github.com/DevGreick/ThreatSpy/releases)**.
2. Descompacte e execute o arquivo.
3. Na primeira vez, vá em **Configurações** e adicione sua chave de API do **VirusTotal** (é a única obrigatória).

<a id="instalacao"></a>
## Instalação

<a id="windows"></a>
### Windows

1. Acesse a página de Releases.
2. Baixe o arquivo `.zip` da versão mais recente para Windows.
3. Descompacte o arquivo em uma pasta de sua preferência.
4. Execute `ThreatSpy.exe`.

<a id="macos"></a>
### macOS

1. Acesse a página de Releases.
2. Baixe o arquivo `.zip` da versão para macOS.
3. Descompacte e execute `ThreatSpy.app`.
4. Nota: o macOS pode exibir um aviso de segurança. Se isso ocorrer, clique com o botão direito, selecione **Abrir** e confirme.

<a id="linux"></a>
### Linux

1. Acesse a página de Releases.
2. Baixe o arquivo `.zip` da versão para Linux.
3. Descompacte e torne o binário executável:
   ```bash
   chmod +x ./ThreatSpy
   ```
4. Execute o programa:
   ```bash
   ./ThreatSpy
   ```

<a id="codigo-fonte"></a>
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

# Execute o programa
python main_gui.py
```

<a id="configuracao"></a>
## Configuração Essencial

Após instalar, a etapa mais importante é configurar as chaves de API. Clique no botão **Configurações** no canto superior direito.

- **Chave principal (essencial)**: **VirusTotal**. Obrigatória para análise de IPs, URLs e arquivos.
- **Chaves opcionais (recomendadas)**:
  - **AbuseIPDB**: score de abuso e localização de IPs.
  - **Shodan**: portas, serviços e possíveis CVEs.
  - **URLHaus**: verificação de URLs ativamente maliciosas.
  - **MalwareBazaar**: identificação de famílias de malware por hash.
  - **GitHub/GitLab**: análise de repositórios sem bloqueios de API.
  - **Ollama**: resumos com IA local (endpoint padrão já configurado).
- As chaves são salvas com **keyring** do sistema.

<a id="como-usar"></a>
## Como Usar

A ferramenta possui dois fluxos de análise principais.

| Tipo de Análise        | Como Fazer |
|------------------------|------------|
| IPs e URLs             | Na aba **Análise de IOCs**, cole os indicadores na caixa de texto e clique em **Analisar Alvos**. |
| Arquivos               | Em **Análise de IOCs**, clique em **Verificar Reputação de Arquivos** e selecione um ou mais arquivos. |
| Repositórios           | Vá para a aba **Análise de Repositório**, cole as URLs do GitHub/GitLab e clique em **Analisar Repositórios**. |
| Relatórios e Resumos   | Após a análise, use **Resumo Gerado por IA** para exportar texto ou PDF. |

<a id="funcionalidades"></a>
## Funcionalidades Principais

- Análise massivamente paralela de indicadores.
- Análise remota de repositórios: segredos, arquivos sensíveis, IOCs em Base64 e scripts maliciosos.
- Interface gráfica moderna em **PySide6** com tema escuro e abas.
- Relatórios em **Excel** (.xlsx) e **PDF**, com *defang* automático.
- Resumos com IA local via **Ollama**.
- Gestão segura de chaves com **keyring** e retentativas para lidar com limites de API.

<a id="tecnologias"></a>
## Tecnologias Utilizadas

| Tecnologia              | Propósito                            |
|-------------------------|--------------------------------------|
| Python                  | Linguagem principal do projeto       |
| PySide6 (Qt)            | Interface gráfica multiplataforma    |
| Ollama                  | Execução de modelos de IA locais     |
| Requests                | Comunicação com APIs de TI           |
| Keyring                 | Armazenamento seguro das chaves      |
| XlsxWriter / ReportLab  | Geração de relatórios em Excel e PDF |
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
