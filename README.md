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
  <a href="#contribuicao"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions Welcome"></a>
</div>

<br>

<div align="center">
  <img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/ThreatsSy.png" alt="Screenshot da interface do ThreatSpy" width="700"/>
</div>

<a id="requisitos"></a>
## ✅ Requisitos

- **Executável**. não precisa de Python.
- **Código‑fonte**. Python 3.8+ e Git.
- **Chave do VirusTotal**. obrigatória para análises de IPs, URLs e arquivos.

### Para usar a IA local (opcional, para qualquer usuário)
- **Ollama instalado e em execução**  
  Windows: https://ollama.com  
  macOS: `brew install --cask ollama`  
  Linux: `curl -fsSL https://ollama.com/install.sh | sh`
- Teste rápido:
  ```bash
  ollama --version
  ollama list || curl -s http://localhost:11434/api/tags
  ollama pull llama3
  ```
- Sem Ollama, os botões de resumo por IA ficam indisponíveis. As demais funções seguem ativas.

> [!TIP]
> Abra o Sumário abaixo para navegar rápido.

<details>
<summary><strong>Sumário</strong> <sub>(clique para expandir)</sub></summary>
<br/>

- [Comece a Usar em 30 Segundos](#start)
- [Instalação pelo Código‑Fonte](#instalacao)
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

> 1) Quer usar **IA local**? Instale e rode o **Ollama** (veja Requisitos).  
> 2) Baixe a versão do seu sistema em **Releases**.  
> 3) Abra o ThreatSpy e adicione a **chave do VirusTotal**.

### Windows
1. Acesse **<a href="https://github.com/DevGreick/ThreatSpy/releases"><strong>Releases</strong></a>**.
2. Baixe `ThreatSpyWindows.zip`.
3. Descompacte e execute `ThreatSpy.exe`.

### macOS
1. Acesse **<a href="https://github.com/DevGreick/ThreatSpy/releases"><strong>Releases</strong></a>**.
2. Baixe `ThreatSpy.app.zip`.
3. Descompacte e abra `ThreatSpy.app`.
4. Se houver aviso de segurança, clique com o botão direito em **Abrir** e confirme.

### Linux
1. Acesse **<a href="https://github.com/DevGreick/ThreatSpy/releases"><strong>Releases</strong></a>**.
2. Baixe `ThreatSpyLinux.zip`.
3. Descompacte e torne executável:
   ```bash
   chmod +x ThreatSpy
   ```
4. Execute:
   ```bash
   ./ThreatSpy
   ```

<a id="instalacao"></a>
## 📦 Instalação pelo Código‑Fonte

Pré‑requisitos: Python 3.8+ e Git. Para IA local, instale e rode o **Ollama**.

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
## ⚙️ Configuração Essencial

Apenas a chave do **VirusTotal** é obrigatória, mas as opcionais enriquecem enormemente a análise, adicionando mais contexto e fontes de dados aos seus relatórios.

| Serviço        | Necessidade | O que habilita?                                   |
| :------------- | :---------- | :------------------------------------------------ |
| VirusTotal     | Obrigatória | Análise de reputação de IPs, URLs e arquivos.     |
| GitHub/GitLab  | Recomendada | Análise de repositórios, evita bloqueios de API.  |
| AbuseIPDB      | Opcional    | Score de abuso de IPs.                            |
| Shodan         | Opcional    | Portas e serviços para IPs.                       |
| URLHaus        | Opcional    | Verifica distribuição ativa de malware em URLs.   |
| MalwareBazaar  | Opcional    | Nome da ameaça por hash.                          |
| Ollama (IA)    | Opcional    | Resumos automáticos com IA local.                 |

**Onde as chaves são salvas?** O ThreatSpy usa `keyring` e armazena no cofre nativo do sistema:  
Windows. Gerenciador de Credenciais • macOS. Keychain • Linux. Secret Service API / KWallet

<a id="uso"></a>
## 🛠️ Como Usar (Exemplos Práticos)

### Exemplo 1. Analisando IOCs
1. Abra **Análise de IOCs**.
2. Cole indicadores, um por linha:
```
185.172.128.150
https://some-random-domain.net/path
8.8.8.8
```
3. Clique em **Analisar Alvos**. O app consulta APIs em paralelo e gera Excel com resultados.

### Exemplo 2. Analisando um repositório suspeito
1. Abra **Análise de Repositório**.
2. Cole a URL de teste:
```
https://github.com/DevGreick/threatspy-test-env
```
3. Clique em **Analisar Repositórios**. A ferramenta detecta segredos e IOCs Base64 e gera relatório sem clonar.

<a id="features"></a>
## ✨ Funcionalidades Principais

- Análise massivamente paralela de indicadores
- Análise de repositórios GitHub e GitLab sem clonar
- GUI moderna em PySide6 com tema escuro e abas
- Relatórios em Excel (.xlsx) e PDF
- Resumos com IA contextual via Ollama
- Gestão segura de chaves por `keyring`

<a id="responsavel"></a>
## ⚖️ Use com responsabilidade

- Use apenas com autorização e para fins educacionais e de pesquisa
- Siga os termos de uso das APIs
- Não analise dados de terceiros sem permissão explícita

## ⚠️ Aviso de Segurança e Privacidade

Esta é uma ferramenta poderosa de verificação de segurança, para funcionar, ela precisa se comunicar com serviços de terceiros para analisar os indicadores que você fornece,  esteja ciente de que:

* **URLs e IPs**: Todos os IPs e URLs fornecidos como entrada, **incluindo URLs extraídas automaticamente do conteúdo de repositórios (após decodificação de Base64)**, são enviados para serviços externos como VirusTotal, AbuseIPDB, URLhaus e Shodan.
* **Cuidado com Dados Sensíveis:**: Se você analisar repositórios privados ou dados que contenham informações confidenciais (como URLs de infraestrutura interna da sua empresa), essas informações serão enviadas para as APIs mencionadas. 
* **Endpoint de IA**: A funcionalidade de resumo por IA envia um dossiê detalhado da análise (contendo todos os resultados) para o endpoint configurado. O padrão é um serviço Ollama local (`http://localhost:11434`), mas se você o alterar para um serviço remoto, os dados da análise sairão da sua máquina.

**Use por sua conta e risco.** O mantenedor não se responsabiliza por qualquer vazamento de dados decorrente do uso desta ferramenta.

<a id="tech"></a>
## 🛠️ Tecnologias Utilizadas

| Tecnologia             | Propósito                           |
|------------------------|-------------------------------------|
| Python                 | Linguagem principal                 |
| PySide6 (Qt)           | Interface gráfica                   |
| Ollama                 | IA local                            |
| Requests               | Comunicação com APIs de TI          |
| Keyring                | Cofre de credenciais do sistema     |
| XlsxWriter / ReportLab | Relatórios Excel e PDF              |
| PyInstaller            | Empacotamento em executáveis        |

<a id="contribuicao"></a>
## 🤝 Contribuição

1. Faça um **fork**.  
2. Crie a branch `feature/nova-feature`.  
3. Commit: `git commit -m "Adiciona nova feature"`  
4. Push: `git push origin feature/nova-feature`  
5. Abra um **Pull Request**.

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
