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

---
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

---

<a id="start"></a>
### ⚡ Comece a Usar em 30 Segundos

Comece baixando o pacote portátil para o seu sistema.

1. **<a href="https://github.com/DevGreick/ThreatSpy/releases">Baixe o arquivo `.zip` na página de Releases</a>**.
2. Descompacte em uma pasta de sua preferência e execute o arquivo `ThreatSpy`.
3. Na primeira execução, abra **Configurações** e adicione sua chave de API do **VirusTotal**. É a única obrigatória.

---

<a id="instalacao"></a>
### 📦 Instalação

#### Windows
1. Acesse a página de **Releases**.
2. Baixe o arquivo `ThreatSpy-Windows.zip`.
3. Descompacte o arquivo e execute `ThreatSpy.exe`.

#### macOS
1. Acesse a página de **Releases**.
2. Baixe o arquivo `ThreatSpy-macOS.zip`.
3. Descompacte e execute `ThreatSpy.app`.
4. **Nota**: o macOS pode exibir um aviso de segurança. Se ocorrer, clique com o botão direito, selecione **Abrir** e confirme.

#### Linux
1. Acesse a página de **Releases**.
2. Baixe o arquivo `ThreatSpy-Linux.zip`.
3. Descompacte e, no terminal, torne o arquivo executável:
    ```bash
    chmod +x ThreatSpy
    ```
4. Execute o programa:
    ```bash
    ./ThreatSpy
    ```

---

<a id="config"></a>
### ⚙️ Configuração Essencial

Após instalar, configure as chaves de API. **Apenas a chave do VirusTotal é obrigatória.**

| Serviço            | Necessidade   | O que habilita?                                         |
| :----------------- | :------------ | :------------------------------------------------------ |
| **VirusTotal**     | Obrigatória   | Análise de reputação de IPs, URLs e arquivos.           |
| **GitHub/GitLab**  | Recomendada   | Análise de repositórios e prevenção de rate limit.      |
| **AbuseIPDB**      | Opcional      | Score de abuso e dados de reputação de IPs.             |
| **Shodan**         | Opcional      | Portas e serviços expostos para IPs.                    |
| **URLHaus**        | Opcional      | Presença em listas de distribuição ativa de malware.    |
| **MalwareBazaar**  | Opcional      | Identificação de famílias de malware por hash.          |
| **Ollama (IA)**    | Opcional      | Geração de resumos locais com IA.                       |

#### Onde as chaves são salvas?

O ThreatSpy usa `keyring`, que armazena as chaves no cofre de credenciais nativo do sistema operacional:

- **Windows**: Gerenciador de Credenciais do Windows  
- **macOS**: Keychain  
- **Linux**: Secret Service API / KWallet  

---

<a id="uso"></a>
### 🛠️ Como Usar (Exemplos Práticos)

#### Exemplo 1: Analisando IOCs

1. Abra a aba **Análise de IOCs**.  
2. Cole alguns indicadores, por exemplo:
    ```
    185.172.128.150
    https://example.com/path
    8.8.8.8
    ```
3. Clique em **Analisar Alvos**. O ThreatSpy consulta as APIs em paralelo e gera um relatório em Excel com os resultados.

#### Exemplo 2: Analisando um Repositório

1. Abra a aba **Análise de Repositório**.  
2. Cole a URL do repositório alvo, por exemplo:
    ```
    https://github.com/owner/repo
    ```
3. Clique em **Analisar Repositórios**. A ferramenta inspeciona segredos expostos, arquivos sensíveis e IOCs em Base64 sem clonar o projeto.

---

<a id="features"></a>
### ✨ Funcionalidades Principais

- **Análise paralela de indicadores** com consultas simultâneas.  
- **Inspeção remota de repositórios** GitHub e GitLab, incluindo segredos, arquivos sensíveis, IOCs em Base64 e scripts maliciosos.  
- **Interface gráfica em PySide6** com tema escuro e organização em abas.  
- **Relatórios em Excel (`.xlsx`) e PDF**, com defang automático.  
- **Resumos com IA local via Ollama** para texto executivo.  
- **Armazenamento seguro de chaves** com `keyring` e retentativas para contornar limites de API.

---

<a id="responsavel"></a>
### ⚖️ Uso Responsável e Limites

- Destinado a fins educacionais e de análise de segurança.  
- Respeite os Termos de Serviço das APIs utilizadas.  
- Não analise dados ou sistemas de terceiros sem autorização explícita.

---

<a id="tech"></a>
### 🛠️ Tecnologias Utilizadas

| Tecnologia              | Propósito                                   |
| ----------------------- | ------------------------------------------- |
| **Python**              | Linguagem do projeto                        |
| **PySide6 (Qt)**        | Interface gráfica multiplataforma           |
| **Ollama**              | Execução de modelos de IA locais            |
| **Requests**            | Comunicação com APIs de Threat Intelligence |
| **Keyring**             | Armazenamento seguro de chaves de API       |
| **XlsxWriter/ReportLab**| Geração de relatórios em Excel e PDF        |
| **PyInstaller**         | Empacotamento em executáveis                |

---

<a id="contribuicao"></a>
### 🤝 Contribuição

Contribuições são bem-vindas.

1. Faça um **fork** do projeto.  
2. Crie uma branch (`git checkout -b feature/nova-feature`).  
3. Commit das alterações (`git commit -m 'Adiciona nova feature'`).  
4. Push para a branch (`git push origin feature/nova-feature`).  
5. Abra um **Pull Request**.

---

<a id="apoie"></a>
### ☕ Apoie o Projeto

Se você achou esta ferramenta útil, considere apoiar meu trabalho. Isso ajuda a manter o projeto ativo e a desenvolver novas funcionalidades.

<div align="center">
<a href="https://buymeacoffee.com/devgreick" target="_blank">
<img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
</a>
</div>

---

<a id="licenca"></a>
### 📜 Licença

Distribuído sob a licença **MIT**. Veja o arquivo `LICENSE`.
