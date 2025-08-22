<div align="center">

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![GUI](https://img.shields.io/badge/GUI-PySide6-purple.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

</div>
<h1 align="center">🔎 ThreatSpy</h1>

<p align="center">
  <img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/spy2-1.png" alt="Logo do ThreatSpy" width="150">
</p>


Uma ferramenta de análise e inteligência de ameaças (Threat Intelligence) que automatiza a consulta de IPs, URLs e arquivos em múltiplas fontes, gera relatórios profissionais e cria resumos com IA local.

> [!TIP]
> Abra o Sumário abaixo para navegar rapidamente pelo documento.

<details>
<summary><strong>Sumário</strong> <sub>(clique para expandir)</sub></summary>
<br/>

<a href="#sobre-o-projeto">Sobre o Projeto</a><br/>
<a href="#caso-real--o-golpe-do-repositório-falso">Caso Real – O Golpe do Repositório Falso</a><br/>
<a href="#funcionalidades-principais">Funcionalidades Principais</a><br/>
<a href="#tecnologias-utilizadas">Tecnologias Utilizadas</a><br/>
<a href="#screenshot-da-ferramenta">Screenshot da Ferramenta</a><br/>
<a href="#download-e-instalacao">Download e Instalação</a><br/>
<a href="#para-usuários-windows">Para Usuários (Windows)</a><br/>
<a href="#para-usuários-macos">Para Usuários (macOS)</a><br/>
<a href="#para-usuários-linux">Para Usuários (Linux)</a><br/>
<a href="#para-desenvolvedores">Para Desenvolvedores (a partir do Código-Fonte)</a><br/>
<a href="#configuracao-essencial">Configuração Essencial</a><br/>
<a href="#como-usar">Como Usar</a><br/>
<a href="#roadmap-futuro">Roadmap Futuro</a><br/>
<a href="#contribuicao">Contribuição</a><br/>
<a href="#apoie-o-projeto">Apoie o Projeto</a><br/>
<a href="#licenca">Licença</a>

</details>

<a id="sobre-o-projeto"></a>

## 🧩 Sobre o Projeto

ThreatSpy é uma ferramenta de Threat Intelligence com interface gráfica, desenvolvida para simplificar a análise de indicadores de ameaça. Com ela, você pode investigar IPs, URLs, arquivos e repositórios de código suspeitos de forma rápida e segura.

O projeto começou como um script simples para um colega e evoluiu para esta suíte de análise completa. A ferramenta automatiza consultas a múltiplas fontes (VirusTotal, AbuseIPDB, Shodan, etc.), gera relatórios detalhados em Excel e PDF, e utiliza um modelo de IA local (via Ollama) para criar resumos executivos das análises.

<a id="caso-real--o-golpe-do-repositório-falso"></a>

## 🚨 Caso real: golpe do repositório falso

Recentemente, um golpe de recrutamento no LinkedIn usou repositórios GitHub maliciosos como testes técnicos para DEVs. O objetivo era fazer o candidato clonar o projeto e rodar um script de instalação malicioso (`npm install`) para infectar sua máquina e roubar credenciais.

O ThreatSpy foi aprimorado para detectar exatamente este tipo de ameaça sem precisar clonar ou executar nada. Basta usar a aba **Análise de Repositório** e colar a URL suspeita. A ferramenta irá verificar:

- **Segredos Expostos**: análise de arquivos como `.env` em busca de chaves de API, tokens e senhas.
- **Arquivos de Configuração Sensíveis**: verificação de arquivos conhecidos por conter dados sensíveis, como `credentials.json` e `database.yml`.
- **IOCs Ocultos**: decodificação de strings Base64 para encontrar URLs e domínios maliciosos escondidos.
- **Comandos Perigosos**: alerta sobre comandos suspeitos em arquivos como `README.md` (ex: `npm install --force` ou `curl ... | sh`).
- **Scripts de Instalação Maliciosos**: auditoria do `package.json` em busca de scripts perigosos nas fases de `preinstall` ou `postinstall`.

Ao final, você recebe um relatório completo do risco antes de expor seu ambiente.

<a id="funcionalidades-principais"></a>

## ✨ Funcionalidades Principais

- **Análise Multi-Fonte de IOCs**: consulta a reputação de IPs, URLs e hashes de arquivos em serviços como VirusTotal, AbuseIPDB, Shodan, URLHaus e MalwareBazaar.
- **Análise de Múltiplos Arquivos**: calcule o hash SHA256 de múltiplos arquivos locais e verifique sua reputação de uma só vez.
- **Análise Estática de Repositórios Aprofundada**: inspeciona repositórios GitHub e GitLab remotamente em busca de:
  - segredos expostos (chaves de API, tokens etc.)
  - arquivos de configuração sensíveis
  - IOCs ofuscados em Base64
  - comandos perigosos em READMEs
  - scripts maliciosos de npm (`preinstall`/`postinstall`)
- **Interface Gráfica Intuitiva**: GUI em PySide6 para analisar múltiplos alvos, arquivos e repositórios de forma organizada e paralela.
- **Relatórios Completos e Seguros**: gera relatórios em Excel (.xlsx) e PDF. Todos os indicadores são *defanged*.
- **Resumo com IA Local**: integração com Ollama para resumos executivos, explicações de risco e planos de ação.
- **Segurança e Privacidade**:
  - chaves de API salvas com segurança via keyring
  - logs em pastas de dados do usuário, garantindo execução em qualquer diretório

<a id="tecnologias-utilizadas"></a>
<h2>🛠️ Tecnologias Utilizadas</h2>

<div align="center">

<table>
  <thead>
    <tr>
      <th>Tecnologia</th>
      <th>Propósito</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Python</td><td>Linguagem principal do projeto</td></tr>
    <tr><td>PySide6 (Qt for Python)</td><td>Interface gráfica multiplataforma</td></tr>
    <tr><td>Ollama</td><td>Execução de modelos de IA locais para resumos</td></tr>
    <tr><td>Requests</td><td>Comunicação com APIs de Threat Intelligence</td></tr>
    <tr><td>Keyring</td><td>Armazenamento seguro das chaves de API</td></tr>
    <tr><td>XlsxWriter / ReportLab</td><td>Geração de relatórios em Excel e PDF</td></tr>
    <tr><td>PyInstaller</td><td>Empacotamento da aplicação em executáveis</td></tr>
  </tbody>
</table>

</div>

<a id="screenshot-da-ferramenta"></a>
<a id="screenshot-da-ferramenta"></a>

## 📸 Screenshot da Ferramenta

<p align="center">
  <img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/ThreatsSy.png" alt="Screenshot da Aplicação">
</p>

<a id="download-e-instalacao"></a>

## ⚡ Download e Instalação

<a id="para-usuários-windows"></a>

### Para Usuários (Windows)

1. Acesse a página de Releases.
2. Baixe o arquivo `.zip` da versão mais recente para Windows.
3. Descompacte o arquivo em uma pasta de sua preferência.
4. Execute o arquivo `ThreatSpy.exe`.
5. Na primeira vez que usar, vá em **Configurações** para adicionar suas chaves de API.

<a id="para-usuários-macos"></a>

### Para Usuários (macOS)

1. Acesse a página de Releases.
2. Baixe o arquivo `.zip` da versão para macOS.
3. Descompacte e execute o `ThreatSpy.app`.
4. **Nota**: o macOS pode exibir um aviso de segurança. Se isso ocorrer, clique com o botão direito, selecione **Abrir** e confirme na caixa de diálogo para permitir a execução.

<a id="para-usuários-linux"></a>

### Para Usuários (Linux)

1. Acesse a página de Releases.
2. Baixe o arquivo `.zip` da versão para Linux.
3. Descompacte o arquivo e torne-o executável:

```bash
chmod +x ThreatSpy
```

4. Execute o programa:

```bash
./ThreatSpy
```

5. Na primeira vez que usar, vá em **Configurações** para adicionar suas chaves de API.

<a id="para-desenvolvedores"></a>

### Para Desenvolvedores (a partir do Código-Fonte)

**Pré-requisitos**: Python 3.8+ e Git instalados. Para a função de IA, o Ollama (https://ollama.com) deve estar instalado e rodando localmente.

Clone o repositório:

```bash
git clone https://github.com/DevGreick/ThreatSpy.git
cd ThreatSpy
```

Crie um ambiente virtual e instale as dependências:

```bash
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Execute o programa:

```bash
python main_gui.py
```

<a id="configuracao-essencial"></a>

## ⚙️ Configuração Essencial

Antes do primeiro uso, você precisa configurar suas chaves de API.

1. Inicie a aplicação.
2. Na tela principal, clique em **Configurações**.
3. Insira suas chaves de API. As chaves são salvas de forma segura no keyring do seu sistema operacional.

**Chave Principal (Essencial):**
- VirusTotal: essencial para a análise de IPs, URLs e arquivos.

**Chaves Opcionais (Recomendadas):**
- GitHub/GitLab: altamente recomendadas para a análise de repositórios, evitando bloqueios de API.
- AbuseIPDB, Shodan, etc.: enriquecem os relatórios com dados adicionais.

**IA Local (Opcional):**
- Ollama: verifique se o serviço está rodando para usar a funcionalidade de resumo por IA. O endpoint padrão já vem configurado.

<a id="como-usar"></a>

## 🛠️ Como Usar

Toda a operação é feita através da interface gráfica.

| Tipo de Análise        | Como Fazer |
|------------------------|------------|
| Analisar IPs e URLs    | Na aba **Análise de IOCs**, cole os indicadores na caixa de texto (um por linha) e clique em **Analisar Alvos**. |
| Analisar Arquivos      | Na aba **Análise de IOCs**, clique em **Verificar Reputação de Arquivos** e selecione um ou mais arquivos locais. |
| Analisar Repositórios  | Vá para a aba **Análise de Repositório**, cole as URLs do GitHub/GitLab e clique em **Analisar Repositórios**. |

Após cada análise, use os botões na parte inferior para gerar resumos em texto ou PDF com a ajuda da IA.

<a id="roadmap-futuro"></a>

## 🗺️ Roadmap Futuro

- [ ] Integração com feeds de ameaças adicionais (AlienVault OTX, CISA KEV).
- [ ] Um dashboard web para visualização centralizada dos relatórios.
- [ ] Automação de alertas com base em regras personalizadas.

<a id="contribuicao"></a>

## 🤝 Contribuição

Contribuições são muito bem-vindas!

1. Faça um fork do projeto.
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`).
3. Commit suas alterações (`git commit -m 'Adiciona nova feature'`).
4. Push para a branch (`git push origin feature/nova-feature`).
5. Abra um Pull Request.

<a id="apoie-o-projeto"></a>

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
