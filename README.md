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

## 🚨 O Golpe do Repositório Falso

Golpes de recrutamento vêm usando repositórios maliciosos como teste técnico para devs. O roteiro é sempre parecido, o candidato clona o repo e roda `npm install`, muitas vezes com instrução de `npm install --force`. Dentro do projeto aparece um `.env` com string em Base64 que leva a um domínio suspeito e scripts de instalação que podem abrir brechas locais.

Com o ThreatSpy, você não precisa clonar ou executar nada. Basta usar a aba "Análise de Repositório", colar a URL suspeita e a ferramenta irá verificar pois ele :

- detecta `.env` e procura chaves, tokens e segredos
- decodifica Base64 e extrai IOCs para checagem de reputação
- inspeciona `package.json` e alerta para `preinstall` e `postinstall`
- lê `README.md` e marca comandos perigosos como `npm install --force` e `curl ... | sh`
- gera relatório com score de risco e links defanged

Ação imediata:

- cole a URL do repo na aba **Análise de Repositório** e veja o risco antes de rodar qualquer comando

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

## 🛠️ Tecnologias Utilizadas

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

## ⚙️ Configuração

Para usar o ThreatSpy, você precisará configurar algumas chaves de API. A única chave **obrigatória** é a do VirusTotal. As outras são **opcionais**, mas enriquecem muito os relatórios.

Você pode adicionar todas as chaves facilmente clicando no botão **Configurações** dentro do aplicativo.

| Serviço         | Necessidade  | O que habilita?                                                  |
|-----------------|--------------|------------------------------------------------------------------|
| VirusTotal      | `Obrigatória`| Análise de reputação de IPs, URLs e Arquivos.                   |
| GitHub / GitLab | `Recomendada`| Análise de Repositórios (evita bloqueios de API).               |
| AbuseIPDB       | `Opcional`   | Adiciona "Score de Abuso" para IPs.                             |
| Shodan          | `Opcional`   | Adiciona informações de portas e serviços para IPs.             |
| URLHaus         | `Opcional`   | Verifica se URLs estão distribuindo malware ativamente.         |
| MalwareBazaar   | `Opcional`   | Identifica o nome da ameaça (malware) de arquivos.              |
| Ollama (IA)     | `Opcional`   | Resumos automáticos gerados por IA local.                       |

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
