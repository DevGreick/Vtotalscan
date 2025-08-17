# Vtotalscan v1.0

<div align="center">

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![GUI](https://img.shields.io/badge/GUI-PySide6-purple.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

</div>

<p align="center">
  <img src="spy2-1.png" alt="Logo do Vtotalscan" width="150">
</p>

Uma ferramenta de análise e inteligência de ameaças (Threat Intelligence) que automatiza a consulta de IPs e URLs em múltiplas fontes, gera relatórios profissionais e cria resumos com IA local.

---

## Sobre o Projeto

O Vtotalscan é uma ferramenta de código aberto para análise de indicadores de comprometimento (IPs e URLs). Ele automatiza consultas em múltiplas APIs (VirusTotal, AbuseIPDB, URLHaus, Shodan) para enriquecer dados e gerar relatórios de forma rápida.

O projeto começou como um script simples para um colega e evoluiu para esta suíte de análise completa, com interface gráfica moderna e IA local para resumos.

## Funcionalidades Principais

* **Análise Multi-API:** Enriqueça seus dados consultando indicadores simultaneamente no **VirusTotal, AbuseIPDB, URLHaus e Shodan**.
* **Interface Gráfica Moderna:** Uma interface intuitiva e agradável construída com **PySide6**, com tema escuro.
* **Relatórios Profissionais:** Exporte os resultados consolidados para arquivos **Excel (.xlsx)** formatados (com cores e links) ou para um resumo em **PDF**.
* **Resumos com IA Local:** Integração com **Ollama** para gerar resumos técnicos inteligentes das análises, com detecção automática dos seus modelos instalados. Seus dados nunca saem da sua máquina.
* **Gestão Segura de Chaves:** Suas chaves de API são armazenadas de forma segura no cofre de credenciais nativo do sistema operacional (**Windows Credential Manager, macOS Keychain, etc.**) usando a biblioteca `keyring`.
* **Processamento Eficiente:** As análises rodam em uma thread separada para não travar a interface, com barra de progresso e opção de cancelamento. O cliente de API implementa um **rate limit inteligente**, respeitando os pedidos de espera das APIs (`Retry-After`).

## 🖥️ Screenshot da Ferramenta

<p align="center">
  <img src="vtotalscan.png" alt="Screenshot da Aplicação">
</p>

## Download e Instalação

### Para Usuários (Recomendado)

1.  Acesse a página de **[Releases](https://github.com/DevGreick/Vtotalscan/releases)**.
2.  Baixe o arquivo `.zip` ou `.exe` da versão mais recente (v1.0).
3.  Se baixou o `.zip`, descompacte o arquivo em uma pasta.
4.  Execute o arquivo `Vtotalscan.exe`.
5.  Na primeira vez que usar, vá em **Configurações** para adicionar suas chaves de API.

### Para Desenvolvedores (a partir do Código-Fonte)

1.  **Pré-requisitos:** Garanta que você tenha **Python 3.8+** e **Git** instalados. Para a função de IA, o **Ollama** ([ollama.com](https://ollama.com)) deve estar instalado.

2.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/DevGreick/Vtotalscan.git](https://github.com/DevGreick/Vtotalscan.git)
    cd Vtotalscan
    ```

3.  **Instale as dependências:**
    (É altamente recomendado criar e ativar um ambiente virtual primeiro)
    ```bash
    pip install -r requirements.txt
    ```

4.  **Execute o programa:**
    ```bash
    python main_gui.py
    ```

## Como Usar

1.  **Insira os Alvos:** Cole os IPs ou URLs na área de texto (um por linha) ou carregue de um arquivo `.txt` usando o botão "Carregar de Arquivo".
2.  **Inicie a Análise:** Clique em "ANALISAR ALVOS" e escolha onde salvar o relatório Excel.
3.  **Acompanhe o Progresso:** Veja o status da análise em tempo real no "Console de Atividade".
4.  **Gere o Resumo com IA:** Após a análise, vá para a aba "Resumo Gerado por IA", selecione um modelo do Ollama e clique em "Gerar Resumo em PDF" ou "Gerar Resumo em Texto".

## Contribuição

Este é um projeto de código aberto e contribuições são muito bem-vindas! Se você encontrar um bug, tiver uma sugestão de melhoria ou quiser adicionar uma nova funcionalidade, sinta-se à vontade para abrir uma **Issue** ou um **Pull Request**.

## 📄 Licença

Este projeto é distribuído sob a Licença MIT. Veja o arquivo `LICENSE` para mais detalhes.
