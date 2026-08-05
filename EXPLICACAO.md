# EXPLICACAO.md — Manual Explicativo dos Comandos / Commands Explanation Manual

Este documento fornece a explicação detalhada, passo a passo, e a finalidade de cada comando operacional do **Ignotus 2.1**.
This document provides a detailed, step-by-step explanation and purpose of each operational command in **Ignotus 2.1**.

---

## ÍNDICE / TABLE OF CONTENTS
1. [Preparação do Ambiente / Environment Setup](#1-preparação-do-ambiente--environment-setup)
2. [Menu e Interface / Menu and Interface](#2-menu-e-interface--menu-and-interface)
3. [Modos Locais Defensivos / Defensive Local Modes](#3-modos-locais-defensivos--defensive-local-modes)
4. [Auditoria de Alvos Remotos (Scan) / Remote Target Audits (Scan)](#4-auditoria-de-alvos-remotos-scan--remote-target-audits-scan)
5. [Módulos Individuais de Varredura / Individual Scanning Modules](#5-módulos-individuais-de-varredura--individual-scanning-modules)
6. [Gerenciamento de Autenticação e Proxy / Auth & Proxy Management](#6-gerenciamento-de-autenticação-e-proxy--auth--proxy-management)
7. [Ferramentas de Desenvolvimento e Testes / Development and Testing Tools](#7-ferramentas-de-desenvolvimento-e-testes--development-and-testing-tools)

---

## 1. Preparação do Ambiente / Environment Setup

### Criar e Ativar Ambiente Python / Create and Activate Python Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```
*   **PT:** Cria uma sandbox virtual (`.venv`) para que as bibliotecas do Ignotus não entrem em conflito com o Python global do sistema. Em seguida, ativa o ambiente no PowerShell e instala todas as dependências de produção e desenvolvimento do framework.
*   **EN:** Creates a virtual sandbox (`.venv`) so Ignotus libraries do not conflict with the system's global Python. It then activates the environment in PowerShell and installs all production and development dependencies.

---

### Compilar o Motor Go / Build the Go Engine
```powershell
.\build_engine.bat
```
*   **PT:** Executa o script que compila o motor de rede de alta velocidade (`ignotus-engine.exe` no Windows ou `ignotus-engine` no Linux/WSL). Esse binário em Go executa varreduras de portas e testes de preflight de rede de forma paralela e otimizada.
*   **EN:** Runs the script to compile the high-speed network engine (`ignotus-engine.exe` on Windows or `ignotus-engine` on Linux/WSL). This Go binary performs optimized, parallel port scans and network preflight tests.

---

### Verificar Versões / Verify System Versions
```powershell
.\.venv\Scripts\python.exe --version
& 'C:\Program Files\Go\bin\go.exe' version
.\bin\ignotus-engine.exe --help
```
*   **PT:** Diagnóstico do ambiente para validar se o Python, o compilador Go e o binário recém-compilado do motor estão com caminhos corretos e operacionais.
*   **EN:** Environment diagnosis to validate if Python, the Go compiler, and the newly-compiled engine binary are correctly placed and operational.

---

## 2. Menu e Interface / Menu and Interface

### Menu Interativo Compacto / Interactive Compact Menu
```powershell
python main.py
# Ou de qualquer pasta se o atalho estiver instalado:
ignotus
```
*   **PT:** Abre o prompt compacto e interativo `ignotus ›`. Nesse painel, você pode digitar os comandos diretamente em uma única linha (ex: `impact alvo.com`) sem a necessidade de passar parâmetros complexos no terminal de origem.
*   **EN:** Opens the interactive compact prompt `ignotus ›`. In this panel, you can type commands directly in a single line (e.g. `impact target.com`) without passing complex parameters in your terminal.

---

### Assistente Interativo Antigo / Legacy Interactive Wizard
```powershell
.\iniciar_ignotus.bat
# Ou:
.\.venv\Scripts\python.exe main.py --interactive
```
*   **PT:** Inicia o assistente guiado que orienta o operador na parametrização do scan interativamente.
*   **EN:** Starts the guided wizard that walks the operator through setting up the scan parameters interactively.

---

## 3. Modos Locais Defensivos / Defensive Local Modes

### Auditoria Nativa do AMSI / Native AMSI Audit
```powershell
.\.venv\Scripts\python.exe main.py --amsi-audit
```
*   **PT:** Roda um teste local e benigno que valida a resposta em tempo real da API do Windows AMSI (Antimalware Scan Interface). Testa o bloqueio de buffers em memória sem baixar ou gravar arquivos suspeitos em disco.
*   **EN:** Runs a local, benign audit validating the real-time response of the Windows AMSI (Antimalware Scan Interface) API. It tests memory buffer blocks without dropping suspicious files on disk.

---

### Modo Vermelho Local / Local Red Mode (Windows)
```powershell
.\.venv\Scripts\python.exe main.py --red-mode
```
*   **PT:** Executa o scanner de postura local no Windows (`quick` por padrão) para auditar integridade de DLLs, assinaturas digitais, configurações do Defender, ASR, UAC, VBS e telemetria local.
*   **EN:** Runs the local posture scanner on Windows (`quick` by default) to audit DLL integrity, digital signatures, Defender configs, ASR, UAC, VBS, and local telemetry.

---

### Modo Vermelho Remoto (VPS) / Remote Red Mode (VPS Audit)
```powershell
python main.py red full root@191.252.200.164
```
*   **PT:** Estabelece **uma única conexão SSH** com a VPS informada. Envia e executa dinamicamente os scripts Linux (`linux_snapshot.py`, `canaries.py` e `impact.py`) no `python3` da máquina remota. Avalia integridade de libs, UFW/iptables, SSH, persistências (cron/systemd) e se há antivírus ativo (ClamAV), devolvendo o relatório no console local.
*   **EN:** Establishes **a single SSH connection** with the target VPS. Dynamically uploads and runs Linux scripts (`linux_snapshot.py`, `canaries.py`, and `impact.py`) into `python3` on the remote host. It audits library integrity, UFW/iptables, SSH, persistence (cron/systemd), and antivirus presence (ClamAV), outputting the report locally.

---

### Baselines e Derivas no Modo Vermelho / Baselines and Drift Control
```powershell
# Gravar nova baseline:
.\.venv\Scripts\python.exe main.py --red-mode --red-profile full --red-save-baseline

# Comparar com baseline recente:
.\.venv\Scripts\python.exe main.py --red-mode --red-profile full --red-compare-baseline
```
*   **PT:** O primeiro comando salva as configurações atuais do sistema (seja local ou remoto) como o estado "seguro e estável" (baseline). O segundo compara o estado atual com a baseline e gera um alerta `WARN` detalhando qualquer desvio ("drift") em chaves de registro, serviços ou tarefas agendadas.
*   **EN:** The first command saves the current system configuration (local or remote) as the "safe and stable" state (baseline). The second compares the current state with the baseline and raises a `WARN` alert detailing any changes ("drift") in registry keys, services, or scheduled tasks.

---

### Purple Team Simulador / Purple Team Simulation
```powershell
.\.venv\Scripts\python.exe main.py --purple-team --purple-profile all --purple-detections config\purple\detections.json
```
*   **PT:** Executa testes locais e benignos (canários) simulando comportamentos de técnicas ATT&CK (criação de processos, conexões TCP loopback, registros temporários) e compara se as regras de detecção listadas no arquivo JSON detectaram os eventos.
*   **EN:** Performs local and benign tests (canaries) simulating behaviors of ATT&CK techniques (process creation, loopback TCP connections, temp registry changes) and matches if the detection rules listed in the JSON file observed the events.

---

## 4. Auditoria de Alvos Remotos (Scan) / Remote Target Audits (Scan)

### Modo Focado em Impactos / Only Impact Mode
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact
```
*   **PT:** Executa a varredura convencional passiva e ativa em busca de subdomínios, DNS, TLS e cabeçalhos HTTP, porém **suprime** a exibição de hosts sem achados de segurança relevantes, focando o relatório nas vulnerabilidades/impactos reais.
*   **EN:** Runs conventional passive and active scanning for subdomains, DNS, TLS, and HTTP headers, but **suppresses** showing hosts with no relevant security findings, focusing the output on verified vulnerabilities/impacts.

---

### Varredura Completa Autorizada / Full Authorized Scan
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --full --scope-file config\scopes\meu-escopo.txt --engine go
```
*   **PT:** Modo mais abrangente de auditoria de rede. Ativa testes intrusivos e de raspagem adicionais (Wayback, fuzzing de arquivos, API explorer, smuggling, SSRF, Nuclei) utilizando o motor compilado em Go. Exige a declaração de um escopo de permissão para atuar.
*   **EN:** The most comprehensive network audit mode. Activates active fuzzing, active scrapers, and intrusive modules (Wayback, file fuzzing, API explorer, smuggling, SSRF, Nuclei) using the compiled Go engine. Requires a configured scope file to execute.

---

### Retomar de onde parou / Resume Checkpoint
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --resume
```
*   **PT:** Lê o arquivo JSON de progresso temporário na pasta `output/checkpoints/` e retoma a varredura de subdomínios a partir do último host concluído, ignorando os que já foram analisados.
*   **EN:** Reads the temporary progress JSON in `output/checkpoints/` and resumes scanning subdomains from the last completed host, skipping those already analyzed.

---

## 5. Módulos Individuais de Varredura / Individual Scanning Modules

As opções a seguir exigem `--only-impact` e a configuração de `--scope-file` se envolverem testes ativos:

### Caça a Assets e Source Maps / Asset Hunting & Source Maps
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --hunt-assets --download-dir output\sourcemaps\example
```
*   **PT:** Procura por caminhos comuns contendo arquivos `.map` (source maps), códigos javascript brutos expostos, segredos vazados no frontend, ou backups em diretórios públicos.
*   **EN:** Looks for common paths exposing `.map` files (source maps), raw client-side Javascript code, frontend leaked secrets, or public directory backups.

---

### Request Smuggling HTTP
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --smuggling --scope-file config\scopes\meu-escopo.txt
```
*   **PT:** Envia payloads malformados de transferência de blocos e comprimento de conteúdo (CL.TE, TE.CL, TE.TE e CL.0) para verificar se o proxy intermediário e o servidor web backend divergem no processamento de requisições HTTP.
*   **EN:** Sends malformed transfer-encoding and content-length payloads (CL.TE, TE.CL, TE.TE, and CL.0) to check if the reverse proxy and the backend web server disagree on HTTP request boundaries.

---

### Auditoria Externa via Kali WSL / External Kali WSL Audit
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --external-audit --scope-file config\scopes\meu-escopo.txt
```
*   **PT:** Aciona a distribuição local WSL do Kali Linux e dispara utilitários externos (como `nmap` e `sslscan`) de forma coordenada. As descobertas são consolidadas no relatório final do Ignotus.
*   **EN:** Spawns the local Kali Linux WSL distribution and executes external security tools (like `nmap` and `sslscan`). The findings are parsed and centralized inside the Ignotus report.

---

### Fuzzing de Arquivos Sensíveis / Sensitive File Fuzzing
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --fuzz-files --scope-file config\scopes\meu-escopo.txt
```
*   **PT:** Varre o servidor web remoto enviando requisições para arquivos comuns de configuração (`.env`, `config.json`, `.git/config`, `backup.zip`, `.sql`) buscando exposições de dados confidenciais.
*   **EN:** Fuzzes the web server by requesting common sensitive directories and files (`.env`, `config.json`, `.git/config`, `backup.zip`, `.sql`) looking for accidental exposures.

---

### Auditoria de OpenAPI e Swagger / OpenAPI & Swagger Testing
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --test-api --scope-file config\scopes\meu-escopo.txt
```
*   **PT:** Busca documentações de API públicas (Swagger UI, OpenAPI spec, Graphql schema) e audita os endpoints expostos buscando autenticação fraca ou vazamento de parâmetros.
*   **EN:** Locates public API documentation (Swagger UI, OpenAPI spec, Graphql schema) and audits exposed routes for weak authentication or parameter leakage.

---

### Wayback Harvester / Wayback CDX Harvester
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --wayback
```
*   **PT:** Consulta a CDX API do Internet Archive para descobrir subdomínios e caminhos históricos que existiram no passado para o domínio alvo, alimentando o escopo de scan.
*   **EN:** Queries the Internet Archive's CDX API to discover historical subdomains and files that used to exist on the target domain, feeding the scanning scope.

---

### GitHub Dorker / Public Repository Scanner
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --github-dork --github-token TOKEN
```
*   **PT:** Varre repositórios públicos no GitHub correspondentes ao domínio alvo buscando credenciais expostas ou vazamento de código fonte.
*   **EN:** Scans public GitHub repositories looking for code leaks or credentials associated with the target domain.

---

### Teste de DoS do Werkzeug / Werkzeug Multipart DoS check
```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --werkzeug-dos --scope-file config\scopes\meu-escopo.txt
```
*   **PT:** Testa se o servidor web remoto é vulnerável a exaustão de CPU ao processar payloads multipart malformados (vulnerabilidade conhecida no Werkzeug). **Nota:** Deve ser ativado de forma 100% explícita e autorizada.
*   **EN:** Probes if the remote web server is vulnerable to CPU exhaustion when parsing malformed multipart headers (known Werkzeug CVE). **Note:** Must be explicitly enabled with strict authorization.

---

## 6. Gerenciamento de Autenticação e Proxy / Auth & Proxy Management

### Cookies e Headers Personalizados / Cookies and Custom Headers
```powershell
# Com Cookie:
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --auth-cookie "session=VALOR"

# Com Header:
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --auth-header "Authorization:Bearer TOKEN"
```
*   **PT:** Passa dados de autenticação para que as requisições HTTP do Ignotus (incluindo raspadores de JS, Swagger e caçadores de assets) acessem diretórios e endpoints que exigem login.
*   **EN:** Injects authentication tokens so Ignotus' HTTP requests (such as JS scrapers, Swagger explorer, and asset hunters) can reach resources and endpoints behind authentication.

---

### Proxies HTTP e SOCKS5 / HTTP & SOCKS5 Routing
```powershell
# HTTP Proxy:
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --proxy http://127.0.0.1:8080

# SOCKS5 Proxy:
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --proxy socks5://127.0.0.1:9050
```
*   **PT:** Redireciona todo o tráfego de rede gerado pelo Ignotus por meio de um proxy externo (como o Burp Suite na porta 8080 ou a rede Tor na porta 9050).
*   **EN:** Routes all outbound network traffic generated by Ignotus through a local or external proxy (like Burp Suite on port 8080 or Tor on port 9050).

---

## 7. Ferramentas de Desenvolvimento e Testes / Development and Testing Tools

### Executar Testes Unitários Python / Run Python Tests
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
*   **PT:** Executa o pytest em modo silencioso/rápido para validar se todas as rotas, lógicas e validações do Python continuam íntegras após modificações de código.
*   **EN:** Runs pytest in quiet/quick mode to validate that all python routes, logic, and parsing filters remain correct after code changes.

---

### Executar Testes Go / Run Go Tests
```powershell
Push-Location engine\go
& 'C:\Program Files\Go\bin\go.exe' test ./...
Pop-Location
```
*   **PT:** Entra na pasta do código Go do motor e roda a suíte de testes nativa do Go para validar a concorrência e integridade do analisador Go.
*   **EN:** Changes directory to the Go engine source and runs native Go tests to validate network concurrency and parser integrity.

---

### Varredura Estática de Erros / Ruff Static Check
```powershell
.\.venv\Scripts\python.exe -m ruff check main.py core tests --select E9,F63,F7,F82
```
*   **PT:** Roda o linter `ruff` nas pastas principais para caçar erros críticos de sintaxe, imports não resolvidos ou erros de lógica estática antes de rodar o código.
*   **EN:** Runs `ruff` linter across core directories to hunt down critical syntax bugs, unresolved imports, or logic errors before execution.
