# I G N O T U S — Manual completo de comandos

Este é o documento central de operação do Ignotus 2.1. Todos os fluxos são
executados pelo terminal.

## 1. Regras de execução

Uma varredura de alvo só inicia com um modo explícito:

- `--only-impact` ou `--only-impacts`: modo focado em achados.
- `--full`: perfil avançado completo e autorizado.

Modos locais independentes:

- `--red-mode`: validação defensiva avançada do endpoint Windows.
- `--amsi-audit`: auditoria defensiva nativa do AMSI/Defender.
- `--purple-team`: simulações Purple Team benignas e locais.
- `--source-map URL`: extração direta de source map.

Módulos ativos ou intrusivos exigem `--scope-file`. O teste
`--werkzeug-dos` nunca é ativado implicitamente por `--full`.

### Política avançada de evidência

O runtime não carrega arquivos de exemplo/mock. Os modos locais usam
`config/red/detections.json` e `config/purple/detections.json`, ambos com
`schema_version: 2` e `mode: strict-impact`. Uma observação só vira impacto
confirmado após evidência de comportamento/permissão; padrões de segredo ficam
`SUPPORTED` ou `UNVERIFIED`, com valor e contexto redigidos.

Auditoria offline do acervo legado (somente leitura, sem rede):

```powershell
python -m core.legacy_corpus `
  --logs C:\Users\Ignotus\Music\ingotus\output\logs `
  --sourcemaps C:\Users\Ignotus\Music\ingotus\output\sourcemaps\sourcemaps `
  --output output\legacy_corpus `
  --max-files 2500
```

O relatório informa explicitamente quando a amostra é truncada e nunca inclui
tokens, cookies, segredos ou trechos de código.

### Catálogo avançado de ativos

O inventário de ativos fica separado do motor em:

```text
config/assets/asset_catalog.json    # 3.844 linhas / 3.652 caminhos
core/asset_catalog.py               # loader, schema e validadores
```

O catálogo é carregado somente se `schema_version=2`, política
`strict-impact-v2`, severidade conhecida e caminhos seguros forem satisfeitos.
Rotas convencionais sem conteúdo validado permanecem observações; um nome de
rota não é promovido automaticamente a vulnerabilidade.

## 2. Abrir o projeto

```powershell
cd C:\Users\Ignotus\Documents\program
```

Abrir o menu interativo diretamente:

```powershell
python main.py
```

O terminal abre diretamente no painel compacto. Não existe mais questionário
passo a passo: digite uma operação em uma única linha no prompt `ignotus ›`.

```text
impact example.com --workers 20
full example.com --scope-file config/scopes/meu-escopo.txt
red impact
purple all
amsi
help
exit
```

Os atalhos `impact` e `full` são convertidos internamente para os modos
obrigatórios `--only-impact` e `--full`. As validações de escopo continuam
ativas; a interface compacta não reduz as proteções do executor.

### Validação automática de serviços expostos

Os modos normais agora incluem aplicações em portas alternativas (`3000`,
`3001`, `3005`, `5000`, `8000`, `8080`, `8443` e `8888`) e PostgreSQL em
`5432`. Não existe um modo separado para VPS.

Quando essas portas estão abertas, o Ignotus:

- tenta HTTPS e HTTP nas portas de aplicação;
- registra status, protocolo, servidor e headers de rate limit;
- negocia o protocolo PostgreSQL e identifica TLS e método de autenticação;
- nunca envia senha ao banco;
- correlaciona `502/503/504` no proxy com aplicação respondendo diretamente;
- grava a evidência em `services.json` e no relatório Markdown.

Execução focada usando o fluxo existente:

```powershell
ignotus 191.252.200.164 --only-impact --engine go --no-checkpoint
```

Execução completa autorizada:

```powershell
ignotus 191.252.200.164 --full `
  --scope-file config\scopes\authorized-test-sites.txt `
  --engine go --no-checkpoint
```

Depois de instalar o atalho local, o mesmo menu abre de qualquer pasta:

```powershell
ignotus
```

O alias `ignorus` também é instalado para tolerar essa grafia, mas o comando
oficial é `ignotus`.

Atalhos diretos do Modo Vermelho:

```powershell
# Perfil rápido
ignotus red

# Perfil completo
ignotus red full

# Validação direta de impacto defensivo
ignotus red impact

# Perfil completo e nova baseline
ignotus red full --red-save-baseline

# Alias em português
ignotus vermelho full
```

Assistente interativo:

```powershell
.\iniciar_ignotus.bat
```

Ou:

```powershell
.\.venv\Scripts\python.exe main.py --interactive
```

Ajuda completa do terminal:

```powershell
.\.venv\Scripts\python.exe main.py --help
```

## 3. Preparar o ambiente

Criar e ativar o ambiente Python:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

Compilar o motor Go:

```powershell
.\build_engine.bat
```

Verificar versões:

```powershell
.\.venv\Scripts\python.exe --version
& 'C:\Program Files\Go\bin\go.exe' version
.\bin\ignotus-engine.exe --help
```

## 4. Arquivo de escopo

Exemplo `config\scopes\meu-escopo.txt`:

```text
# Regras autorizadas
in: example.com
in: *.example.com
in: 203.0.113.10

# Exclusões opcionais
out: admin.example.com
```

Escopo usado nos ambientes de teste atuais:

```text
config\scopes\authorized-test-sites.txt
```

Visualizar:

```powershell
Get-Content config\scopes\authorized-test-sites.txt
```

## 5. Formatos de alvo

```powershell
# Domínio
.\.venv\Scripts\python.exe main.py "example.com" --only-impact

# Wildcard; use aspas para impedir expansão do shell
.\.venv\Scripts\python.exe main.py "*.example.com" --only-impact

# IPv4
.\.venv\Scripts\python.exe main.py "203.0.113.10" --only-impact

# IPv6
.\.venv\Scripts\python.exe main.py "2001:db8::10" --only-impact

# Host e porta, sem descoberta passiva
.\.venv\Scripts\python.exe main.py "example.com:8443" --only-impact

# URL
.\.venv\Scripts\python.exe main.py "https://example.com/path" --only-impact
```

## 6. Modos principais

### Apenas impactos

```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact
```

`--only-impact` e `--only-impacts` são equivalentes. Esse modo não autoriza
automaticamente smuggling, SSRF, Nuclei, fuzzing, auditoria WSL ou DoS.

### Perfil completo avançado

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --full `
  --scope-file config\scopes\meu-escopo.txt `
  --engine go `
  --workers 1 `
  --rate-limit 0.5 `
  --scan-timeout 900
```

`--full` ativa:

- Wayback;
- GitHub dorking;
- caça a assets e source maps;
- fuzzing de arquivos sensíveis;
- exploração de Swagger/OpenAPI;
- request smuggling;
- SSRF;
- Nuclei oficial;
- screenshots headless;
- auditoria externa Nmap/sslscan pelo Kali WSL;
- comparação histórica.

`--full` não ativa `--werkzeug-dos`.

## 7. Comandos dos ambientes autorizados

### VPS por IP

Inventário e impactos:

```powershell
.\.venv\Scripts\python.exe main.py "191.252.200.164" --full`
  --engine go `
  --scope-file config\scopes\authorized-test-sites.txt `
  --workers 2 `
  --interactive `
  --rate-limit 0.5 `
  --scan-timeout 300
```

Auditoria avançada de SSH, HTTP e TLS com WSL:

```powershell
.\.venv\Scripts\python.exe main.py "191.252.200.164" --only-impact `
  --external-audit `
  --engine go `
  --scope-file config\scopes\authorized-test-sites.txt `
  --workers 1 `
  --rate-limit 0.25 `
  --scan-timeout 600
```

Hostname administrativo na porta 443:

```powershell
.\.venv\Scripts\python.exe main.py "vps64602.publiccloud.com.br:443" --full `
  --engine go `
  --scope-file config\scopes\authorized-test-sites.txt `
  --workers 1 `
  --rate-limit 0.25 `
  --scan-timeout 900
```

### Papirar

```powershell
.\.venv\Scripts\python.exe main.py "papirar-oficial.vercel.app:443" --full `
  --engine go `
  --scope-file config\scopes\authorized-test-sites.txt `
  --workers 1 `
  --rate-limit 0.25 `
  --scan-timeout 900
```

### Go Beast

```powershell
.\.venv\Scripts\python.exe main.py "go-beast.vercel.app:443" --full `
  --engine go `
  --scope-file config\scopes\authorized-test-sites.txt `
  --workers 1 `
  --rate-limit 0.5 `
  --scan-timeout 900
```

### OPS Web Beta

```powershell
.\.venv\Scripts\python.exe main.py "ops-web-beta.vercel.app:443" --full `
  --engine go `
  --scope-file config\scopes\authorized-test-sites.txt `
  --workers 1 `
  --rate-limit 0.5 `
  --scan-timeout 900
```

## 8. AMSI avançado defensivo

Execução:

```powershell
.\.venv\Scripts\python.exe main.py --amsi-audit
```

Diretório personalizado:

```powershell
.\.venv\Scripts\python.exe main.py --amsi-audit `
  --amsi-output output\amsi\minha-auditoria
```

O modo valida diretamente:

- assinatura e versão de `amsi.dll`;
- provedores AMSI registrados;
- serviço antimalware e proteção em tempo real;
- monitor comportamental do Defender;
- chamadas nativas `AmsiInitialize`, `AmsiOpenSession` e `AmsiScanString`;
- controle benigno em memória;
- marcador industrial inerte de teste em memória;
- Script Block Logging e Module Logging.

Ele não desativa AMSI, não executa bypass, não cria persistência e não grava o
marcador de teste em disco.

Relatórios:

```text
output\amsi\amsi_audit_*.json
output\amsi\amsi_audit_*.md
```

## 9. Modo Vermelho defensivo avançado

O Modo Vermelho é local, independente de alvo e totalmente operado pelo
terminal. Ele mede a capacidade defensiva do Windows; não desativa controles,
não implementa evasão, não cria persistência e não executa malware.

Execução rápida recomendada:

```powershell
.\.venv\Scripts\python.exe main.py --red-mode
```

Pelo assistente, execute `--interactive` e escolha a operação `red`.

Execução completa com criação de baseline:

```powershell
.\.venv\Scripts\python.exe main.py --red-mode `
  --red-profile full `
  --red-save-baseline
```

Comparar o estado atual com a baseline mais recente:

```powershell
.\.venv\Scripts\python.exe main.py --red-mode `
  --red-profile full `
  --red-compare-baseline
```

Comparar com uma baseline específica:

```powershell
.\.venv\Scripts\python.exe main.py --red-mode `
  --red-profile full `
  --red-compare-baseline C:\baselines\endpoint-aprovado.json
```

Perfis disponíveis:

| Perfil | Controles executados |
|---|---|
| `quick` | Integridade nativa, Defender essencial e proteções da plataforma |
| `amsi` | AMSI real, integridade de DLLs e comparação limpa AMSI/ETW |
| `defender` | Antivírus, nuvem, ASR, PUA, CFA, exclusões e assinaturas |
| `telemetry` | PowerShell logging, Event Logs, Sysmon e canários benignos |
| `persistence` | Run keys, Startup, tarefas, WMI, serviços e drivers |
| `impact` | Prevenção real do Defender, correlação de eventos e matriz ATT&CK |
| `full` | Todos os controles acima, incluindo impacto, e baseline/drift quando solicitado |

Exemplos por perfil:

```powershell
.\.venv\Scripts\python.exe main.py --red-mode --red-profile amsi
.\.venv\Scripts\python.exe main.py --red-mode --red-profile defender
.\.venv\Scripts\python.exe main.py --red-mode --red-profile telemetry
.\.venv\Scripts\python.exe main.py --red-mode --red-profile persistence
.\.venv\Scripts\python.exe main.py --red-mode --red-profile impact
```

### Prova de impacto defensivo

O perfil `impact` e o perfil `full` não se limitam a consultar configurações.
Eles executam uma cadeia de validação segura e atribuem um resultado objetivo:

- `BLOCKED`: o controle impediu ou removeu a atividade e existe evidência;
- `DETECTED`: a atividade ocorreu e foi observada na telemetria;
- `MISSED`: a atividade ocorreu, a fonte estava disponível, mas não houve evento;
- `NOT_OBSERVABLE`: a fonte necessária não está instalada, habilitada ou acessível;
- `BLOCKED_UNCONFIRMED`: houve bloqueio aparente sem evidência consultável;
- `ERROR`: o teste não pôde ser concluído.

Execução direta:

```powershell
ignotus red impact
```

A prova de prevenção usa o arquivo de teste antimalware EICAR, que é um
marcador padronizado e inerte. O arquivo nunca é executado. O Ignotus:

1. cria o marcador em uma pasta temporária exclusiva;
2. permite que a proteção em tempo real atue;
3. solicita uma verificação customizada ao Defender quando necessário;
4. procura eventos 1116, 1117, 1118 e 1119;
5. correlaciona o alerta pelo marcador único;
6. remove qualquer arquivo e diretório temporário restante;
7. mantém o alerta no histórico do Defender como evidência da validação.

A matriz de impacto também correlaciona os canários benignos com:

| Fonte | Eventos | Cobertura |
|---|---|---|
| PowerShell Operational | 4103 e 4104 | módulos e script blocks |
| Security | 4688 | criação de processo |
| Sysmon | 1 | criação de processo |
| Sysmon | 3 | conexão de rede em loopback |
| Sysmon | 11 | criação de arquivo |
| Sysmon | 12 e 13 | chave e valor de registro |
| Sysmon | 17 e 18 | criação e conexão de named pipe |
| Defender Operational | 1116–1119 | detecção e remediação antimalware |

Cada teste é associado a uma técnica ATT&CK quando aplicável e o relatório
calcula cobertura efetiva e taxa de detecção entre as fontes observáveis.

Diretório personalizado:

```powershell
.\.venv\Scripts\python.exe main.py --red-mode `
  --red-profile full `
  --red-output output\red\workstation-01
```

O núcleo defensivo em C# é compilado em memória pelo próprio PowerShell e:

- resolve `AmsiScanBuffer`, `AmsiScanString`, `EtwEventWrite` e `NtTraceEvent`;
- abre uma cópia limpa e somente leitura das DLLs com `SEC_IMAGE`;
- compara os primeiros bytes da função carregada com a imagem limpa;
- verifica proteção de memória gravável/executável;
- sinaliza prólogos incompatíveis com a imagem assinada;
- nunca altera memória, não faz unhook e não executa bypass.

O perfil `telemetry` e o `full` usam marcadores únicos e benignos para processo,
PowerShell, arquivo temporário, chave temporária em `HKCU`, TCP em `127.0.0.1`
e named pipe local. Arquivo, chave, sockets e pipe são removidos ao final.

Mapeamento operacional estrito de detecções do SIEM/EDR (carregado automaticamente; o `rule_id` só é válido após confirmação no produto):

```json
{
  "detections": {
    "RED-PROCESS-CANARY": {
      "status": "validated",
      "rule_id": "SIEM-WIN-PROCESS-001"
    }
  }
}
```

Uso:

```powershell
.\.venv\Scripts\python.exe main.py --red-mode `
  --red-profile telemetry `
  --red-detections config\red\detections.json
```

Saídas:

```text
output\red\red_mode_<perfil>_*.json
output\red\red_mode_<perfil>_*.md
output\red\baselines\latest.json
```

Componentes principais:

```text
core\red_mode\runner.py
core\red_mode\checks.py
core\red_mode\canaries.py
core\red_mode\baseline.py
core\red_mode\reporting.py
scripts\red_mode_snapshot.ps1
scripts\red_mode_event_check.ps1
scripts\red_mode_native_probe.ps1
scripts\red_mode_defender_impact.ps1
tools\redprobe\RedProbe.cs
```

## 10. Purple Team seguro

Perfil básico de telemetria:

```powershell
.\.venv\Scripts\python.exe main.py --purple-team `
  --purple-profile baseline
```

Perfil de rede somente em loopback:

```powershell
.\.venv\Scripts\python.exe main.py --purple-team `
  --purple-profile network
```

Todos os controles:

```powershell
.\.venv\Scripts\python.exe main.py --purple-team `
  --purple-profile all `
  --purple-detections config\purple\detections.json
```

Diretório personalizado:

```powershell
.\.venv\Scripts\python.exe main.py --purple-team `
  --purple-profile all `
  --purple-output output\purple\minha-execucao
```

Relatórios padrão:

```text
output\purple\purple_*.json
output\purple\purple_*.md
```

## 11. Módulos individuais

As opções abaixo devem ser combinadas com `--only-impact` e, quando ativas,
com um arquivo de escopo autorizado.

### Auditoria externa WSL

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --external-audit `
  --scope-file config\scopes\meu-escopo.txt
```

### Request smuggling

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --smuggling `
  --scope-file config\scopes\meu-escopo.txt
```

Um status HTTP `400` ou `5xx` isolado não é considerado evidência. Anomalias de
tempo precisam se repetir.

### SSRF

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --ssrf `
  --scope-file config\scopes\meu-escopo.txt
```

### Nuclei oficial

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --nuclei `
  --scope-file config\scopes\meu-escopo.txt `
  --scan-timeout 600
```

### Arquivos sensíveis e backups

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --fuzz-files `
  --scope-file config\scopes\meu-escopo.txt
```

### Swagger/OpenAPI

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --test-api `
  --scope-file config\scopes\meu-escopo.txt
```

### Caça a assets

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --hunt-assets `
  --download-dir output\sourcemaps\example
```

### Screenshot headless

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --screenshot
```

### Wayback

```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact `
  --wayback
```

### GitHub dorking

```powershell
$env:IGNOTUS_GITHUB_TOKEN = 'TOKEN_AQUI'
.\.venv\Scripts\python.exe main.py "example.com" --only-impact `
  --github-dork `
  --github-token $env:IGNOTUS_GITHUB_TOKEN
Remove-Item Env:\IGNOTUS_GITHUB_TOKEN
```

Não coloque tokens diretamente no arquivo `COMANDOS.md`.

### Comparação histórica

```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact `
  --diff
```

### Teste de disponibilidade Werkzeug

Somente quando houver autorização específica para indisponibilidade:

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --werkzeug-dos `
  --scope-file config\scopes\meu-escopo.txt
```

Essa opção permanece separada de `--full`.

## 12. Autenticação e proxy

Cookie de sessão:

```powershell
$env:IGNOTUS_SESSION = 'VALOR_DO_COOKIE'
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --hunt-assets `
  --auth-cookie "session=$env:IGNOTUS_SESSION"
Remove-Item Env:\IGNOTUS_SESSION
```

Bearer token:

```powershell
$env:IGNOTUS_TOKEN = 'TOKEN_AQUI'
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --test-api `
  --scope-file config\scopes\meu-escopo.txt `
  --auth-header "Authorization:Bearer $env:IGNOTUS_TOKEN"
Remove-Item Env:\IGNOTUS_TOKEN
```

Proxy HTTP:

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --proxy http://127.0.0.1:8080
```

Proxy SOCKS5:

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact `
  --proxy socks5://127.0.0.1:9050
```

## 13. Source maps

Extração standalone:

```powershell
.\.venv\Scripts\python.exe main.py `
  --source-map "https://example.com/static/app.js.map" `
  --download-dir output\sourcemaps\example
```

Pesquisar referências depois da extração:

```powershell
rg -n -i "api[_-]?key|secret|token|password|authorization" `
  output\sourcemaps\example
```

## 14. Motor, desempenho e retomada

Selecionar motor:

```powershell
# Automático: Go com fallback Python
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --engine auto

# Exigir Go
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --engine go

# Exigir Python
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --engine python
```

Limitar concorrência e taxa:

```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact `
  --workers 4 `
  --rate-limit 1 `
  --scan-timeout 600
```

Retomar checkpoint:

```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --resume
```

Checkpoint personalizado:

```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact `
  --checkpoint-file output\checkpoints\example-custom.json
```

Desabilitar checkpoint:

```powershell
.\.venv\Scripts\python.exe main.py "example.com" --only-impact --no-checkpoint
```

Pular port scan:

```powershell
.\.venv\Scripts\python.exe main.py "example.com:443" --only-impact --no-portscan
```

## 15. Nuclei gerenciado pelo projeto

Versão instalada:

```powershell
.\tools\bin\nuclei.exe -version
```

Instalar ou atualizar o binário:

```powershell
$env:IGNOTUS_GOBIN = "$PWD\tools\bin"
$env:GOBIN = $env:IGNOTUS_GOBIN
& 'C:\Program Files\Go\bin\go.exe' install `
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
Remove-Item Env:\GOBIN
Remove-Item Env:\IGNOTUS_GOBIN
```

Atualizar templates oficiais:

```powershell
.\tools\bin\nuclei.exe -update-templates
```

O adaptador Ignotus usa taxa conservadora, baixa concorrência e exclui tags de
DoS, fuzzing intrusivo e brute force. Registros JSONL completos são preservados
mesmo se o processo alcançar o timeout.

## 16. Kali WSL

Listar distribuição:

```powershell
wsl.exe --list --verbose
```

Verificar ferramentas:

```powershell
wsl.exe -d kali-linux -- bash -lc `
  "command -v nmap; command -v httpx; command -v nikto; command -v sslscan; command -v ffuf; command -v gobuster; command -v curl; command -v openssl"
```

O uso normal deve ocorrer por `--external-audit`, para que o Ignotus centralize
e deduplique as evidências.

## 17. Testes e build

Todos os testes Python:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Testes Go:

```powershell
Push-Location engine\go
& 'C:\Program Files\Go\bin\go.exe' test ./...
Pop-Location
```

Checagem de erros críticos:

```powershell
.\.venv\Scripts\python.exe -m ruff check main.py core tests `
  --select E9,F63,F7,F82
```

Recompilar o motor Go:

```powershell
.\build_engine.bat
```

## 18. Saídas

```text
database\ingotus.db
evidence\<alvo>\<host>\
output\json\*_results.json
output\json\*_asset_graph.json
output\markdown\report_*.md
output\markdown\report_*.html
output\checkpoints\*.json
output\sourcemaps\
output\purple\
output\amsi\
output\red\
output\authorized-impact\
output\vps-advanced\
```

Listar relatórios recentes:

```powershell
Get-ChildItem output -Recurse -File |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 20 FullName,Length,LastWriteTime
```

## 19. Diagnóstico rápido

Confirmar motor Go:

```powershell
Test-Path .\bin\ignotus-engine.exe
```

Confirmar Nuclei:

```powershell
Test-Path .\tools\bin\nuclei.exe
```

Confirmar Kali WSL:

```powershell
wsl.exe -d kali-linux -- uname -a
```

Verificar DNS e porta sem iniciar scan:

```powershell
Resolve-DnsName example.com -Type A
Test-NetConnection example.com -Port 443
```

Consultar logs locais:

```powershell
Get-ChildItem logs -File -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 5
```

## 20. Referência compacta de opções

| Opção | Função |
|---|---|
| `--interactive`, `-i` | Assistente interativo do terminal |
| `--only-impact` | Executa modo focado em achados |
| `--full` | Perfil avançado completo autorizado |
| `--scope-file FILE` | Regras de escopo obrigatórias para módulos ativos |
| `--engine auto|python|go` | Seleciona o motor de preflight |
| `--workers N` | Número de pipelines concorrentes |
| `--rate-limit N` | Pipelines iniciados por segundo |
| `--scan-timeout N` | Prazo global em segundos |
| `--no-portscan` | Pula o scan geral de portas |
| `--proxy URL` | Proxy HTTP ou SOCKS5 |
| `--hunt-assets` | Assets, configurações e source maps |
| `--source-map URL` | Extração standalone de source map |
| `--auth-cookie NAME=VALUE` | Cookie para fluxos autenticados |
| `--auth-header NAME:VALUE` | Header para fluxos autenticados |
| `--download-dir DIR` | Destino de assets/source maps |
| `--smuggling` | Validação CL.TE, TE.CL, TE.TE e CL.0 |
| `--ssrf` | Validação SSRF com confirmação disponível |
| `--nuclei` | Templates oficiais Nuclei |
| `--external-audit` | Nmap/sslscan via Kali WSL |
| `--fuzz-files` | Arquivos sensíveis e backups |
| `--test-api` | Swagger/OpenAPI |
| `--screenshot` | Captura headless |
| `--werkzeug-dos` | Teste de disponibilidade explícito e separado |
| `--wayback` | Histórico do Wayback |
| `--github-dork` | Busca pública no GitHub |
| `--github-token TOKEN` | Token GitHub; prefira variável de ambiente |
| `--diff` | Comparação com histórico |
| `--resume` | Retoma checkpoint compatível |
| `--checkpoint-file FILE` | Checkpoint personalizado |
| `--no-checkpoint` | Desabilita checkpoint |
| `--purple-team` | Purple Team benigno local |
| `--purple-profile` | `baseline`, `network` ou `all` |
| `--purple-detections FILE` | Mapeamento de regras EDR/SIEM/NDR |
| `--purple-output DIR` | Destino Purple Team |
| `--amsi-audit` | Auditoria AMSI/Defender nativa |
| `--amsi-output DIR` | Destino dos relatórios AMSI |
| `--red-mode` | Validação defensiva avançada local do Windows |
| `--red-profile` | `quick`, `amsi`, `defender`, `telemetry`, `persistence`, `impact` ou `full` |
| `--red-output DIR` | Destino dos relatórios do Modo Vermelho |
| `--red-detections FILE` | Substitui a política estrita operacional de canários |
| `--red-save-baseline` | Salva o estado estável atual como baseline |
| `--red-compare-baseline [FILE]` | Compara o endpoint com a baseline |
