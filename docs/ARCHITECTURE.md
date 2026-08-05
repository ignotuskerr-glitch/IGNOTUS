# Arquitetura do Ignotus

## Camadas

```text
main.py
├── core/cli.py                 modos e validação
├── core/interactive.py         terminal guiado
├── core/runtime/               cancelamento, limites e checkpoint
├── core/engines/               adaptadores de motores externos
├── core/reporting/             deduplicação e grafo de ativos
├── core/                       analisadores Python
├── providers/                  descoberta passiva extensível
└── engine/go/                  preflight concorrente DNS/HTTP/TCP
```

## Fronteira Python/Go

O Python envia uma requisição JSON por linha para o processo
`bin/ignotus-engine.exe`. O motor valida DNS, CNAME, conectividade TCP e HTTP e
devolve uma resposta JSON por host. Não existe interpolação de shell nem FFI. Se
o motor falhar no modo `auto`, o pipeline Python assume o trabalho.

## Segurança operacional

- Nenhum alvo inicia sem `--full` ou `--only-impacts`.
- Módulos intrusivos exigem arquivo de escopo existente.
- O arquivo de escopo é aplicado antes da fase ativa.
- Testes de disponibilidade nunca são herdados de `--full`.
- Checkpoints não armazenam corpo HTTP, headers de autenticação ou snippets crus.
- Escritas de checkpoint são atômicas e permitem retomada após interrupção.

## Saídas

- SQLite: histórico relacional de scans.
- JSON: resultado sanitizado e grafo de ativos.
- Markdown/HTML: relatórios para leitura humana.
- Checkpoint: estado incremental por alvo.
- Evidências: arquivos por host e impacto.

## Desenvolvimento

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\build_engine.bat
```
