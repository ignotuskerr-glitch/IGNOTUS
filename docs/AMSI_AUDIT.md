# Ignotus Advanced AMSI Audit

## Execução

```powershell
python main.py --amsi-audit
python main.py --amsi-audit --amsi-output output/amsi
```

O comando é um modo local independente. Ele não aceita alvo, `--full` ou
`--only-impact` na mesma execução.

## Validações reais

- Assinatura Authenticode e versão de `%WINDIR%\System32\amsi.dll`.
- Provedores registrados em `HKLM\SOFTWARE\Microsoft\AMSI\Providers`.
- Estado do serviço antimalware, antivírus, proteção em tempo real e monitor
  comportamental do Microsoft Defender.
- Chamada nativa `AmsiInitialize`, `AmsiOpenSession` e `AmsiScanString`.
- Controle negativo com conteúdo benigno.
- Controle positivo com marcador industrial inerte mantido apenas em memória.
- Estado de Script Block Logging e Module Logging do PowerShell.

## Interpretação

`PASS` significa que o controle foi observado diretamente. `WARN` é um gap de
telemetria ou endurecimento. `FAIL` indica que um controle obrigatório não foi
confirmado. Os relatórios JSON e Markdown mantêm valores nativos e o resumo.

O modo não desabilita controles, não altera o registro, não cria persistência e
não grava o marcador de teste em disco.
