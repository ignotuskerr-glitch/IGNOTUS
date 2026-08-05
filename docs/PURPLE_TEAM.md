# Purple Team seguro

O modo Purple Team do Ignotus valida a geração de telemetria por meio de ações
locais benignas. Ele não contém malware, bypass de EDR/AMSI/ETW, persistência,
injeção, execução furtiva em memória ou comunicação de comando e controle.

## Uso no terminal

```powershell
python main.py --purple-team --purple-profile baseline
python main.py --purple-team --purple-profile network
python main.py --purple-team --purple-profile all
```

`baseline` executa canários de sistema, processo, arquivo, compactação e conteúdo
codificado sem execução. `network` usa exclusivamente loopback (`localhost` e
`127.0.0.1`) para DNS, TCP e HTTP. `all` combina os dois perfis.

## Cobertura de detecção

Passe um arquivo JSON para associar cada simulação a uma regra do EDR, SIEM ou
NDR:

```powershell
python main.py --purple-team --purple-profile all `
  --purple-detections config/purple/detections.json
```

Estados `detected`, `validated` e `covered` contam como cobertura validada.
`planned` identifica uma regra planejada, mas ainda não comprovada. A ausência de
mapeamento aparece como `not_configured`, evitando afirmar detecção sem evidência.

## Segurança operacional

- Todo tráfego de simulação permanece no próprio computador.
- Arquivos e ZIPs são criados em diretório temporário e removidos.
- O processo filho apenas imprime o marcador `IGNOTUS_PURPLE_TEAM_CANARY`.
- Conteúdo Base64 é decodificado como texto e nunca executado.
- Os relatórios registram execução e cobertura como dimensões separadas.
