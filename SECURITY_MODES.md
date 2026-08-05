# Modos seguros de operação

- **Passivo:** providers públicos, CT, Wayback e análise local de arquivos já obtidos.
- **Ativo seguro:** DNS, HTTP/TLS e coleta limitada, sempre respeitando escopo.
- **Ativo intrusivo:** SSRF, smuggling, Nuclei, fuzzing e testes de API. Exigem
  autorização e `--scope-file`; nunca devem ser usados fora das regras do programa.

O Ignotus exige um modo explícito para iniciar um alvo:

- `--only-impacts` (`--only-impact`): perfil focado e saída apenas com achados;
- `--full`: módulos avançados e arquivo de escopo obrigatório.

O teste de DoS do Werkzeug nunca é herdado por esses modos. Ele só pode ser
habilitado explicitamente com `--werkzeug-dos` e sempre exige `--scope-file`.

Em infraestrutura compartilhada, como plataformas serverless e CDNs, não execute
testes de carga ou disponibilidade: a autorização da aplicação não implica
propriedade da infraestrutura subjacente.

Uma source map pública é registrada como `INFO`. Um padrão semelhante a segredo é
um candidato e só deve ser reportado como vulnerabilidade após validação inócua,
redigida e permitida pelo programa.
