from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.red_mode.models import RedRun
from core.redaction import redact_text


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _payload(run: RedRun) -> dict[str, Any]:
    return _redact(
        {
            "schema_version": 1,
            "mode": "defensive-red-mode",
            "safety": "Local defensive validation only; no bypass, evasion, persistence or malware.",
            "profile": run.profile,
            "generated_at": run.generated_at,
            "summary": run.summary,
            "checks": [check.to_dict() for check in run.checks],
            "drift": run.drift,
            "baseline_path": run.baseline_path,
            "canaries": run.canaries,
            "impact": run.impact,
            "native_probe": run.native_probe,
            "snapshot": run.snapshot,
        }
    )


def _markdown(run: RedRun) -> str:
    summary = run.summary
    lines = [
        "# Ignotus — Advanced Defensive Red Mode",
        "",
        f"- Perfil: `{run.profile}`",
        f"- Gerado em: `{run.generated_at}`",
        f"- Pontuação de postura: **{summary['score']}/100**",
        f"- Resultado: {summary['PASS']} PASS · {summary['WARN']} WARN · {summary['FAIL']} FAIL · {summary['INFO']} INFO",
        "- Segurança operacional: somente validação defensiva local; sem evasão, persistência ou malware.",
        "",
        "## Verificações",
        "",
        "| Estado | Categoria | Controle | Resultado |",
        "|---|---|---|---|",
    ]
    for check in run.checks:
        detail = redact_text(check.detail).replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {check.status} | {check.category} | `{check.id}` — {check.title} | {detail} |"
        )
        if check.recommendation:
            recommendation = (
                redact_text(check.recommendation).replace("|", "\\|").replace("\n", " ")
            )
            lines.append(f"|  |  | Recomendação | {recommendation} |")

    lines.extend(["", "## Drift de baseline", ""])
    if run.drift:
        lines.append(f"Foram detectadas **{len(run.drift)}** alterações estáveis:")
        lines.append("")
        for item in run.drift[:100]:
            lines.append(f"- `{item.get('change')}` em `{item.get('path')}`")
    elif run.baseline_path:
        lines.append(
            "Nenhuma alteração estável detectada em relação à baseline informada."
        )
    else:
        lines.append("Comparação não solicitada.")

    lines.extend(["", "## Canários benignos", ""])
    if run.canaries:
        lines.append(f"- Marcador: `{run.canaries.get('marker')}`")
        lines.append(f"- Limpeza: {run.canaries.get('cleanup')}")
        lines.append(f"- Ações locais: {len(run.canaries.get('actions') or {})}")
        lines.append(f"- Eventos consultados: {len(run.canaries.get('events') or [])}")
    else:
        lines.append("Não executados neste perfil.")

    lines.extend(["", "## Impacto defensivo comprovado", ""])
    if run.impact:
        impact_summary = run.impact.get("summary") or {}
        lines.append(
            f"- Cobertura efetiva: **{impact_summary.get('effective_coverage_percent', 0)}%**"
        )
        lines.append(
            f"- Taxa de detecção observável: **{impact_summary.get('observable_detection_rate_percent', 0)}%**"
        )
        lines.append(
            f"- BLOCKED={impact_summary.get('BLOCKED', 0)} · DETECTED={impact_summary.get('DETECTED', 0)} · "
            f"MISSED={impact_summary.get('MISSED', 0)} · NOT_OBSERVABLE={impact_summary.get('NOT_OBSERVABLE', 0)}"
        )
        lines.append("")
        lines.append("| Teste | ATT&CK | Estado | Sinais observados |")
        lines.append("|---|---|---|---|")
        for item in run.impact.get("matrix") or []:
            signals = ", ".join(item.get("observed_signals") or []) or "—"
            lines.append(
                f"| `{item.get('id')}` | {item.get('attack_id') or '—'} | **{item.get('state')}** | {signals} |"
            )
        defender = run.impact.get("defender") or {}
        lines.append("")
        lines.append(
            f"O marcador EICAR era inerte, não foi executado e terminou com `cleaned={defender.get('cleaned')}`."
        )
    else:
        lines.append("Não executado neste perfil.")
    lines.append("")
    return "\n".join(lines)


def write_reports(run: RedRun, output_dir: str | Path) -> tuple[str, str]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = (destination / f"red_mode_{run.profile}_{stamp}.json").resolve()
    markdown_path = (destination / f"red_mode_{run.profile}_{stamp}.md").resolve()
    json_path.write_text(
        json.dumps(_payload(run), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    markdown_path.write_text(_markdown(run), encoding="utf-8")
    return str(json_path), str(markdown_path)
