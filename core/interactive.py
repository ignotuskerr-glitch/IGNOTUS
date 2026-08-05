"""Compact command console used when Ignotus starts without arguments."""

from __future__ import annotations

import argparse
import getpass
import os
import shlex
import socket
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.rule import Rule
from rich.text import Text

from core.cli import build_parser, normalize_terminal_aliases
from core.config import BASE_DIR, VERSION

console = Console()

_LAUNCHER_LOGO = r"""
 ██╗ ██████╗ ███╗   ██╗ ██████╗ ████████╗██╗   ██╗███████╗
 ██║██╔════╝ ████╗  ██║██╔═══██╗╚══██╔══╝██║   ██║██╔════╝
 ██║██║  ███╗██╔██╗ ██║██║   ██║   ██║   ██║   ██║███████╗
 ██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║   ██║╚════██║
 ██║╚██████╔╝██║ ╚████║╚██████╔╝   ██║   ╚██████╔╝███████║
 ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝
""".strip("\n")

_HELP = """[bold white]COMANDOS[/bold white]
  [bright_red]impact[/bright_red] ALVO [opções]                     scan focado em impactos
  [bright_red]full[/bright_red] ALVO --scope-file ARQUIVO [opções] scan completo autorizado
  [bright_red]scan[/bright_red] ALVO --only-impact [opções]        sintaxe explícita
  [bright_red]red[/bright_red] [quick|impact|full]                 validação defensiva local
  [bright_red]purple[/bright_red] [baseline|network|all]           simulação Purple Team local
  [bright_red]amsi[/bright_red]                                    auditoria AMSI defensiva
  [bright_red]help[/bright_red]                                    mostrar esta ajuda
  [bright_red]exit[/bright_red]                                    sair

[dim]Exemplos:[/dim]
  impact example.com --workers 20
  full example.com --scope-file config/scopes/example.txt
  red impact
"""


def _engine_status() -> tuple[str, str]:
    candidates = (
        Path(BASE_DIR, "bin", "ignotus-engine.exe"),
        Path(BASE_DIR, "bin", "ignotus-engine"),
    )
    if any(path.is_file() for path in candidates):
        return "READY", "Go engine available"
    return "FALLBACK", "Python engine available"


def _scope_count() -> int:
    scope_dir = Path(BASE_DIR, "config", "scopes")
    return len(tuple(scope_dir.glob("*.txt"))) if scope_dir.is_dir() else 0


def _status_line(label: str, detail: str, *, warning: bool = False) -> None:
    marker = "!" if warning else "+"
    style = "bold yellow" if warning else "bold green"
    console.print(f" [{style}][{marker}][/{style}] [dim]{label:<18}[/dim] {detail}")


def print_launcher() -> None:
    """Render one compact dashboard before accepting a command."""
    if console.is_terminal and not os.getenv("IGNOTUS_NO_CLEAR"):
        console.clear()

    console.print(Text(_LAUNCHER_LOGO, style="bold bright_red"), soft_wrap=True)
    console.print(
        f"[dim]v{VERSION}[/dim]  [bright_red]terminal-first[/bright_red]"
        "  [dim]recon · validate · document[/dim]"
    )
    console.print(Rule(style="red"))

    engine_state, engine_detail = _engine_status()
    _status_line("runtime", f"Python {sys.version_info.major}.{sys.version_info.minor}")
    _status_line("network engine", engine_detail, warning=engine_state != "READY")
    _status_line("profiles", f"{_scope_count()} authorized scope file(s) found")
    _status_line("workspace", str(BASE_DIR))

    console.print(Rule(style="dim red"))
    console.print(f" [dim]SESSION[/dim]   {datetime.now().astimezone():%Y-%m-%d %H:%M:%S %Z}")
    console.print(f" [dim]OPERATOR[/dim]  {getpass.getuser()}@{socket.gethostname()}")
    console.print(f" [dim]ENGINE[/dim]    {engine_state}")
    console.print(" [dim]STATE[/dim]     [bold green]READY[/bold green]")
    console.print(Rule(style="dim red"))
    console.print(
        " [dim]impact <target>[/dim]  ·  [dim]full <target> --scope-file <file>[/dim]"
        "  ·  [dim]red impact[/dim]  ·  [dim]help[/dim]\n"
    )


def _split_command(command: str) -> list[str]:
    # On Windows, posix=False preserves backslashes in paths. Strip the quote
    # characters retained by shlex in that mode. WSL/Linux use normal POSIX rules.
    tokens = shlex.split(command, posix=os.name != "nt")
    if os.name == "nt":
        tokens = [
            token[1:-1]
            if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}
            else token
            for token in tokens
        ]
    return tokens


def _expand_console_command(tokens: list[str]) -> list[str] | None:
    """Translate terminal-friendly verbs to the canonical CLI syntax."""
    if not tokens:
        return None

    verb = tokens[0].lower()
    rest = tokens[1:]
    if verb == "scan":
        return rest
    if verb in {"impact", "impacto", "impactos"}:
        return [*rest, "--only-impact"]
    if verb in {"full", "completo"}:
        return [*rest, "--full"]
    if verb in {"red", "vermelho"}:
        return normalize_terminal_aliases(tokens)
    if verb == "purple":
        profile = rest[0].lower() if rest else "baseline"
        trailing = rest[1:] if rest else []
        return ["--purple-team", "--purple-profile", profile, *trailing]
    if verb == "amsi":
        return ["--amsi-audit", *rest]
    # Allow pasting the normal direct CLI syntax without a leading `scan`.
    return tokens


def _parse_console_command(command: str) -> argparse.Namespace | None:
    try:
        tokens = _split_command(command)
    except ValueError as exc:
        console.print(f"[bold red][-][/bold red] comando inválido: {exc}")
        return None

    if not tokens:
        return None
    verb = tokens[0].lower()
    if verb in {"exit", "quit", "sair"}:
        console.print("[dim]session closed[/dim]")
        raise SystemExit(0)
    if verb in {"help", "ajuda", "?"}:
        console.print(_HELP)
        return None
    if verb in {"clear", "cls", "limpar"}:
        console.clear()
        print_launcher()
        return None

    argv = _expand_console_command(tokens)
    if not argv:
        return None

    parser = build_parser()
    try:
        parsed = parser.parse_args(argv)
    except SystemExit:
        console.print(
            "[bold red][-][/bold red] sintaxe inválida. Digite [bold]help[/bold] "
            "para exemplos curtos."
        )
        return None

    parsed.interactive = True
    parsed.compact_ui = True
    return parsed


def configure_interactively(args: argparse.Namespace) -> argparse.Namespace:
    """Open the terminal-first launcher and return the selected operation."""
    del args  # the launcher builds a clean namespace from the entered command
    print_launcher()
    while True:
        try:
            command = console.input(
                "[bold bright_red]ignotus[/bold bright_red] [dim]›[/dim] "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]session closed[/dim]")
            raise SystemExit(0) from None
        parsed = _parse_console_command(command)
        if parsed is not None:
            console.print("\n[bold green][+][/bold green] command accepted · starting\n")
            return parsed
