"""Command-line parsing and safety validation for Ignotus Recon."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence

from core.config import DEFAULT_WORKERS

MAX_WORKERS = 128
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _default_detection_file(mode: str) -> str:
    return os.path.join(PROJECT_ROOT, "config", mode, "detections.json")

INTRUSIVE_FLAGS = {
    "--smuggling": "smuggling",
    "--ssrf": "ssrf",
    "--nuclei": "nuclei",
    "--fuzz-files": "fuzz_files",
    "--test-api": "test_api",
    "--external-audit": "external_audit",
    "--werkzeug-dos": "werkzeug_dos",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ignotus",
        description="Ignotus Recon — Security Impact Validator for Pentest / Bug Bounty / Red Team",
        epilog=(
            "Shortcuts: 'ignotus' opens the interactive terminal; "
            "'ignotus red [quick|amsi|defender|telemetry|persistence|impact|full]' "
            "starts Defensive Red Mode."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        help=(
            "Target to scan: domain, wildcard, IP, URL, or host:port. "
            "Optional with --interactive or --source-map."
        ),
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Open the guided interactive terminal",
    )
    parser.add_argument(
        "--purple-team",
        action="store_true",
        help="Run local, benign Purple Team telemetry simulations (no malware/evasion)",
    )
    parser.add_argument(
        "--purple-profile",
        choices=("baseline", "network", "all"),
        default="baseline",
        help="Purple Team simulation profile (default: baseline)",
    )
    parser.add_argument(
        "--purple-detections",
        default=None,
        metavar="FILE",
        help="Operational strict JSON mapping; defaults to config/purple/detections.json",
    )
    parser.add_argument(
        "--purple-output",
        default="output/purple",
        metavar="DIR",
        help="Purple Team report directory (default: output/purple)",
    )
    parser.add_argument(
        "--amsi-audit",
        action="store_true",
        help="Run the advanced defensive Windows AMSI validation mode",
    )
    parser.add_argument(
        "--amsi-output",
        default="output/amsi",
        metavar="DIR",
        help="AMSI audit report directory (default: output/amsi)",
    )
    parser.add_argument(
        "--red-mode",
        action="store_true",
        help="Run advanced local defensive endpoint validation",
    )
    parser.add_argument(
        "--red-profile",
        choices=(
            "quick",
            "amsi",
            "defender",
            "telemetry",
            "persistence",
            "impact",
            "full",
        ),
        default="quick",
        help="Red Mode defensive profile (default: quick)",
    )
    parser.add_argument(
        "--red-output",
        default="output/red",
        metavar="DIR",
        help="Red Mode report directory (default: output/red)",
    )
    parser.add_argument(
        "--red-detections",
        default=None,
        metavar="FILE",
        help="Operational strict JSON mapping; defaults to config/red/detections.json",
    )
    parser.add_argument(
        "--red-save-baseline",
        action="store_true",
        help="Save the current stable endpoint state as the latest baseline",
    )
    parser.add_argument(
        "--red-compare-baseline",
        nargs="?",
        const="output/red/baselines/latest.json",
        default=None,
        metavar="FILE",
        help="Compare with a baseline (default: output/red/baselines/latest.json)",
    )
    parser.add_argument("--no-portscan", action="store_true", help="Skip port scanning")
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Concurrent scanning threads (default: {DEFAULT_WORKERS}, max: {MAX_WORKERS})",
    )
    parser.add_argument(
        "--only-impacts",
        "--only-impact",
        dest="only_impacts",
        action="store_true",
        help=(
            "Run the impact-focused mode and only print hosts with findings; "
            "does not authorize availability tests"
        ),
    )
    parser.add_argument("--proxy", type=str, default=None, help="HTTP/SOCKS proxy")
    parser.add_argument(
        "--hunt-assets",
        action="store_true",
        help="Search for exposed source maps, configs, schemas and backups",
    )
    parser.add_argument("--source-map", type=str, default=None, metavar="URL")
    parser.add_argument("--auth-cookie", type=str, default=None, metavar="NAME=VALUE")
    parser.add_argument("--auth-header", type=str, default=None, metavar="NAME:VALUE")
    parser.add_argument(
        "--download-dir",
        type=str,
        default="output/sourcemaps",
        help="Directory used for downloaded source maps and assets",
    )
    parser.add_argument("--smuggling", action="store_true")
    parser.add_argument("--ssrf", action="store_true")
    parser.add_argument("--nuclei", action="store_true")
    parser.add_argument("--fuzz-files", action="store_true")
    parser.add_argument("--test-api", action="store_true")
    parser.add_argument("--screenshot", action="store_true")
    parser.add_argument(
        "--external-audit",
        action="store_true",
        help="Run conservative Nmap/sslscan validation through Kali WSL",
    )
    parser.add_argument(
        "--werkzeug-dos",
        action="store_true",
        help=(
            "Explicitly enable the intrusive Werkzeug multipart DoS validation. "
            "Requires --scope-file."
        ),
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Enable the complete advanced profile; requires --scope-file",
    )
    parser.add_argument("--wayback", action="store_true")
    parser.add_argument("--github-dork", action="store_true")
    parser.add_argument(
        "--github-token",
        type=str,
        default=os.getenv("IGNOTUS_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN"),
        metavar="TOKEN"
    )
    parser.add_argument("--scope-file", type=str, default=None, metavar="FILE")
    parser.add_argument("--diff", action="store_true")
    parser.add_argument(
        "--engine",
        choices=("auto", "python", "go"),
        default="auto",
        help="Network preflight engine (default: auto)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=10.0,
        metavar="HOSTS/S",
        help="Maximum number of host pipelines started per second",
    )
    parser.add_argument(
        "--scan-timeout",
        type=float,
        default=900.0,
        metavar="SECONDS",
        help="Global scan deadline (default: 900 seconds)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume completed hosts from a compatible checkpoint",
    )
    parser.add_argument(
        "--checkpoint-file",
        default=None,
        metavar="FILE",
        help="Custom checkpoint path",
    )
    parser.add_argument(
        "--no-checkpoint",
        action="store_true",
        help="Disable incremental checkpoint persistence",
    )
    return parser


def apply_full_mode(args: argparse.Namespace) -> argparse.Namespace:
    """Expand --full into its concrete module flags."""
    if not args.full:
        return args

    for name in (
        "wayback",
        "github_dork",
        "hunt_assets",
        "fuzz_files",
        "test_api",
        "smuggling",
        "ssrf",
        "nuclei",
        "screenshot",
        "external_audit",
        "diff",
    ):
        setattr(args, name, True)
    return args


def enabled_intrusive_options(args: argparse.Namespace) -> list[str]:
    return [
        flag for flag, attr in INTRUSIVE_FLAGS.items() if getattr(args, attr, False)
    ]


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.red_mode:
        if (
            args.source_map
            or args.full
            or args.only_impacts
            or args.purple_team
            or args.amsi_audit
        ):
            parser.error(
                "--red-mode cannot be combined with other scan/local modes"
            )
        if args.red_detections and not os.path.isfile(args.red_detections):
            parser.error(f"detection mapping not found: {args.red_detections}")
        if args.red_compare_baseline and not os.path.isfile(args.red_compare_baseline):
            parser.error(f"baseline not found: {args.red_compare_baseline}")
        return

    if args.red_save_baseline or args.red_compare_baseline or args.red_detections:
        parser.error(
            "--red-save-baseline, --red-compare-baseline and --red-detections require --red-mode"
        )

    if args.amsi_audit:
        if (
            args.target
            or args.source_map
            or args.full
            or args.only_impacts
            or args.purple_team
        ):
            parser.error(
                "--amsi-audit é um modo local independente; não combine com alvo/scan"
            )
        return

    if args.purple_team:
        if args.target or args.source_map or args.full or args.only_impacts:
            parser.error(
                "--purple-team é um modo local independente; não combine com alvo/scan"
            )
        if args.purple_detections and not os.path.isfile(args.purple_detections):
            parser.error(
                f"arquivo de detecções não encontrado: {args.purple_detections}"
            )
        return

    if not args.target and not args.source_map:
        parser.error("informe um alvo ou use --interactive")

    if not 1 <= args.workers <= MAX_WORKERS:
        parser.error(f"--workers deve estar entre 1 e {MAX_WORKERS}")

    if args.target and not (args.full or args.only_impacts):
        parser.error("selecione um modo de execuÃ§Ã£o: --full ou --only-impacts")

    if args.full and args.only_impacts:
        parser.error("use apenas um modo: --full ou --only-impacts")

    if not 0.1 <= args.rate_limit <= 1000:
        parser.error("--rate-limit deve estar entre 0.1 e 1000 hosts/s")

    if not 1 <= args.scan_timeout <= 86400:
        parser.error("--scan-timeout deve estar entre 1 e 86400 segundos")

    if args.scope_file and not os.path.isfile(args.scope_file):
        parser.error(f"arquivo de escopo não encontrado: {args.scope_file}")


InteractiveConfigurer = Callable[[argparse.Namespace], argparse.Namespace]


def normalize_terminal_aliases(argv: Sequence[str]) -> list[str]:
    """Translate concise terminal commands into the canonical flags."""
    tokens = list(argv)
    if not tokens:
        return ["--interactive"]
    command = tokens[0].lower()
    if command in {"menu", "interactive", "interativo"}:
        return ["--interactive", *tokens[1:]]
    if command in {"red", "vermelho"}:
        remaining = tokens[1:]
        if remaining and remaining[0].lower() in {
            "quick",
            "amsi",
            "defender",
            "telemetry",
            "persistence",
            "impact",
            "full",
        }:
            return [
                "--red-mode",
                "--red-profile",
                remaining[0].lower(),
                *remaining[1:],
            ]
        return ["--red-mode", *remaining]
    return tokens


def parse_cli_args(
    argv: Sequence[str] | None = None,
    interactive_configurer: InteractiveConfigurer | None = None,
) -> tuple[argparse.Namespace, argparse.ArgumentParser]:
    parser = build_parser()
    raw_argv = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(normalize_terminal_aliases(raw_argv))

    if args.interactive:
        if interactive_configurer is None:
            from core.interactive import configure_interactively

            interactive_configurer = configure_interactively
        args = interactive_configurer(args)

    if args.red_mode and not args.red_detections:
        args.red_detections = _default_detection_file("red")
    if args.purple_team and not args.purple_detections:
        args.purple_detections = _default_detection_file("purple")

    apply_full_mode(args)
    validate_args(parser, args)
    return args, parser
