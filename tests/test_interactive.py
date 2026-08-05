import pytest

from core import interactive
from core.cli import build_parser


def test_interactive_can_exit_before_any_scan(monkeypatch):
    monkeypatch.setattr(interactive.console, "input", lambda *args, **kwargs: "exit")

    args = build_parser().parse_args(["--interactive"])
    with pytest.raises(SystemExit) as exc:
        interactive.configure_interactively(args)
    assert exc.value.code == 0


def test_interactive_accepts_compact_impact_command(monkeypatch):
    monkeypatch.setattr(
        interactive.console,
        "input",
        lambda *args, **kwargs: (
            "impact example.com --workers 10 --rate-limit 5 --scan-timeout 300"
        ),
    )

    args = build_parser().parse_args(["--interactive"])
    configured = interactive.configure_interactively(args)

    assert configured.target == "example.com"
    assert configured.only_impacts
    assert not configured.full
    assert configured.workers == 10
    assert configured.rate_limit == 5
    assert configured.scan_timeout == 300
    assert configured.compact_ui


def test_interactive_can_configure_red_mode(monkeypatch):
    monkeypatch.setattr(
        interactive.console,
        "input",
        lambda *args, **kwargs: "red full --red-save-baseline",
    )

    args = build_parser().parse_args(["--interactive"])
    configured = interactive.configure_interactively(args)

    assert configured.red_mode
    assert configured.red_profile == "full"
    assert configured.red_save_baseline
    assert configured.target is None
    assert configured.compact_ui


def test_console_command_keeps_full_scope_requirement(tmp_path):
    scope_file = tmp_path / "scope file.txt"
    scope_file.write_text("in: example.com\n", encoding="utf-8")
    parsed = interactive._parse_console_command(
        f'full example.com --scope-file "{scope_file}"'
    )

    assert parsed is not None
    assert parsed.full
    assert parsed.scope_file == str(scope_file)
