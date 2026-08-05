from io import BytesIO, StringIO, TextIOWrapper

from rich.console import Console

from core import logger
from core.models import HostResult, Impact


def test_banner_contains_identity_and_red_team_context(monkeypatch):
    output = StringIO()
    test_console = Console(file=output, force_terminal=False, width=100)
    monkeypatch.setattr(logger, "console", test_console)

    logger.print_banner()

    rendered = output.getvalue()
    assert "I  G  N  O  T  U  S" in rendered
    assert "R E D   T E A M   R E C O N" in rendered
    assert "OFFENSIVE SECURITY FRAMEWORK" in rendered
    assert logger.BANNER_DISCLAIMER in rendered


def test_unicode_logo_does_not_wrap_at_80_columns(monkeypatch):
    output = StringIO()
    test_console = Console(file=output, force_terminal=False, width=80)
    monkeypatch.setattr(logger, "console", test_console)

    logger.print_banner()

    rendered_lines = output.getvalue().splitlines()
    for logo_line in logger._RED_TEAM_LOGO.splitlines():
        assert logo_line in rendered_lines


def test_banner_falls_back_to_ascii_on_legacy_windows_encoding(monkeypatch):
    stream = TextIOWrapper(BytesIO(), encoding="cp1252")
    monkeypatch.setattr(
        logger,
        "console",
        Console(file=stream, force_terminal=False, width=100),
    )

    assert logger._select_banner_logo() == logger._ASCII_LOGO
    assert not logger.console_supports("⠋")


def test_summary_counts_findings_instead_of_hosts(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        logger,
        "console",
        Console(file=output, force_terminal=False, width=120),
    )
    result = HostResult(
        host="example.com",
        impacts=[
            Impact("MEDIUM", "one", "evidence"),
            Impact("MEDIUM", "two", "evidence"),
        ],
    )

    logger.print_summary_table({result.host: result})

    assert "MEDIUM 2" in output.getvalue()
