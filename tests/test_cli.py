import pytest

from core.cli import parse_cli_args


def test_scan_requires_an_explicit_execution_mode():
    with pytest.raises(SystemExit):
        parse_cli_args(["example.com"])


def test_only_impacts_is_output_filter_not_intrusive_permission():
    args, _ = parse_cli_args(["example.com", "--only-impacts"])
    assert args.only_impacts
    assert not args.werkzeug_dos


def test_werkzeug_dos_requires_scope_file():
    with pytest.raises(SystemExit):
        parse_cli_args(["example.com", "--only-impacts", "--werkzeug-dos"])


def test_explicit_werkzeug_dos_with_scope_is_allowed(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("in: *.example.com\n", encoding="utf-8")
    args, _ = parse_cli_args(
        [
            "example.com",
            "--only-impacts",
            "--werkzeug-dos",
            "--scope-file",
            str(scope_file),
        ]
    )
    assert args.werkzeug_dos


def test_full_does_not_enable_availability_test_implicitly(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("in: *.example.com\n", encoding="utf-8")
    args, _ = parse_cli_args(["example.com", "--full", "--scope-file", str(scope_file)])
    assert args.full
    assert not args.werkzeug_dos
    assert args.external_audit


def test_intrusive_mode_rejects_missing_scope_file():
    with pytest.raises(SystemExit):
        parse_cli_args(
            [
                "example.com",
                "--only-impacts",
                "--werkzeug-dos",
                "--scope-file",
                "missing-scope.txt",
            ]
        )


@pytest.mark.parametrize("workers", ["0", "129", "-1"])
def test_workers_are_bounded(workers):
    with pytest.raises(SystemExit):
        parse_cli_args(["example.com", "--only-impacts", "--workers", workers])


def test_source_map_mode_does_not_require_dummy_target():
    args, _ = parse_cli_args(["--source-map", "https://example.com/app.js.map"])
    assert args.target is None


def test_interactive_configurer_can_supply_target():
    def configure(args):
        args.target = "example.com"
        args.only_impacts = True
        return args

    args, _ = parse_cli_args(["--interactive"], interactive_configurer=configure)
    assert args.target == "example.com"


def test_only_impact_alias_is_supported():
    args, _ = parse_cli_args(["example.com", "--only-impact"])
    assert args.only_impacts


def test_local_modes_use_operational_strict_policies_by_default():
    red, _ = parse_cli_args(["red", "impact"])
    purple, _ = parse_cli_args(["--purple-team", "--purple-profile", "all"])
    assert red.red_detections.endswith("config\\red\\detections.json")
    assert purple.purple_detections.endswith("config\\purple\\detections.json")


def test_purple_team_is_a_standalone_terminal_mode():
    args, _ = parse_cli_args(["--purple-team", "--purple-profile", "all"])
    assert args.purple_team
    assert args.target is None


def test_purple_team_rejects_scan_modes():
    with pytest.raises(SystemExit):
        parse_cli_args(["example.com", "--purple-team", "--full"])


def test_amsi_audit_is_a_standalone_terminal_mode():
    args, _ = parse_cli_args(["--amsi-audit"])
    assert args.amsi_audit
    assert args.target is None


def test_amsi_audit_rejects_target_scan():
    with pytest.raises(SystemExit):
        parse_cli_args(["example.com", "--amsi-audit", "--only-impact"])


def test_empty_command_opens_interactive_terminal():
    def configure(args):
        args.red_mode = True
        return args

    args, _ = parse_cli_args([], interactive_configurer=configure)
    assert args.interactive
    assert args.red_mode


@pytest.mark.parametrize("alias", ["red", "vermelho"])
def test_red_terminal_alias_activates_quick_profile(alias):
    args, _ = parse_cli_args([alias])
    assert args.red_mode
    assert args.red_profile == "quick"


def test_red_terminal_alias_accepts_profile_and_options():
    args, _ = parse_cli_args(["red", "full", "--red-save-baseline"])
    assert args.red_mode
    assert args.red_profile == "full"
    assert args.red_save_baseline


@pytest.mark.parametrize("rate", ["0", "1001"])
def test_rate_limit_is_bounded(rate):
    with pytest.raises(SystemExit):
        parse_cli_args(["example.com", "--only-impacts", "--rate-limit", rate])
