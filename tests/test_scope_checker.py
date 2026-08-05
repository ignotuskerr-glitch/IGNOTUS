from core.scope_checker import ScopeChecker, load_scope_file


def test_empty_scope_fails_closed():
    assert not ScopeChecker().is_in_scope("example.com")


def test_wildcard_and_exclusion():
    scope = ScopeChecker(["*.example.com"], ["admin.example.com"])
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("api.example.com")
    assert not scope.is_in_scope("admin.example.com")
    assert not scope.is_in_scope("example.net")


def test_scope_file_prefixes_are_parsed_exactly(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "in: *.example.com\nout: timeout.example.com\n!dev.example.com\n",
        encoding="utf-8",
    )
    included, excluded = load_scope_file(str(scope_file))
    assert included == ["*.example.com"]
    assert excluded == ["timeout.example.com", "dev.example.com"]
