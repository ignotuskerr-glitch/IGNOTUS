from pathlib import Path

from core.path_safety import safe_output_path


def test_accepts_relative_source_path(tmp_path):
    result = safe_output_path(str(tmp_path), "webpack:///src/app.ts")
    assert result == (tmp_path / "src" / "app.ts").resolve()


def test_rejects_parent_traversal(tmp_path):
    assert safe_output_path(str(tmp_path), "../../outside.txt") is None


def test_rejects_absolute_and_windows_paths(tmp_path):
    assert safe_output_path(str(tmp_path), "/etc/passwd") is None
    assert safe_output_path(str(tmp_path), "C:/Windows/system.ini") is None


def test_result_is_confined_to_root(tmp_path):
    result = safe_output_path(str(tmp_path), "src/components/button.tsx")
    assert result is not None
    result.relative_to(Path(tmp_path).resolve())
