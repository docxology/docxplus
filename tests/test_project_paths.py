"""Project path helpers."""

from __future__ import annotations

from pathlib import Path

from docxplus import project_paths


def test_project_root_is_directory():
    assert project_paths.project_root().is_dir()


def test_output_dirs_keys():
    dirs = project_paths.output_dirs()
    assert {"output", "documents", "figures", "data", "reports"} <= set(dirs)
    assert all(isinstance(p, Path) for p in dirs.values())


def test_ensure_output_dirs_creates(tmp_path, monkeypatch):
    monkeypatch.setattr(project_paths, "_ROOT", tmp_path)
    dirs = project_paths.ensure_output_dirs()
    assert dirs["figures"].is_dir()
    assert dirs["reports"].is_dir()
