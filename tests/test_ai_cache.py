"""Tests for the AI engines' concurrent driver and disk result cache."""

from __future__ import annotations

from pathlib import Path

from xsec.engines._ai_common import AiReviewError, review_many
from xsec.models import Finding, Severity


def _finding(file: str, rule_id: str = "AI-CWE-89") -> Finding:
    return Finding(
        rule_id=rule_id, severity=Severity.HIGH, message="found it",
        file=file, line=3, engine="ai", fix="do better",
    )


def _make_files(tmp_path: Path, n: int = 2) -> list[Path]:
    files = []
    for i in range(n):
        f = tmp_path / f"f{i}.py"
        f.write_text(f"print({i})\n")
        files.append(f)
    return files


def test_second_run_hits_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XSEC_CACHE_DIR", str(tmp_path / "cache"))
    files = _make_files(tmp_path)
    calls: list[Path] = []

    def review_one(path: Path, source: str) -> list[Finding]:
        calls.append(path)
        return [_finding(str(path))]

    errors: list[str] = []
    first = review_many(files, "test|model", review_one, errors)
    second = review_many(files, "test|model", review_one, errors)

    assert len(calls) == 2  # one call per file, none on the second run
    assert len(first) == len(second) == 2
    assert second[0].rule_id == "AI-CWE-89"
    assert second[0].severity is Severity.HIGH
    assert second[0].fix == "do better"
    assert errors == []


def test_changed_content_invalidates_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XSEC_CACHE_DIR", str(tmp_path / "cache"))
    files = _make_files(tmp_path, n=1)
    calls: list[Path] = []

    def review_one(path: Path, source: str) -> list[Finding]:
        calls.append(path)
        return []

    review_many(files, "test|model", review_one, [])
    files[0].write_text("print('edited')\n")
    review_many(files, "test|model", review_one, [])
    assert len(calls) == 2


def test_different_model_does_not_share_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XSEC_CACHE_DIR", str(tmp_path / "cache"))
    files = _make_files(tmp_path, n=1)
    calls: list[str] = []

    def review_one(path: Path, source: str) -> list[Finding]:
        calls.append(str(path))
        return []

    review_many(files, "test|model-a", review_one, [])
    review_many(files, "test|model-b", review_one, [])
    assert len(calls) == 2


def test_cache_disabled_by_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("XSEC_CACHE_DIR", str(tmp_path / "cache"))
    files = _make_files(tmp_path, n=1)
    calls: list[str] = []

    def review_one(path: Path, source: str) -> list[Finding]:
        calls.append(str(path))
        return []

    review_many(files, "test|m", review_one, [], use_cache=False)
    review_many(files, "test|m", review_one, [], use_cache=False)
    assert len(calls) == 2


def test_cache_disabled_by_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XSEC_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("XSEC_AI_CACHE", "0")
    files = _make_files(tmp_path, n=1)
    calls: list[str] = []

    def review_one(path: Path, source: str) -> list[Finding]:
        calls.append(str(path))
        return []

    review_many(files, "test|m", review_one, [])
    review_many(files, "test|m", review_one, [])
    assert len(calls) == 2


def test_failures_collect_errors_and_are_not_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("XSEC_CACHE_DIR", str(tmp_path / "cache"))
    files = _make_files(tmp_path, n=1)
    attempts: list[str] = []

    def review_one(path: Path, source: str) -> list[Finding]:
        attempts.append(str(path))
        raise AiReviewError("rate limited")

    errors: list[str] = []
    out = review_many(files, "test|m", review_one, errors)
    assert out == []
    assert len(errors) == 1 and "rate limited" in errors[0]

    # a failure must not poison the cache: the next run retries
    review_many(files, "test|m", review_one, errors)
    assert len(attempts) == 2


def test_results_keep_input_file_order(tmp_path, monkeypatch):
    monkeypatch.setenv("XSEC_CACHE_DIR", str(tmp_path / "cache"))
    files = _make_files(tmp_path, n=5)

    def review_one(path: Path, source: str) -> list[Finding]:
        return [_finding(str(path))]

    out = review_many(files, "test|m", review_one, [])
    assert [f.file for f in out] == [str(p) for p in files]
