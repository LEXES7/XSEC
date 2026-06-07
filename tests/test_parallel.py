"""Tests for the parallel map helper."""

from __future__ import annotations

import xsec.parallel as par


def _double(x: int) -> list[int]:
    return [x, x]


def test_inline_path_small_batch():
    # below threshold -> inline, order preserved
    assert par.parallel_map(_double, [1, 2, 3]) == [1, 1, 2, 2, 3, 3]


def test_empty():
    assert par.parallel_map(_double, []) == []


def test_results_match_sequential_above_threshold(monkeypatch):
    items = list(range(200))
    expected = [y for x in items for y in _double(x)]
    # parallel (process pool) result must equal the plain sequential result
    assert par.parallel_map(_double, items) == expected


def test_falls_back_inline_when_threshold_high(monkeypatch):
    monkeypatch.setattr(par, "_PARALLEL_THRESHOLD", 10**9)
    items = list(range(100))
    expected = [y for x in items for y in _double(x)]
    assert par.parallel_map(_double, items) == expected
