"""Parallel helpers for scanning many files at once.

Measurement drove this design. Profiling showed scanning is ~98% CPU (AST
parsing and regex), not I/O, so *thread* pools don't help - the GIL serializes
the CPU work. A *process* pool sidesteps the GIL and gives a real speed-up on
large repos, at the cost of process startup and pickling results across the
boundary.

So we only reach for a process pool when there are enough files to amortize
that overhead; below the threshold (or when processes can't start) we run
inline. ``func`` must be a top-level callable so it can be pickled.
"""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")

# below this many files, the process-pool overhead isn't worth it
_PARALLEL_THRESHOLD = 64


def _worker_count(n_items: int) -> int:
    cpu = os.cpu_count() or 4
    return max(1, min(cpu, n_items))


def parallel_map(func: Callable[[T], list[R]], items: Iterable[T]) -> list[R]:
    """Run ``func`` over ``items`` and flatten the results, in input order.

    Uses a process pool for large batches (real parallelism for CPU-bound
    work), and falls back to a simple inline loop for small batches or if the
    pool can't be created. ``func`` must be importable/picklable.
    """
    items = list(items)
    if len(items) < _PARALLEL_THRESHOLD:
        return _inline(func, items)

    try:
        with ProcessPoolExecutor(max_workers=_worker_count(len(items))) as pool:
            results = list(pool.map(func, items, chunksize=8))
    except (OSError, ValueError, RuntimeError):
        # restricted environments may forbid spawning processes; degrade safely
        return _inline(func, items)

    flat: list[R] = []
    for chunk in results:
        flat.extend(chunk)
    return flat


def _inline(func: Callable[[T], list[R]], items: list[T]) -> list[R]:
    out: list[R] = []
    for item in items:
        out.extend(func(item))
    return out
