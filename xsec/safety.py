"""Resource limits for processing untrusted input.

XSEC scans code it did not write, so a hostile or accidentally-huge repo is
part of its threat model. These limits keep a single bad file from hanging the
scanner or exhausting memory:

* file size  - skip files larger than ``MAX_FILE_BYTES``
* line length - truncate lines longer than ``MAX_LINE_CHARS`` before any regex
  runs (the main defense against catastrophic backtracking / ReDoS)
* file count - stop discovery after ``MAX_FILES`` files
* binary     - skip files that look binary (NUL byte in the first chunk)

The numbers are deliberately generous for real source files and far below what
it takes to cause trouble.
"""

from __future__ import annotations

from pathlib import Path

MAX_FILE_BYTES = 5 * 1024 * 1024      # 5 MB: no real source file is bigger
MAX_LINE_CHARS = 5_000                # lines longer than this get truncated
MAX_FILES = 50_000                    # stop walking after this many files
_BINARY_SNIFF_BYTES = 8192


def is_probably_binary(data: bytes) -> bool:
    """A NUL byte in the first chunk is a reliable 'this is binary' signal."""
    return b"\x00" in data[:_BINARY_SNIFF_BYTES]


def read_text_safely(path: Path) -> str | None:
    """Read a file as text within the safety limits.

    Returns the text, or ``None`` if the file is too large, binary, or
    unreadable. Lines longer than ``MAX_LINE_CHARS`` are truncated so a single
    giant line can't feed a pathological regex.
    """
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None

    if is_probably_binary(data):
        return None

    text = data.decode("utf-8", errors="replace")
    return _truncate_lines(text)


def _truncate_lines(text: str) -> str:
    # cap any over-long line; this is the main guard against regex backtracking
    if not any(len(line) > MAX_LINE_CHARS for line in text.splitlines()):
        return text
    return "\n".join(
        line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS]
        for line in text.splitlines()
    )
