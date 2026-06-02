"""Base class every engine implements."""

from __future__ import annotations

import abc
from pathlib import Path

from xsec.models import Finding


class Engine(abc.ABC):
    """An engine takes a list of files and returns findings.

    Engines collect errors instead of raising on a single bad file.
    """

    name: str = "engine"

    @abc.abstractmethod
    def analyze(self, files: list[Path]) -> list[Finding]:
        raise NotImplementedError

    def available(self) -> tuple[bool, str]:
        # returns (ok, reason). override when the engine needs a key/network.
        return True, ""
