"""Code-execution sink used by /api/run-code."""
from __future__ import annotations

import os


def run_code(snippet: str) -> str:
    os.system(snippet)
    return "ran"
