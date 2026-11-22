"""Handlers for `Worker` in the tests. A module of their own, so the child process imports little."""

from __future__ import annotations

import os
import time
from typing import Any

from fuzz_agent import worker


def rewrite_unless_marked(request: tuple[worker.Mode, str]) -> Any:
    """`worker.rewrite`, except that a statement containing HANG never returns and one containing DIE exits."""
    _, sql = request
    if 'HANG' in sql:
        time.sleep(3600)
    if 'DIE' in sql:
        os._exit(1)
    return worker.rewrite(request)
