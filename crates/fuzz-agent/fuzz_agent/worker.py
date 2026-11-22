"""p14g in a process of its own, so that a statement that makes `rewrite()` hang costs a restart, not the run.

Python cannot interrupt a call into Rust, so a `rewrite()` that never returns would stop the fuzzer for good. The
calls are made in a child process instead, which is killed and started again when one takes too long.
"""

from __future__ import annotations

import multiprocessing
import time
from collections.abc import Callable
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any, Literal

Mode = Literal['inline', 'params']


@dataclass(frozen=True)
class Rewritten:
    """What `SafeSql` holds, in a form that can cross between processes."""

    sql: str
    params: list[str]
    kind: str
    tables: list[str]


@dataclass(frozen=True)
class Rejected:
    kind: str
    message: str


@dataclass(frozen=True)
class Crashed:
    """`rewrite()` raised something other than `P14gError`, which for a Rust panic is `PanicException`."""

    error: str


@dataclass(frozen=True)
class Hung:
    seconds: float


Handler = Callable[[Any], Any]

_POLICIES: dict[Mode, Any] = {}


def rewrite(request: tuple[Mode, str]) -> Rewritten | Rejected | Crashed:
    """Run p14g on one statement with the target policy, in one literal mode."""
    from p14g import P14gError

    from . import target

    mode, sql = request
    # built once in the child, since a policy holds Python callables and cannot be sent from the parent
    if mode not in _POLICIES:
        _POLICIES[mode] = target.policy() if mode == 'inline' else target.policy(literals='params')
    policy = _POLICIES[mode]
    try:
        safe = policy.rewrite(sql, context=target.CONTEXT)
    except P14gError as e:
        return Rejected(e.kind, str(e))
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:  # noqa: BLE001 - a Rust panic is not an `Exception`
        return Crashed(f'{type(e).__name__}: {e}')
    return Rewritten(safe.sql, safe.params, safe.kind, safe.tables)


STARTUP_TIMEOUT = 60.0
"""Seconds a new process has to start and import what it needs, which is not counted against a request."""


def _serve(connection: Connection, handler: Handler) -> None:
    connection.send('ready')
    while True:
        try:
            request = connection.recv()
        except EOFError:
            return
        connection.send(handler(request))


class Worker:
    """A child process that answers requests with `handler`, and is replaced when one takes too long."""

    def __init__(self, handler: Handler = rewrite, timeout: float = 10.0):
        self.handler = handler
        self.timeout = timeout
        # spawn, not fork: the parent has threads (Logfire's exporters, asyncio's) that fork does not copy safely
        self._context = multiprocessing.get_context('spawn')
        self._process: Any = None
        # `Pipe()` gives a `Connection`, or on Windows a `PipeConnection`, which typeshed does not relate
        self._connection: Any = None

    def ask(self, request: Any) -> Any:
        """The handler's answer, or `Hung` when it does not come within the timeout."""
        if self._connection is None:
            self._start()
        assert self._connection is not None
        start = time.perf_counter()
        self._connection.send(request)
        if self._connection.poll(self.timeout):
            try:
                return self._connection.recv()
            except EOFError:
                # the process died without answering, as it does when Rust aborts rather than unwinding
                self.close()
                return Crashed('the worker process died')
        self.close()
        return Hung(time.perf_counter() - start)

    def close(self) -> None:
        if self._process is not None:
            self._process.kill()
            self._process.join()
        if self._connection is not None:
            self._connection.close()
        self._process = None
        self._connection = None

    def _start(self) -> None:
        parent, child = self._context.Pipe()
        self._process = self._context.Process(target=_serve, args=(child, self.handler), daemon=True)
        self._process.start()
        child.close()
        self._connection = parent
        if not (parent.poll(STARTUP_TIMEOUT) and parent.recv() == 'ready'):
            self.close()
            raise RuntimeError(f'the worker process did not start within {STARTUP_TIMEOUT:.0f}s')
