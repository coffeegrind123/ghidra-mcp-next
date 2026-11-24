# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra MCP worker process.

Each worker manages a single Ghidra program and exposes analysis
capabilities as MCP tools.  The supervisor spawns workers and routes
tool calls to the correct one.

**Threading model:** pyghidra/JPype starts the JVM on the main thread.
The MCP server's asyncio event loop runs on a daemon background thread.
All sync tool functions are dispatched to the main thread via
:func:`~re_mcp_ghidra.helpers.call_ghidra`.
"""

from __future__ import annotations

import faulthandler
import importlib
import logging
import os
import pkgutil
import sys
import threading
import time
from collections.abc import Callable
from typing import Any

from re_mcp.server import BackendServer, MainThreadExecutor

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ghidra-specific uppercase words for auto-titling
# ---------------------------------------------------------------------------

_UPPERCASE_WORDS = frozenset(
    {
        "abi",
        "asm",
        "cfg",
        "elf",
        "exe",
        "ghidra",
        "io",
        "mcp",
        "pdb",
        "pe",
    }
)


# ---------------------------------------------------------------------------
# GhidraServer (BackendServer subclass)
# ---------------------------------------------------------------------------


class GhidraServer(BackendServer):
    """FastMCP subclass that dispatches sync tool/resource execution to the main thread."""

    _uppercase_words = _UPPERCASE_WORDS

    async def _dispatch(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        from re_mcp_ghidra.helpers import call_ghidra  # noqa: PLC0415

        return await call_ghidra(fn, *args, **kwargs)

    def tool(self, name_or_fn: Any = None, **kwargs: Any) -> Any:
        """Register a tool, recording it for batch/execute and making writes atomic.

        batch and execute call tools directly on the main thread through
        :data:`re_mcp_ghidra.programmable.registry`, inside one transaction,
        instead of round-tripping through MCP.  A write tool called on its own
        (outside batch/execute) is wrapped by
        :func:`re_mcp_ghidra.programmable.atomic` so it gets its own transaction
        and undo step instead of failing with "Transaction has not been started".
        """
        from re_mcp_ghidra.programmable import atomic, registry  # noqa: PLC0415

        annotations = kwargs.get("annotations") or {}
        read_only = bool(
            annotations.get("readOnlyHint")
            if isinstance(annotations, dict)
            else getattr(annotations, "readOnlyHint", False)
        )

        def prepare(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
            wrapped = fn if read_only else atomic(name, fn)
            registry.add(name, wrapped)
            return wrapped

        if callable(name_or_fn):
            name = kwargs.get("name") or name_or_fn.__name__
            return super().tool(prepare(name, name_or_fn), **kwargs)

        inner = super().tool(name_or_fn, **kwargs)
        explicit = name_or_fn if isinstance(name_or_fn, str) else kwargs.get("name")

        def decorator(fn: Callable[..., Any]) -> Any:
            return inner(prepare(explicit or fn.__name__, fn))

        return decorator


# ---------------------------------------------------------------------------
# Stall watchdog
# ---------------------------------------------------------------------------

STALL_ENV = "GHIDRA_MCP_STALL_DUMP_S"
STALL_POLL_S = 2.0


def _java_threads() -> str:
    """Every JVM thread's full stack, with the lock it waits on and who holds it.

    ThreadInfo.toString() cuts stacks at 8 frames, so the frames are printed
    here. Runs on a watchdog thread: JPype releases the GIL while the main
    thread is inside a Java call, so this works while the main thread is stuck.
    """
    from java.lang.management import ManagementFactory  # noqa: PLC0415

    bean = ManagementFactory.getThreadMXBean()
    lines = []
    deadlocked = bean.findDeadlockedThreads()
    if deadlocked is not None:
        lines.append(f"DEADLOCKED thread ids: {list(deadlocked)}")
    for info in bean.dumpAllThreads(True, True):
        head = f'"{info.getThreadName()}" id={info.getThreadId()} {info.getThreadState()}'
        if info.getLockName() is not None:
            head += f" on {info.getLockName()}"
        if info.getLockOwnerName() is not None:
            head += f' owned by "{info.getLockOwnerName()}" id={info.getLockOwnerId()}'
        lines.append(head)
        lines.extend(f"    at {frame}" for frame in info.getStackTrace())
        lines.extend(
            f"    - locked {m} (at depth {m.getLockedStackDepth()})"
            for m in info.getLockedMonitors()
        )
        lines.extend(f"    - locked synchronizer {s}" for s in info.getLockedSynchronizers())
    return "\n".join(lines)


def _start_stall_watchdog(executor: MainThreadExecutor) -> None:
    """When one tool call runs longer than $GHIDRA_MCP_STALL_DUMP_S, dump all stacks once.

    A hung Java call never returns and may never check its TaskMonitor, so
    nothing reaches the log. Python stacks (faulthandler) and Java stacks go to
    stderr, which the supervisor writes to the worker's log file when
    RE_MCP_LOG_DIR is set. Off unless the variable is set; for diagnosis only.
    """
    try:
        limit = float(os.environ.get(STALL_ENV, "0"))
    except ValueError:
        log.warning("Ignoring %s=%r: not a number", STALL_ENV, os.environ.get(STALL_ENV))
        return
    if limit <= 0:
        return

    def watch() -> None:
        dumped_for = None
        while True:
            time.sleep(STALL_POLL_S)
            since = executor.busy_since
            if since is None or since == dumped_for or time.monotonic() - since < limit:
                continue
            dumped_for = since
            print(
                f"=== stall: one tool call has run {time.monotonic() - since:.0f}s ===",
                file=sys.stderr,
                flush=True,
            )
            faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
            try:
                print(_java_threads(), file=sys.stderr, flush=True)
            except Exception:
                log.exception("Java thread dump failed")

    threading.Thread(target=watch, daemon=True, name="stall-watchdog").start()
    log.info("Stall watchdog on: dumps stacks after %ss in one call", limit)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the ``re-mcp-ghidra-worker`` script."""
    import re_mcp_ghidra  # noqa: PLC0415

    re_mcp_ghidra.configure_logging()
    re_mcp_ghidra.bootstrap()

    from re_mcp_ghidra import resources as ghidra_resources  # noqa: PLC0415
    from re_mcp_ghidra import tools as tools_pkg  # noqa: PLC0415
    from re_mcp_ghidra.helpers import set_main_executor  # noqa: PLC0415

    executor = MainThreadExecutor()
    set_main_executor(executor)

    mcp = GhidraServer(
        "Ghidra",
        instructions=(
            "Ghidra binary analysis server. Use open_database to load a binary "
            "before calling other tools. Addresses can be specified as hex strings "
            '(e.g. "0x401000"), bare hex ("4010a0"), decimal, or symbol names '
            '(e.g. "main").'
        ),
        on_duplicate="error",
    )

    ghidra_resources.register(mcp)
    tool_count = 0
    for _finder, module_name, _ispkg in pkgutil.iter_modules(tools_pkg.__path__):
        mod = importlib.import_module(f"re_mcp_ghidra.tools.{module_name}")
        if hasattr(mod, "register"):
            log.debug("Registering tool module: %s", module_name)
            mod.register(mcp)
            tool_count += 1
    log.info("Worker ready: registered %d tool modules", tool_count)

    def _run_mcp() -> None:
        try:
            mcp.run(transport="stdio")
        finally:
            executor.shutdown()

    _start_stall_watchdog(executor)
    mcp_thread = threading.Thread(target=_run_mcp, daemon=True, name="mcp-server")
    mcp_thread.start()
    log.info("MCP server started on daemon thread")

    try:
        executor.run_forever()
    except (KeyboardInterrupt, SystemExit):
        log.info("Main thread shutting down")
    finally:
        mcp_thread.join(timeout=5)

        from re_mcp_ghidra.session import session  # noqa: PLC0415

        if session.is_open():
            log.info("Saving database on shutdown: %s", session.current_path)
            try:
                session.close(save=True)
            except Exception:
                log.exception("Failed to save database on shutdown")


if __name__ == "__main__":
    main()
