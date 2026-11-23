# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Transactional batch and Python execution inside the worker.

Both run as ONE job on the Ghidra main thread, so no other request can
interleave with them, and both wrap their work in ONE program transaction:

    startTransaction("MCP: <label>")
        op 0 -> tool function (its own transaction nests inside ours)
        op 1 -> ...
    endTransaction(commit = every op succeeded and not dry_run/read_only)

Measured on Ghidra 12.0.3 (context/design.md): an outer abort rolls back
nested transactions that already committed, a nested abort poisons the outer
commit (endTransaction returns False), and a committed outer transaction is a
single undo step named by its description.  The modification number rises on
every transaction, aborted ones included, so every result and error carries
the current ``revision``.
"""

from __future__ import annotations

import ast
import collections
import contextlib
import functools
import io
import json
import logging
import re
import sys
import time
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, validate_call
from pydantic import ValidationError as PydanticValidationError

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.session import session

log = logging.getLogger(__name__)

MAX_BATCH_OPS = 100
MAX_EXECUTE_TIMEOUT_S = 600
DEFAULT_EXECUTE_TIMEOUT_S = 30
MAX_STDOUT_CHARS = 64 * 1024
MAX_RESULT_CHARS = 256 * 1024
OPERATION_CACHE_SIZE = 256
UNDO_PREFIX = "MCP: "

# Tools that manage the worker or the transaction themselves; they cannot run
# inside someone else's transaction.
NOT_IN_TRANSACTION = frozenset(
    {
        "open_database",
        "close_database",
        "save_database",
        "undo",
        "redo",
        "wait_for_analysis",
        "reanalyze_range",
        "run_auto_analysis",
        "set_image_base",
        "run_ghidra_script",
        "checkout_file",
        "checkin_file",
        "undo_checkout",
        "add_to_repository",
        "_batch",
        "_execute",
    }
)

# "$3.items.0.name" as a whole string, or "${3.items.0.name}" inside one.
_WHOLE_REF = re.compile(r"^\$(\d+)((?:\.[A-Za-z0-9_\-]+)*)$")
_INLINE_REF = re.compile(r"\$\{(\d+)((?:\.[A-Za-z0-9_\-]+)*)\}")


# ---------------------------------------------------------------------------
# Tool registry: the plain sync functions behind the worker's MCP tools
# ---------------------------------------------------------------------------


class ToolRegistry:
    """Name -> validated sync callable, for calling tools on the main thread."""

    def __init__(self) -> None:
        self._raw: dict[str, Callable[..., Any]] = {}
        self._validated: dict[str, Callable[..., Any]] = {}

    def add(self, name: str, fn: Callable[..., Any]) -> None:
        self._raw[name] = fn

    def names(self) -> list[str]:
        return sorted(n for n in self._raw if not n.startswith("_"))

    def __contains__(self, name: str) -> bool:
        return name in self._raw

    def call(self, name: str, params: dict[str, Any]) -> Any:
        """Validate *params* against the tool's signature, call it, return JSON data."""
        fn = self._validated.get(name)
        if fn is None:
            raw = self._raw.get(name)
            if raw is None:
                raise GhidraError(
                    f"Unknown tool {name!r}. search_tools lists the tools.",
                    error_type="UnknownTool",
                )
            fn = validate_call(raw)
            self._validated[name] = fn
        try:
            result = fn(**params)
        except PydanticValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
            )
            raise GhidraError(
                f"Invalid arguments for {name}: {problems}. get_schema shows its parameters.",
                error_type="InvalidArguments",
            ) from exc
        return to_json(result)


registry = ToolRegistry()


def to_json(value: Any) -> Any:
    """Convert tool results and script return values to JSON-compatible data."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): to_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_json(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    # JPype boxes Java numbers and strings; everything else becomes its toString().
    for cast in (int, float):
        with contextlib.suppress(Exception):
            if type(value).__name__ in ("JInt", "JLong", "JShort", "JByte") and cast is int:
                return int(value)
            if type(value).__name__ in ("JDouble", "JFloat") and cast is float:
                return float(value)
    if hasattr(value, "__iter__") and type(value).__module__.startswith(("java", "ghidra")):
        with contextlib.suppress(Exception):
            return [to_json(v) for v in value]
    return str(value)


def atomic(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    """Run a write tool in its own transaction when none is open.

    Inside batch/execute a transaction is already open and the call passes
    straight through.  Called on its own, the tool gets transaction
    "MCP: <name>": committed on success (one undo step), rolled back if it
    raises.  Tools that manage the worker or their own transaction
    (NOT_IN_TRANSACTION) are never wrapped.
    """
    if name in NOT_IN_TRANSACTION:
        return fn

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        program = session.program if session.is_open() else None
        if program is None or program.getCurrentTransactionInfo() is not None:
            return fn(*args, **kwargs)
        tx = program.startTransaction(UNDO_PREFIX + name)
        ok = False
        try:
            result = fn(*args, **kwargs)
            ok = True
            return result
        finally:
            program.endTransaction(tx, ok)

    return wrapper


# ---------------------------------------------------------------------------
# $N references
# ---------------------------------------------------------------------------


def _lookup(results: list[Any], index: int, path: str, op_index: int) -> Any:
    if index >= op_index:
        raise GhidraError(
            f"${index} refers to op {index}, which has not run yet (this is op {op_index}).",
            error_type="InvalidReference",
        )
    value = results[index]
    for part in filter(None, path.split(".")):
        if isinstance(value, list) and part.lstrip("-").isdigit():
            try:
                value = value[int(part)]
            except IndexError:
                raise GhidraError(
                    f"${index}{path}: index {part} is out of range (length {len(value)}).",
                    error_type="InvalidReference",
                ) from None
        elif isinstance(value, dict) and part in value:
            value = value[part]
        else:
            keys = list(value) if isinstance(value, dict) else type(value).__name__
            raise GhidraError(
                f"${index}{path}: no {part!r} in op {index}'s result (has: {keys}).",
                error_type="InvalidReference",
            )
    return value


def resolve_refs(value: Any, results: list[Any], op_index: int) -> Any:
    """Replace ``$N.path`` / ``${N.path}`` strings with earlier ops' results.

    A whole-string reference keeps the referenced value's JSON type; an inline
    one is interpolated as text.  ``$$`` at the start of a string escapes a
    literal ``$`` (``"$$5"`` -> ``"$5"``).
    """
    if isinstance(value, dict):
        return {k: resolve_refs(v, results, op_index) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_refs(v, results, op_index) for v in value]
    if not isinstance(value, str) or "$" not in value:
        return value
    if value.startswith("$$"):
        return value[1:]
    whole = _WHOLE_REF.match(value)
    if whole:
        return _lookup(results, int(whole.group(1)), whole.group(2), op_index)
    return _INLINE_REF.sub(
        lambda m: str(_lookup(results, int(m.group(1)), m.group(2), op_index)), value
    )


# ---------------------------------------------------------------------------
# Transaction, guards, replay
# ---------------------------------------------------------------------------

_operations: collections.OrderedDict[str, dict[str, Any]] = collections.OrderedDict()


def revision() -> int:
    return int(session.program.getModificationNumber())


def _check_guards(if_revision: int | None, operation_id: str | None) -> dict[str, Any] | None:
    """Return a stored result for a replayed operation_id, or raise on a stale revision."""
    if operation_id and operation_id in _operations:
        return {**_operations[operation_id], "replayed": True}
    if if_revision is not None and if_revision != revision():
        raise GhidraError(
            f"The program changed since revision {if_revision} (now {revision()}). "
            "Re-read what you depend on, then retry with the new revision.",
            error_type="TargetChanged",
            revision=revision(),
        )
    return None


def _remember(operation_id: str | None, result: dict[str, Any]) -> None:
    if not operation_id:
        return
    _operations[operation_id] = result
    while len(_operations) > OPERATION_CACHE_SIZE:
        _operations.popitem(last=False)


@contextlib.contextmanager
def _transaction(label: str, keep: bool):
    """One outer program transaction; yields a dict whose ``committed`` is set on exit.

    The transaction is committed only when the body returns normally and *keep*
    is true; any exception aborts it, which also rolls back every nested
    transaction the tools committed.
    """
    program = session.program
    info = program.getCurrentTransactionInfo()
    if info is not None:
        raise GhidraError(
            f"Transaction {info.getDescription()!r} is already open on this program.",
            error_type="TransactionOpen",
        )
    state: dict[str, Any] = {"committed": False, "undo_name": None}
    name = UNDO_PREFIX + label
    tx = program.startTransaction(name)
    ok = False
    try:
        yield state
        ok = True
    finally:
        committed = bool(program.endTransaction(tx, ok and keep))
        state["committed"] = committed
        if committed and program.getUndoName() == name:
            state["undo_name"] = name
    if ok and keep and not state["committed"]:
        raise GhidraError(
            "A tool aborted its own part of the change, so Ghidra rolled back the whole "
            "submission. Nothing was changed.",
            error_type="RolledBack",
            revision=revision(),
        )


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------


def run_batch(
    ops: list[dict[str, Any]],
    label: str = "",
    if_revision: int | None = None,
    operation_id: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run *ops* in order inside one transaction. See context/design.md."""
    if not ops:
        raise GhidraError("ops is empty.", error_type="InvalidArgument")
    if len(ops) > MAX_BATCH_OPS:
        raise GhidraError(
            f"{len(ops)} ops; a batch takes at most {MAX_BATCH_OPS}.",
            error_type="InvalidArgument",
        )
    for i, op in enumerate(ops):
        tool = op.get("tool")
        if tool in NOT_IN_TRANSACTION:
            raise GhidraError(
                f"op {i}: {tool} cannot run inside a batch; call it on its own.",
                error_type="InvalidOp",
                op_index=i,
            )
        if not isinstance(tool, str) or tool not in registry:
            raise GhidraError(
                f"op {i}: unknown tool {tool!r}. search_tools lists the tools.",
                error_type="UnknownTool",
                op_index=i,
            )

    replay = _check_guards(if_revision, operation_id)
    if replay is not None:
        return replay

    label = label or ", ".join(dict.fromkeys(op["tool"] for op in ops))[:80]
    results: list[Any] = []
    with _transaction(label, keep=not dry_run) as tx:
        for i, op in enumerate(ops):
            try:
                params = resolve_refs(op.get("params") or {}, results, i)
                results.append(registry.call(op["tool"], params))
            except GhidraError as exc:
                raise _op_error(exc, i, op["tool"]) from exc
            except Exception as exc:
                raise _op_error(GhidraError(str(exc), error_type="Failed"), i, op["tool"]) from exc

    out = {
        "results": results,
        "applied": tx["committed"],
        "dry_run": dry_run,
        "undo_name": tx["undo_name"],
        "revision": revision(),
    }
    if not dry_run:
        _remember(operation_id, out)
    return out


def _op_error(exc: GhidraError, index: int, tool: str) -> GhidraError:
    """Re-raise a failing op's error with its position; the transaction is aborted."""
    details = {k: v for k, v in exc.details.items() if k not in ("op_index", "tool")}
    return GhidraError(
        f"op {index} ({tool}) failed: {exc.args[0]} Nothing was changed: the whole "
        "batch was rolled back.",
        error_type=exc.error_type,
        op_index=index,
        tool=tool,
        revision=revision(),
        **details,
    )


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


class _Tools:
    """``tools.<name>(**params)`` inside execute: calls any tool, returns its dict."""

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_") or name in NOT_IN_TRANSACTION or name not in registry:
            raise AttributeError(
                f"No tool {name!r} available in execute. search_tools lists the tools."
            )
        return lambda **params: registry.call(name, params)

    def __dir__(self) -> list[str]:
        return [n for n in registry.names() if n not in NOT_IN_TRANSACTION]


def _compile_body(code: str) -> Any:
    """Compile *code* as the body of a function.

    ``return`` gives the result; with no ``return`` anywhere at top level, a
    final bare expression is returned (like a REPL).
    """
    try:
        tree = ast.parse(code, "<execute>", "exec")
    except SyntaxError as exc:
        raise GhidraError(
            f"SyntaxError: {exc.msg} (line {exc.lineno})", error_type="SyntaxError"
        ) from exc

    body = tree.body or [ast.Pass()]
    has_return = any(isinstance(n, ast.Return) for n in ast.walk(tree))
    if not has_return and isinstance(body[-1], ast.Expr):
        body[-1] = ast.Return(value=body[-1].value)

    fn = ast.FunctionDef(
        name="__execute__",
        args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=body,
        decorator_list=[],
        type_params=[],
    )
    module = ast.Module(body=[fn], type_ignores=[])
    ast.fix_missing_locations(module)
    try:
        return compile(module, "<execute>", "exec")
    except SyntaxError as exc:
        raise GhidraError(
            f"SyntaxError: {exc.msg} (line {exc.lineno})", error_type="SyntaxError"
        ) from exc


def _decompile(target: Any, timeout_s: int = 60) -> str:
    from ghidra.util.task import ConsoleTaskMonitor  # noqa: PLC0415

    from re_mcp_ghidra.helpers import resolve_function  # noqa: PLC0415

    func = target if hasattr(target, "getEntryPoint") else resolve_function(str(target))
    iface = session.decompiler()
    iface.openProgram(session.program)
    try:
        res = iface.decompileFunction(func, timeout_s, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            raise GhidraError(
                f"Decompilation failed: {res.getErrorMessage()}",
                error_type="DecompilationFailed",
            )
        return str(res.getDecompiledFunction().getC())
    finally:
        iface.dispose()


def _globals(stdout: io.StringIO) -> dict[str, Any]:
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    program = session.program
    flat = session.flat_api

    def _print(*args: Any, sep: str = " ", end: str = "\n", **_: Any) -> None:
        stdout.write(sep.join(str(a) for a in args) + end)

    return {
        "__name__": "__execute__",
        "print": _print,
        "program": program,
        "currentProgram": program,
        "flat": flat,
        "monitor": TaskMonitor.DUMMY,
        "toAddr": flat.toAddr,
        "decompile": _decompile,
        "tools": _Tools(),
        "json": json,
        "re": re,
    }


@contextlib.contextmanager
def _deadline(seconds: float):
    """Raise TimeoutError from the script once *seconds* have passed.

    Checked on every Python line (trace hook), so a single long-running Java
    call can overrun the deadline; it is interrupted at the next Python line.
    """
    end = time.monotonic() + seconds

    def tracer(frame, event, arg):
        if event == "line" and time.monotonic() > end:
            raise TimeoutError(f"execute timed out after {seconds:g}s")
        return tracer

    def global_tracer(frame, event, arg):
        if frame.f_code.co_filename == "<execute>":
            return tracer
        return None

    old = sys.gettrace()
    sys.settrace(global_tracer)
    try:
        yield
    finally:
        sys.settrace(old)


def _cap(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]", True


def run_python(
    code: str,
    read_only: bool = False,
    label: str = "",
    timeout_s: int = DEFAULT_EXECUTE_TIMEOUT_S,
    if_revision: int | None = None,
    operation_id: str | None = None,
) -> dict[str, Any]:
    """Run *code* against the open program inside one transaction."""
    timeout_s = max(1, min(int(timeout_s), MAX_EXECUTE_TIMEOUT_S))
    replay = _check_guards(if_revision, operation_id)
    if replay is not None:
        return replay

    compiled = _compile_body(code)
    stdout = io.StringIO()
    env = _globals(stdout)
    exec(compiled, env)
    fn = env["__execute__"]

    result: Any = None
    with _transaction(label or "execute", keep=not read_only) as tx:
        try:
            with _deadline(timeout_s):
                result = fn()
        except GhidraError as exc:
            raise GhidraError(
                f"{exc.args[0]} Nothing was changed: the script's transaction was rolled back.",
                error_type=exc.error_type,
                stdout=_cap(stdout.getvalue(), MAX_STDOUT_CHARS)[0],
                revision=revision(),
            ) from exc
        except Exception as exc:
            raise GhidraError(
                f"{type(exc).__name__}: {exc}. Nothing was changed: the script's "
                "transaction was rolled back.",
                error_type="TimeoutError" if isinstance(exc, TimeoutError) else "ScriptError",
                line=_script_line(exc),
                stdout=_cap(stdout.getvalue(), MAX_STDOUT_CHARS)[0],
                revision=revision(),
            ) from exc

    data = to_json(result)
    text = json.dumps(data, default=str)
    truncated = False
    if len(text) > MAX_RESULT_CHARS:
        data, truncated = _cap(text, MAX_RESULT_CHARS)
    out_text, out_truncated = _cap(stdout.getvalue(), MAX_STDOUT_CHARS)
    out = {
        "result": data,
        "stdout": out_text,
        "truncated": truncated or out_truncated,
        "applied": tx["committed"],
        "read_only": read_only,
        "undo_name": tx["undo_name"],
        "revision": revision(),
    }
    if not read_only:
        _remember(operation_id, out)
    return out


def _script_line(exc: BaseException) -> int | None:
    tb = exc.__traceback__
    line = None
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == "<execute>":
            line = tb.tb_lineno
        tb = tb.tb_next
    return line
