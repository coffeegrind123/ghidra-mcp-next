# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Decompiler variable tools — list, rename, retype variables and get comments."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_function,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DecompilerVariable(BaseModel):
    """A decompiler local variable or parameter."""

    name: str = Field(description="Variable name.")
    type: str = Field(description="Variable type.")
    is_param: bool = Field(description="Whether this is a function parameter.")
    size: int = Field(description="Variable size in bytes.")
    storage: str = Field(default="", description="Storage location description.")


class ListDecompilerVarsResult(BaseModel):
    """Decompiler variables for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    variable_count: int = Field(description="Number of variables.")
    variables: list[DecompilerVariable] = Field(description="Variable list.")


class _Verified(BaseModel):
    displaced: list[str] = Field(
        default_factory=list,
        description="Other variables the edit removed (a widened type swallowed them).",
    )
    storage: str = Field(default="", description="Where the variable lives (e.g. EAX:4).")
    verified: bool = Field(default=True, description="The re-decompiled function shows the edit.")
    actual_name: str = Field(default="", description="Name after the edit, as decompiled.")
    actual_type: str = Field(default="", description="Type after the edit, as decompiled.")


class RenameDecompilerVarResult(_Verified):
    """Result of renaming a decompiler variable."""

    function: str = Field(description="Function address (hex).")
    old_name: str = Field(description="Previous variable name.")
    new_name: str = Field(description="New variable name.")


class RetypeDecompilerVarResult(_Verified):
    """Result of retyping a decompiler variable."""

    function: str = Field(description="Function address (hex).")
    variable: str = Field(description="Variable name.")
    old_type: str = Field(description="Previous variable type.")
    new_type: str = Field(description="New variable type.")


class VariableEdit(_Verified):
    old_name: str = Field(description="Name before the edit.")
    old_type: str = Field(description="Type before the edit.")
    new_name: str | None = Field(default=None, description="Requested name, if any.")
    new_type: str | None = Field(default=None, description="Requested type, if any.")


class EditVariablesResult(BaseModel):
    function: str = Field(description="Function address (hex).")
    edits: list[VariableEdit] = Field(description="One entry per requested edit, in order.")
    all_verified: bool = Field(description="Every edit shows in the re-decompiled function.")
    displaced: list[str] = Field(
        default_factory=list,
        description="Other variables the edits removed (a widened type swallowed them).",
    )


VarStorage = Annotated[
    str,
    Field(
        description=(
            "Pick the variable by storage instead of name, exactly as "
            "list_decompiler_variables shows it. Example: 'Stack[-0x18]:8'"
        )
    ),
]
AllowDisplace = Annotated[
    bool,
    Field(
        description=(
            "Allow a retype to swallow neighbouring variables it now overlaps (Ghidra "
            "deletes them); false fails with EditDisplaced and changes nothing. "
            "Example: false"
        )
    ),
]
RequireVerified = Annotated[
    bool,
    Field(
        description=(
            "Fail with EditReverted (and change nothing) when the re-decompiled "
            "function does not show the edit. Example: true"
        )
    ),
]


def _symbols(high) -> list:
    out = []
    it = high.getLocalSymbolMap().getSymbols()
    while it.hasNext():
        out.append(it.next())
    return out


def _anchor(sym) -> str:
    """Where a variable starts: kept across a retype that changes its size."""
    storage = sym.getStorage()
    first = storage.getFirstVarnode() if storage is not None else None
    return str(first.getAddress()) if first is not None else str(storage)


def _edit_variables(
    func, edits: list[dict], require_verified: bool, label: str, allow_displace: bool = False
):
    """Apply decompiler variable edits from one snapshot; verify; all or nothing.

    Returns ([per-edit dicts], all_verified, displaced names). Raises GhidraError
    (NotFound, InvalidArguments, EditReverted, EditDisplaced); on any error the
    transaction is aborted.

    Measured on Ghidra 12.0.3: widening a 4-byte stack local to 8 bytes over its
    neighbour keeps the edit and deletes the neighbour without a word, so the
    variables present before and after are compared too.
    """
    from ghidra.program.model.pcode import HighFunctionDBUtil  # noqa: PLC0415
    from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

    from re_mcp_ghidra.tools.program_analysis import _high_function  # noqa: PLC0415
    from re_mcp_ghidra.tools.structs import _parse_data_type  # noqa: PLC0415

    program = session.program
    syms = _symbols(_high_function(func))
    by_name = {str(s.getName()): s for s in syms}
    by_storage: dict[str, list] = {}
    for s in syms:
        by_storage.setdefault(str(s.getStorage()), []).append(s)
    plan, seen = [], set()
    for i, edit in enumerate(edits):
        name, storage = edit.get("name") or "", edit.get("storage") or ""
        new_name, new_type = edit.get("new_name") or None, edit.get("new_type") or None
        if bool(name) == bool(storage):
            raise GhidraError(
                f"Edit {i}: give exactly one of name or storage.", error_type="InvalidArguments"
            )
        if not new_name and not new_type:
            raise GhidraError(
                f"Edit {i}: nothing to change (new_name, new_type).", error_type="InvalidArguments"
            )
        if storage and len(by_storage.get(storage, [])) > 1:
            names = ", ".join(str(x.getName()) for x in by_storage[storage])
            raise GhidraError(
                f"Edit {i}: storage {storage} holds several variables ({names}); pick one by name.",
                error_type="InvalidArguments",
            )
        sym = by_name.get(name) if name else (by_storage.get(storage) or [None])[0]
        if sym is None:
            known = sorted(by_name) if name else sorted(by_storage)
            raise GhidraError(
                f"Edit {i}: no variable {'named ' + repr(name) if name else 'at ' + storage} "
                f"in {func.getName()}. Known: {', '.join(known[:40])}.",
                error_type="NotFound",
            )
        key = str(sym.getName())
        if key in seen:
            raise GhidraError(
                f"Edit {i}: {sym.getName()} is edited twice; combine new_name and new_type.",
                error_type="InvalidArguments",
            )
        seen.add(key)
        dt = _parse_data_type(new_type) if new_type else None
        plan.append((sym, new_name, new_type, dt))

    tx = program.startTransaction(label)
    commit = False
    try:
        before = []
        for sym, new_name, _new_type, dt in plan:
            before.append((str(sym.getName()), str(sym.getDataType()), _anchor(sym)))
            HighFunctionDBUtil.updateDBVariable(sym, new_name, dt, SourceType.USER_DEFINED)

        after = _symbols(_high_function(func))
        # Stack variables only, by location: register temporaries (uVar1, ...)
        # may legitimately merge or renumber between two decompiles.
        edited = {anchor for _n, _t, anchor in before}
        still = {_anchor(x) for x in after}
        displaced = sorted(
            str(x.getName())
            for x in syms
            if x.getStorage().isStackStorage()
            and _anchor(x) not in edited
            and _anchor(x) not in still
        )
        by_anchor: dict[str, list] = {}
        for s in after:
            by_anchor.setdefault(_anchor(s), []).append(s)
        done, all_ok = [], True
        for (_sym, new_name, new_type, dt), (old_name, old_type, anchor) in zip(
            plan, before, strict=True
        ):
            # Several variables can share a location (uVar20, uVar21 in RBP):
            # prefer the one with the expected name.
            candidates = by_anchor.get(anchor, [])
            expected = new_name or old_name
            got = next((s for s in candidates if str(s.getName()) == expected), None)
            got = got or (candidates[0] if len(candidates) == 1 else None)
            ok = got is not None
            if ok and new_name:
                ok = str(got.getName()) == new_name
            if ok and dt is not None:
                ok = got.getDataType().isEquivalent(dt)
            all_ok &= ok
            done.append(
                {
                    "function": format_address(func.getEntryPoint().getOffset()),
                    "old_name": old_name,
                    "old_type": old_type,
                    "new_name": new_name,
                    "new_type": new_type,
                    "storage": str(got.getStorage()) if got is not None else "",
                    "verified": ok,
                    "actual_name": str(got.getName()) if got is not None else "",
                    "actual_type": str(got.getDataType()) if got is not None else "",
                }
            )
        if require_verified and not all_ok:
            bad = [d for d in done if not d["verified"]]
            raise GhidraError(
                "The decompiler did not keep "
                + "; ".join(
                    f"{d['old_name']} -> {d['new_name'] or d['old_name']}"
                    f"{': ' + d['new_type'] if d['new_type'] else ''}"
                    f" (now {d['actual_name'] or 'gone'}: {d['actual_type'] or '?'})"
                    for d in bad
                )
                + ". Nothing was changed. A type wider than the variable's storage overlaps "
                "its neighbour; retype the neighbour or pick a narrower type.",
                error_type="EditReverted",
            )
        if displaced and not allow_displace:
            raise GhidraError(
                f"The edit would delete {', '.join(displaced)}: the new type overlaps "
                "them. Nothing was changed. Retype them first, or pass "
                "allow_displace=true.",
                error_type="EditDisplaced",
            )
        for d in done:
            d["displaced"] = displaced
        commit = True
        return done, all_ok, displaced
    finally:
        program.endTransaction(tx, commit)


class DecompilerCommentItem(BaseModel):
    """A decompiler comment at an address."""

    address: str = Field(description="Comment address (hex).")
    comment: str = Field(description="Comment text.")


class GetDecompilerCommentsResult(BaseModel):
    """Decompiler comments for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    comments: list[DecompilerCommentItem] = Field(description="Comments.")


def _decompile(func):
    """Decompile a function, returning (DecompileResults, HighFunction).

    Raises :class:`GhidraError` on failure.
    """
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    program = session.program
    decomp = session.decompiler()
    decomp.openProgram(program)
    try:
        results = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
        if not results.decompileCompleted():
            error_msg = results.getErrorMessage() or "Decompilation failed"
            raise GhidraError(error_msg, error_type="DecompilationFailed")

        high_func = results.getHighFunction()
        if high_func is None:
            raise GhidraError(
                "Decompilation returned no HighFunction", error_type="DecompilationFailed"
            )
        return results, high_func
    except GhidraError:
        raise
    except Exception as e:
        raise GhidraError(f"Decompilation failed: {e}", error_type="DecompilationFailed") from e
    finally:
        decomp.dispose()


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"decompiler"})
    @session.require_open
    def list_decompiler_variables(
        function_address: Address,
    ) -> ListDecompilerVarsResult:
        """List decompiler locals and parameters for a function.

        Returns each variable's name, type, storage, and whether it is a
        parameter.  Use this before rename_decompiler_variable or
        retype_decompiler_variable to get the exact current names.

        Args:
            function_address: Address or name of the function.
        """
        func = resolve_function(function_address)
        _results, high_func = _decompile(func)

        variables = []
        local_sym_map = high_func.getLocalSymbolMap()
        sym_iter = local_sym_map.getSymbols()
        while sym_iter.hasNext():
            sym = sym_iter.next()
            high_var = sym.getHighVariable()
            var_type = str(high_var.getDataType()) if high_var else "undefined"
            var_size = high_var.getSize() if high_var else 0
            storage_desc = str(sym.getStorage()) if sym.getStorage() else ""

            variables.append(
                DecompilerVariable(
                    name=sym.getName(),
                    type=var_type,
                    is_param=sym.isParameter(),
                    size=var_size,
                    storage=storage_desc,
                )
            )

        entry = func.getEntryPoint().getOffset()
        return ListDecompilerVarsResult(
            function=format_address(entry),
            name=func.getName(),
            variable_count=len(variables),
            variables=variables,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"decompiler", "modification"})
    @session.require_open
    def rename_decompiler_variable(
        function_address: Address,
        old_name: Annotated[
            str,
            Field(
                description="Current variable name exactly as shown in the decompiler "
                "output (see list_decompiler_variables); empty when storage is given. "
                "Example: 'local_10'"
            ),
        ] = "",
        new_name: Annotated[
            str,
            Field(description="New name to assign to the variable. Example: 'buf_len'"),
        ] = "",
        storage: VarStorage = "",
        require_verified: RequireVerified = True,
    ) -> RenameDecompilerVarResult:
        """Rename a local variable or parameter in a function's decompiled output.

        Changes only the name and keeps the type; use retype_decompiler_variable to
        change the type, edit_decompiler_variables for several edits at once. Name the
        variable by old_name or by storage (stable when auto names renumber). The
        function is decompiled again to check the edit took. Returns function,
        old_name, new_name, storage, verified, actual_name and actual_type.
        """
        if not new_name:
            raise GhidraError("new_name is required.", error_type="InvalidArguments")
        (done,), _, _ = _edit_variables(
            resolve_function(function_address),
            [{"name": old_name, "storage": storage, "new_name": new_name}],
            require_verified,
            "Rename decompiler variable",
        )
        return RenameDecompilerVarResult(
            function=done["function"],
            old_name=done["old_name"],
            new_name=new_name,
            storage=done["storage"],
            verified=done["verified"],
            actual_name=done["actual_name"],
            actual_type=done["actual_type"],
            displaced=done["displaced"],
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"decompiler", "modification"})
    @session.require_open
    def retype_decompiler_variable(
        function_address: Address,
        variable_name: Annotated[
            str,
            Field(
                description="Variable name exactly as shown in the decompiler output "
                "(see list_decompiler_variables); empty when storage is given. "
                "Example: 'param_1'"
            ),
        ] = "",
        new_type: Annotated[
            str,
            Field(
                description="C type to apply, resolved against the program's data "
                "types. Example: 'char *'"
            ),
        ] = "",
        storage: VarStorage = "",
        require_verified: RequireVerified = True,
        allow_displace: AllowDisplace = False,
    ) -> RetypeDecompilerVarResult:
        """Change the data type of a local variable or parameter in decompiled output.

        Changes only the type and keeps the name; use rename_decompiler_variable to
        rename, edit_decompiler_variables for several edits at once. Name the variable
        by variable_name or by storage. The function is decompiled again to check the
        edit took (else EditReverted). A wider type that overlaps a neighbouring
        variable makes Ghidra delete the neighbour: that fails with EditDisplaced unless
        allow_displace. Returns function, variable, old_type, new_type, storage,
        verified, actual_name, actual_type and displaced.
        """
        if not new_type:
            raise GhidraError("new_type is required.", error_type="InvalidArguments")
        (done,), _, _ = _edit_variables(
            resolve_function(function_address),
            [{"name": variable_name, "storage": storage, "new_type": new_type}],
            require_verified,
            "Retype decompiler variable",
            allow_displace,
        )
        return RetypeDecompilerVarResult(
            function=done["function"],
            variable=done["old_name"],
            old_type=done["old_type"],
            new_type=new_type,
            storage=done["storage"],
            verified=done["verified"],
            actual_name=done["actual_name"],
            actual_type=done["actual_type"],
            displaced=done["displaced"],
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"decompiler", "modification"})
    @session.require_open
    def edit_decompiler_variables(
        function_address: Address,
        edits: Annotated[
            list[dict],
            Field(
                min_length=1,
                description=(
                    "[{name or storage, new_name?, new_type?}], all against the variables "
                    "as list_decompiler_variables shows them now. Example: "
                    '[{"storage": "Stack[-0x18]:8", "new_name": "buf", "new_type": "char *"}, '
                    '{"name": "param_1", "new_name": "ctx"}]'
                ),
            ),
        ],
        require_verified: RequireVerified = True,
        allow_displace: AllowDisplace = False,
    ) -> EditVariablesResult:
        """Rename and retype several decompiler variables of one function at once.

        Use instead of a chain of rename/retype calls: every edit is resolved
        against one decompilation, so auto names (uVar1, local_18) cannot
        renumber between edits and hit the wrong variable. All edits apply in one
        transaction and are checked with one more decompile; if any did not take
        (EditReverted), any would delete an overlapped neighbour (EditDisplaced,
        unless allow_displace) or any target is unknown, nothing changes. Returns
        {function, edits: [{old_name, storage, new_name, new_type, old_type,
        verified, actual_name, actual_type}], all_verified, displaced}.
        """
        done, all_ok, displaced = _edit_variables(
            resolve_function(function_address),
            edits,
            require_verified,
            "Edit decompiler variables",
            allow_displace,
        )
        return EditVariablesResult(
            function=done[0]["function"],
            edits=[
                VariableEdit(**{k: v for k, v in d.items() if k not in ("function", "displaced")})
                for d in done
            ],
            all_verified=all_ok,
            displaced=displaced,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"decompiler", "comments"})
    @session.require_open
    def get_decompiler_comments(
        function_address: Address,
    ) -> GetDecompilerCommentsResult:
        """List pre-comments (visible in decompiler) for a function.

        Returns PRE comments on code units within the function body,
        which Ghidra's decompiler renders above the corresponding
        pseudocode line.

        Args:
            function_address: Address or name of the function.
        """
        from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

        func = resolve_function(function_address)
        program = session.program
        listing = program.getListing()
        body = func.getBody()

        comments = []
        cu_iter = listing.getCodeUnits(body, True)
        while cu_iter.hasNext():
            cu = cu_iter.next()
            pre_cmt = cu.getComment(CodeUnit.PRE_COMMENT)
            if pre_cmt:
                comments.append(
                    DecompilerCommentItem(
                        address=format_address(cu.getAddress().getOffset()),
                        comment=pre_cmt,
                    )
                )

        entry = func.getEntryPoint().getOffset()
        return GetDecompilerCommentsResult(
            function=format_address(entry),
            name=func.getName(),
            comments=comments,
        )
