# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Run GhidraScripts (Java or Python) against the open program."""

from __future__ import annotations

import os
from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE_NON_IDEMPOTENT, ANNO_READ_ONLY
from re_mcp_ghidra.programmable import MAX_STDOUT_CHARS, _cap, _transaction, revision
from re_mcp_ghidra.session import session

# Searched by bare script name, after Ghidra's own script directories.
USER_SCRIPT_DIRS_ENV = "GHIDRA_MCP_SCRIPT_DIRS"
DEFAULT_USER_SCRIPT_DIR = os.path.expanduser("~/ghidra_scripts")
SCRIPT_EXTENSIONS = (".java", ".py")
PY_TRACEBACK = "Traceback (most recent call last)"


class ScriptResult(BaseModel):
    script: str = Field(description="Absolute path of the script that ran.")
    stdout: str = Field(description="What the script printed (println/print), capped at 64 KiB.")
    stderr: str = Field(description="What the script wrote to its error stream.")
    applied: bool = Field(description="Whether the script's changes were committed.")
    undo_name: str | None = Field(description='Undo step name, "MCP: script <name>".')
    revision: int = Field(description="Program modification number afterwards.")


class ScriptInfo(BaseModel):
    name: str = Field(description="Script file name, what run_ghidra_script takes.")
    path: str = Field(description="Absolute path.")
    category: str = Field(description="@category from the script header, if any.")
    description: str = Field(description="First line of the script's header comment.")


class ScriptList(BaseModel):
    items: list[ScriptInfo] = Field(description="Matching scripts.")
    total: int = Field(description="Number of matching scripts.")


def _script_dirs() -> list[str]:
    dirs = [d for d in os.environ.get(USER_SCRIPT_DIRS_ENV, "").split(os.pathsep) if d]
    dirs.append(DEFAULT_USER_SCRIPT_DIR)

    from ghidra.app.script import GhidraScriptUtil  # noqa: PLC0415

    GhidraScriptUtil.acquireBundleHostReference()
    try:
        dirs += [str(d.getAbsolutePath()) for d in GhidraScriptUtil.getScriptSourceDirectories()]
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
    return [d for d in dict.fromkeys(dirs) if os.path.isdir(d)]


def _resolve(script: str) -> str:
    path = os.path.expanduser(script)
    if os.path.isabs(path):
        if not os.path.isfile(path):
            raise GhidraError(f"Script not found: {path}", error_type="NotFound")
        return path
    for directory in _script_dirs():
        candidate = os.path.join(directory, script)
        if os.path.isfile(candidate):
            return candidate
    raise GhidraError(
        f"No script named {script!r} in the script directories. list_ghidra_scripts shows "
        "them; or pass an absolute path.",
        error_type="NotFound",
    )


def _header(path: str) -> tuple[str, str]:
    """(category, first description line) from a script's leading comment block."""
    category = description = ""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for _, line in zip(range(40), fh, strict=False):
                text = line.strip().lstrip("/#*").strip()
                if text.startswith("@category"):
                    category = text.removeprefix("@category").strip()
                elif text and not text.startswith("@") and not description:
                    description = text
    except OSError:
        pass
    return category, description


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"scripts"})
    @session.require_open
    def run_ghidra_script(
        script: Annotated[
            str,
            Field(
                description=(
                    "Script file name found in the script directories (list_ghidra_scripts), "
                    'or an absolute path to a .java or .py GhidraScript. Example: "DumpFuncs.java"'
                )
            ),
        ],
        args: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Arguments the script reads with getScriptArgs(). "
                    'Example: ["0x401000", "out.txt"]'
                )
            ),
        ] = None,
    ) -> ScriptResult:
        """Run an existing GhidraScript (Java or Python) on the open program.

        Use for scripts you already have; for new logic prefer execute, which
        returns structured results. currentProgram is the open program. The run
        is one transaction: if the script throws, its changes are rolled back and
        the error carries its stderr. Java scripts are compiled by Ghidra on
        first use (needs a JDK). Limits: stdout and stderr are capped at 64 KiB
        each; there is no time limit, since a running Java script cannot be
        interrupted, so a script that loops forever blocks this database. Returns
        {script, stdout, stderr, applied, undo_name, revision}.
        """
        from generic.jar import ResourceFile  # noqa: PLC0415
        from ghidra.app.script import (  # noqa: PLC0415
            GhidraScriptUtil,
            GhidraState,
            ScriptControls,
        )
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415
        from java.io import File, PrintWriter, StringWriter  # noqa: PLC0415

        path = _resolve(script)
        out, err = StringWriter(), StringWriter()
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            source = ResourceFile(File(path))
            provider = GhidraScriptUtil.getProvider(source)
            if provider is None:
                raise GhidraError(
                    f"{path} is not a GhidraScript type this Ghidra can run.",
                    error_type="InvalidArgument",
                )
            # Ghidra compiles and loads a .java script as an OSGi bundle; a
            # directory it was not started with must be registered first, or the
            # load fails with "Failed to find source bundle containing script".
            GhidraScriptUtil.getBundleHost().add(source.getParentFile(), True, False)
            try:
                instance = provider.getScriptInstance(source, PrintWriter(err, True))
            except Exception as exc:
                raise GhidraError(
                    f"Could not load {path}: {exc}. {err}".strip(),
                    error_type="ScriptLoadFailed",
                ) from exc
            if instance is None:
                raise GhidraError(f"Could not load {path}: {err}", error_type="ScriptLoadFailed")
            state = GhidraState(None, session._project, session.program, None, None, None)
            controls = ScriptControls(
                PrintWriter(out, True), PrintWriter(err, True), TaskMonitor.DUMMY
            )
            instance.setScriptArgs(list(args or []))
            with _transaction(f"script {os.path.basename(path)}", keep=True) as tx:
                try:
                    instance.execute(state, controls)
                    # pyghidra (Ghidra 12.0/12.1) catches a Python script's exception
                    # and prints the traceback instead of raising; treat that as the
                    # failure it is, so the transaction rolls back.
                    if path.endswith(".py") and PY_TRACEBACK in str(err):
                        raise RuntimeError(str(err).strip().splitlines()[-1])
                except Exception as exc:
                    raise GhidraError(
                        f"{os.path.basename(path)} failed: {exc}. Nothing was changed: the "
                        "script's transaction was rolled back.",
                        error_type="ScriptError",
                        stdout=_cap(str(out), MAX_STDOUT_CHARS)[0],
                        stderr=_cap(str(err), MAX_STDOUT_CHARS)[0],
                        revision=revision(),
                    ) from exc
        finally:
            GhidraScriptUtil.releaseBundleHostReference()

        return ScriptResult(
            script=path,
            stdout=_cap(str(out), MAX_STDOUT_CHARS)[0],
            stderr=_cap(str(err), MAX_STDOUT_CHARS)[0],
            applied=tx["committed"],
            undo_name=tx["undo_name"],
            revision=revision(),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"scripts"})
    def list_ghidra_scripts(
        filter_pattern: Annotated[
            str,
            Field(
                description=(
                    "Case-insensitive substring of the file name, category or description; "
                    'empty lists all. Example: "switch"'
                )
            ),
        ] = "",
    ) -> ScriptList:
        """List the GhidraScripts run_ghidra_script can run by name.

        Searches GHIDRA_MCP_SCRIPT_DIRS, ~/ghidra_scripts, then Ghidra's bundled
        script directories (a name found earlier wins). Returns {items: [{name,
        path, category, description}], total}.
        """
        needle = filter_pattern.lower()
        seen: set[str] = set()
        items: list[ScriptInfo] = []
        for directory in _script_dirs():
            for name in sorted(os.listdir(directory)):
                if not name.endswith(SCRIPT_EXTENSIONS) or name in seen:
                    continue
                seen.add(name)
                path = os.path.join(directory, name)
                category, description = _header(path)
                if needle and needle not in f"{name} {category} {description}".lower():
                    continue
                items.append(
                    ScriptInfo(name=name, path=path, category=category, description=description)
                )
        return ScriptList(items=items, total=len(items))
