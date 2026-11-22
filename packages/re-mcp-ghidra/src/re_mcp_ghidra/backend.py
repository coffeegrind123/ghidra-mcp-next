# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra backend for re-mcp."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from re_mcp.backend import BackendInfo

from re_mcp_ghidra import find_ghidra_dir
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.transforms import MANAGEMENT_TOOLS, PINNED_TOOLS

INSTRUCTIONS = """\
Headless Ghidra 12 for reverse engineering native binaries.

Start: open_database(file_path) imports a binary into <dir>/ghidra_projects/ \
(the directory must be writable); for an existing project pass the .gpr as \
file_path plus program (list_project_files shows the paths). It returns at once: \
call wait_for_analysis(database) before anything else. Every other tool takes \
database (the id open_database returned).

Work loop: read (decompile_function, get_function, get_xrefs_to, list_strings, \
find_code_by_string) -> plan -> ONE batch per coherent change (renames, \
prototypes, comments, struct edits), with a label -> re-read to check -> \
save_database. Use execute (Python 3 against the Ghidra API and every tool) for \
loops, computed edits, or reads no tool covers; read_only=true for pure reads.

batch and execute are atomic: each runs in ONE transaction; if anything fails \
NOTHING changes, and the error names the failing op. A success is one undo step \
"MCP: <label>" (undo removes it). Later ops can use earlier results: "$0.start", \
"name_${1.address}". Pass if_revision (the revision from your last result) to \
refuse to act on a program that changed (TargetChanged); pass operation_id on \
writes so a retry never applies twice.

Finding tools: about 20 tools are listed; ~110 more are found with \
search_tools("struct|enum") and called through call, batch or execute. \
get_schema(tools=[...]) gives parameters. ghidra://api/tools.pyi has every tool \
as a typed Python signature with its documentation.

Addresses: "0x401000", "401000", decimal, or a symbol name ("main"). \
Paginated results have items, total, offset, limit, has_more.

Names: analysis-created names (FUN_, DAT_, LAB_) are SourceType.DEFAULT; \
any rename replaces them with a USER_DEFINED name.

Saving: nothing reaches disk until save_database (close_database saves by \
default). A versioned (Ghidra Server) file must be checked out before it can \
be saved.

Errors are tool errors with error_type: NotFound, InvalidAddress, \
InvalidArguments (fix the params; get_schema), TargetChanged (re-read, retry \
with the new revision), RolledBack, TimeoutError, ScriptError (line and stdout \
included), NoDatabase (open one first).
"""

API_STUB_HEADER = '''"""ghidra-mcp-next tool API.

Each def below is one tool. The same signature is what:
  - a batch op takes: {"tool": "<name>", "params": {...}}  (database is passed to batch)
  - execute calls:    tools.<name>(**params) -> dict

Inside execute you also have: program / currentProgram (ghidra.program.model.listing.Program),
flat (ghidra.program.flatapi.FlatProgramAPI), monitor, toAddr(int|str), decompile(func_or_addr)
-> str, print() (captured as stdout), and any import from the ghidra and java packages, e.g.
    from ghidra.program.model.symbol import SourceType
    fm = program.getFunctionManager()
    for f in fm.getFunctions(True):
        if f.getName().startswith("FUN_") and f.getBody().getNumAddresses() < 16:
            f.setName("thunk_" + f.getName()[4:], SourceType.USER_DEFINED)
    return fm.getFunctionCount()
"""
'''


if TYPE_CHECKING:
    from fastmcp import FastMCP
    from re_mcp.transforms import ToolTransform
    from re_mcp.worker_provider import WorkerPoolProvider


class GhidraBackend:
    """Ghidra backend implementation."""

    @staticmethod
    def info() -> BackendInfo:
        return BackendInfo(
            name="ghidra",
            display_name="Ghidra",
            uri_scheme="ghidra",
            worker_module="re_mcp_ghidra.server",
            pinned_tools=PINNED_TOOLS,
            management_tools=MANAGEMENT_TOOLS,
            env_prefix="GHIDRA_MCP_",
            state_dir_name="re-mcp-ghidra",
        )

    @staticmethod
    def build_instructions(transform: ToolTransform) -> str:
        # Claude Code keeps only the first 4,096 characters; tests enforce it.
        disabled = [
            name
            for name, on in (("execute", transform.has_execute), ("batch", transform.has_batch))
            if not on
        ]
        if not disabled:
            return INSTRUCTIONS
        return INSTRUCTIONS + f"\nDisabled on this server: {', '.join(disabled)}.\n"

    @staticmethod
    def api_stub_header() -> str:
        return API_STUB_HEADER

    @staticmethod
    def register_management_tools(mcp: FastMCP, pool: WorkerPoolProvider) -> None:
        @mcp.tool(annotations={"title": "Open Database"})
        async def open_database(
            file_path: str,
            run_auto_analysis: bool = False,
            keep_open: bool = True,
            database_id: str = "",
            force_new: bool = False,
            language: str = "",
            compiler_spec: str = "",
            program: str = "",
        ) -> dict:
            """Open a binary, or a program in an existing Ghidra project.

            Returns immediately with ``"opening": true`` — call
            wait_for_analysis before using other tools on this database.
            Re-opening an already-open database returns the existing worker.

            **Multiple binaries:** use a separate subagent per binary.

            **force_new=True** is destructive: deletes existing Ghidra
            project and all prior analysis.

            Args:
                file_path: Path to a binary (imported into a project next to it,
                           ``<dir>/ghidra_projects/``), or to an existing project's
                           ``.gpr`` file (then ``program`` is required).
                program: Program path inside the ``.gpr`` project, e.g.
                         ``/firmware/app.bin``. list_project_files lists them.
                run_auto_analysis: Run Ghidra auto-analysis after opening.
                keep_open: Keep other open databases (default True).
                database_id: Custom ID (must match [a-z][a-z0-9_]{0,31}).
                force_new: Delete existing project and start fresh.
                language: Ghidra language ID (e.g. ``x86:LE:64:default``,
                          ``ARM:LE:32:v8``). Auto-detected when omitted.
                          Use list_targets to see options.
                compiler_spec: Ghidra compiler spec (e.g. ``gcc``,
                               ``windows``). Auto-detected when omitted.
            """
            extra = {
                k: v
                for k, v in {
                    "language": language,
                    "compiler_spec": compiler_spec,
                    "program": program,
                }.items()
                if v is not None and v != ""
            }

            return await pool.open_database(
                file_path,
                run_auto_analysis,
                database_id,
                keep_open,
                force_new,
                **extra,
            )

        @mcp.tool(annotations={"title": "List Project Files", "readOnlyHint": True})
        def list_project_files(project: str) -> dict:
            """List the folders and files stored in an existing Ghidra project.

            Use before open_database(file_path=<project>, program=<path>) to find
            the program path. Reads the project's index directly, so it works
            without opening anything and while no database is open.

            Returns ``{"project", "folders": ["/", "/drivers"], "files":
            ["/server.dll", "/drivers/usb.sys"]}``. For a shared (Ghidra Server)
            project, server files that were never checked out are not listed.

            Args:
                project: Path to the project's ``.gpr`` file, e.g.
                         ``/home/me/ghidra_projects/fw.gpr``.
            """
            from re_mcp_ghidra.project_index import (  # noqa: PLC0415
                list_project_files as _list,
            )

            return _list(project)

    @staticmethod
    def register_prompts(mcp: FastMCP) -> None:
        from re_mcp_ghidra.prompts import register_all  # noqa: PLC0415

        register_all(mcp)

    @staticmethod
    def canonical_path(file_path: str, **kwargs: object) -> str:
        # One worker per program: a project file plus the program inside it.
        # Path("/p/x.gpr:/dir/app").stem is "app", which becomes the database id.
        path = os.path.realpath(os.path.expanduser(file_path))
        program = str(kwargs.get("program") or "")
        if path.endswith(".gpr") and program:
            return f"{path}:{program if program.startswith('/') else '/' + program}"
        return path

    @staticmethod
    def list_targets() -> dict:
        ghidra_dir = find_ghidra_dir()
        if ghidra_dir is None:
            raise GhidraError("Ghidra installation not found", error_type="NotFound")
        return _list_ghidra_targets(ghidra_dir)


def _list_ghidra_targets(ghidra_dir: str) -> dict:
    """List available Ghidra languages and compiler specs from .ldefs files."""
    import xml.etree.ElementTree as ET  # noqa: PLC0415

    languages: list[dict[str, str]] = []
    processors_dir = os.path.join(ghidra_dir, "Ghidra", "Processors")

    if not os.path.isdir(processors_dir):
        return {"languages": [], "processors_dir": processors_dir}

    for proc_name in sorted(os.listdir(processors_dir)):
        ldefs_dir = os.path.join(processors_dir, proc_name, "data", "languages")
        if not os.path.isdir(ldefs_dir):
            continue
        for fname in sorted(os.listdir(ldefs_dir)):
            if not fname.endswith(".ldefs"):
                continue
            try:
                tree = ET.parse(os.path.join(ldefs_dir, fname))
                for lang_elem in tree.findall(".//language"):
                    lang_id = lang_elem.get("id", "")
                    lang_desc = ""
                    desc_elem = lang_elem.find("description")
                    if desc_elem is not None and desc_elem.text:
                        lang_desc = desc_elem.text.strip()
                    compiler_specs = []
                    for cspec in lang_elem.findall("compiler"):
                        cs_id = cspec.get("id", "")
                        cs_name = cspec.get("name", "")
                        if cs_id:
                            compiler_specs.append({"id": cs_id, "name": cs_name})
                    if lang_id:
                        entry: dict[str, Any] = {
                            "id": lang_id,
                            "processor": lang_elem.get("processor", ""),
                            "endian": lang_elem.get("endian", ""),
                            "size": lang_elem.get("size", ""),
                            "variant": lang_elem.get("variant", ""),
                            "description": lang_desc,
                        }
                        if compiler_specs:
                            entry["compiler_specs"] = compiler_specs
                        languages.append(entry)
            except ET.ParseError:
                continue

    return {"languages": languages}
