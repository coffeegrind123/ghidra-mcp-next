# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Cross-database function matching and documentation propagation (supervisor side).

Bootstrap-safe: no JVM here.  Each database lives in its own worker, so these
tools call the workers' get_function_hashes / get_function_documentation /
apply_function_documentation and the internal _export_types / _import_types,
and do the matching in Python.

Matching follows Function ID's uniqueness rule: a hash links two functions only
when it occurs exactly once in each database.  Hashes that occur more than once
on either side are reported as ambiguous and never applied, because a wrong
name copied onto a function is worse than none.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections import defaultdict
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from re_mcp.worker_provider import WorkerPoolProvider

HASH_PAGE = 5000
DOC_EXPORT_CHUNK = 100  # ops per read-only _batch; the batch limit is 100
DEFAULT_MAX_FUNCTIONS = 2000
FIELDS = ("name", "prototype", "plate", "comments", "labels", "locals", "tags", "no_return")

Algorithm = Annotated[
    Literal["fid_specific", "fid_full", "exact_instructions", "exact_bytes", "exact_mnemonics"],
    Field(
        description=(
            "Hash used to match. fid_specific (default) keeps operand constants: fewest false "
            "matches. fid_full masks constants, so it also matches code relinked at other "
            'addresses. exact_bytes requires identical bytes. Example: "fid_full"'
        )
    ),
]
SourceDb = Annotated[
    str, Field(description='Database to copy from (the documented one). Example: "app_v1"')
]
TargetDb = Annotated[str, Field(description='Database to copy to. Example: "app_v2"')]


async def _call(pool: WorkerPoolProvider, database: str, tool: str, params: dict) -> dict:
    from re_mcp.worker_provider import parse_result, require_success  # noqa: PLC0415

    worker = pool.resolve_worker(database)
    result = await pool.proxy_to_worker(worker, tool, params)
    data = parse_result(result)
    require_success(result, data, f"{tool} failed on {database}")
    return data


async def _hashes(pool, database: str, algorithm: str, names: str) -> list[dict]:
    items: list[dict] = []
    offset = 0
    while True:
        page = await _call(
            pool,
            database,
            "get_function_hashes",
            {"algorithm": algorithm, "names": names, "offset": offset, "limit": HASH_PAGE},
        )
        items.extend(page["items"])
        if not page.get("has_more"):
            return items
        offset += HASH_PAGE


def match_unique(source: list[dict], target: list[dict]) -> tuple[list[dict], int, int]:
    """Pair functions whose hash occurs exactly once on each side.

    Returns (matches, ambiguous_hashes, too_small).
    """
    src: dict[str, list[dict]] = defaultdict(list)
    tgt: dict[str, list[dict]] = defaultdict(list)
    too_small = 0
    for item in source:
        if item["hash"] is None:
            too_small += 1
        else:
            src[item["hash"]].append(item)
    for item in target:
        if item["hash"] is not None:
            tgt[item["hash"]].append(item)

    matches, ambiguous = [], 0
    for value, s_items in src.items():
        t_items = tgt.get(value)
        if not t_items:
            continue
        if len(s_items) != 1 or len(t_items) != 1:
            ambiguous += 1
            continue
        s, t = s_items[0], t_items[0]
        matches.append(
            {
                "source": {"address": s["address"], "name": s["name"]},
                "target": {
                    "address": t["address"],
                    "name": t["name"],
                    "is_default_name": t["is_default_name"],
                },
                "hash": value,
            }
        )
    matches.sort(key=lambda m: m["target"]["address"])
    return matches, ambiguous, too_small


def register_matching_tools(mcp: FastMCP, pool: WorkerPoolProvider) -> None:
    @mcp.tool(annotations={"title": "Match Functions", "readOnlyHint": True})
    async def match_functions(
        source_database: SourceDb,
        target_database: TargetDb,
        algorithm: Algorithm = "fid_specific",
        source_names: Annotated[
            Literal["all", "named", "unnamed"],
            Field(description='Which source functions to match. Example: "named"'),
        ] = "named",
        target_names: Annotated[
            Literal["all", "named", "unnamed"],
            Field(description='Which target functions to match. Example: "unnamed"'),
        ] = "all",
        offset: Annotated[int, Field(ge=0, description="Skip this many matches. Example: 0")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=5000, description="Most matches to return. Example: 200")
        ] = 200,
    ) -> dict:
        """Find the same functions in two open databases by hash (e.g. two builds).

        Read-only. Use before propagate_documentation to see what would match.
        A hash counts only when it occurs exactly once in each database; repeated
        hashes are counted in ambiguous and never matched. Returns {algorithm,
        matched, matches: [{source: {address, name}, target: {address, name,
        is_default_name}, hash}] (one page, by target address), has_more,
        ambiguous, source_too_small, source_hashed, target_hashed}.
        """
        source = await _hashes(pool, source_database, algorithm, source_names)
        target = await _hashes(pool, target_database, algorithm, target_names)
        matches, ambiguous, too_small = match_unique(source, target)
        return {
            "algorithm": algorithm,
            "matched": len(matches),
            "matches": matches[offset : offset + limit],
            "has_more": offset + limit < len(matches),
            "ambiguous": ambiguous,
            "source_too_small": too_small,
            "source_hashed": len(source),
            "target_hashed": len(target),
        }

    @mcp.tool(annotations={"title": "Propagate Documentation"})
    async def propagate_documentation(
        source_database: SourceDb,
        target_database: TargetDb,
        algorithm: Algorithm = "fid_specific",
        fields: Annotated[
            list[
                Literal[
                    "name",
                    "prototype",
                    "plate",
                    "comments",
                    "labels",
                    "locals",
                    "tags",
                    "no_return",
                ]
            ],
            Field(
                description=(
                    "What to copy. comments and labels need bodies of identical layout. "
                    'Example: ["name", "prototype", "plate"]'
                )
            ),
        ] = list(FIELDS),  # noqa: B006 -- pydantic copies the default; never mutated
        overwrite: Annotated[
            Literal["default_only", "always"],
            Field(
                description=(
                    "default_only (default): fill in only what the target still has as "
                    "analysis defaults; always: replace the target's own work too. "
                    'Example: "default_only"'
                )
            ),
        ] = "default_only",
        dry_run: Annotated[
            bool,
            Field(description="Apply, report, then roll everything back. Example: true"),
        ] = False,
        max_functions: Annotated[
            int,
            Field(ge=1, le=20000, description="Most matches to apply. Example: 2000"),
        ] = DEFAULT_MAX_FUNCTIONS,
    ) -> dict:
        """Copy names, prototypes and comments to the matching functions of another database.

        Use when a new build or a related binary contains functions you already
        documented. Matches named source functions by hash (unique on both sides,
        as match_functions), copies the data types their prototypes and locals
        use, then applies everything to the target as ONE change: one undo step
        "MCP: propagate from <source>"; any error rolls all of it back. Save the
        target afterwards. Returns {matched, applied: {field: count}, skipped:
        [{address, field, reason}], types_added, ambiguous, dry_run, undo_name,
        revision}.
        """
        source = await _hashes(pool, source_database, algorithm, "named")
        target = await _hashes(pool, target_database, algorithm, "all")
        matches, ambiguous, _ = match_unique(source, target)
        matches = matches[:max_functions]
        if not matches:
            return {
                "matched": 0,
                "applied": {},
                "skipped": [],
                "types_added": [],
                "ambiguous": ambiguous,
                "dry_run": dry_run,
                "undo_name": None,
                "revision": None,
            }

        docs: list[dict] = []
        for start in range(0, len(matches), DOC_EXPORT_CHUNK):
            chunk = matches[start : start + DOC_EXPORT_CHUNK]
            ops = [
                {
                    "tool": "get_function_documentation",
                    "params": {"address": m["source"]["address"]},
                }
                for m in chunk
            ]
            out = await _call(pool, source_database, "_batch", {"ops": ops, "dry_run": True})
            docs.extend(out["results"])

        paths = sorted({p for d in docs for p in d.get("types_used", [])})
        workdir = tempfile.mkdtemp(prefix="ghidra-mcp-types-")
        archive = os.path.join(workdir, "types.gdt")
        try:
            await _call(
                pool, source_database, "_export_types", {"paths": paths, "archive": archive}
            )
            entries = [
                {"address": m["target"]["address"], "documentation": d}
                for m, d in zip(matches, docs, strict=True)
            ]
            result = await _call(
                pool,
                target_database,
                "_batch",
                {
                    "ops": [
                        {"tool": "_import_types", "params": {"archive": archive}},
                        {
                            "tool": "apply_function_documentation",
                            "params": {
                                "entries": entries,
                                "fields": fields,
                                "overwrite": overwrite,
                            },
                        },
                    ],
                    "label": f"propagate from {source_database}",
                    "dry_run": dry_run,
                },
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        imported, report = result["results"]
        return {
            "matched": len(matches),
            "applied": report["applied"],
            "skipped": report["skipped"],
            "types_added": imported["added"],
            "ambiguous": ambiguous,
            "dry_run": dry_run,
            "undo_name": result.get("undo_name"),
            "revision": result.get("revision"),
        }
