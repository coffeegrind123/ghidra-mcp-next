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
    Literal[
        "fid_specific", "fid_full", "exact_instructions", "exact_bytes", "exact_mnemonics", "fuzzy"
    ],
    Field(
        description=(
            "How to match. fid_specific (default) keeps operand constants: fewest false "
            "matches. fid_full masks constants, so it also matches code relinked at other "
            "addresses. exact_bytes requires identical bytes. fuzzy: exact fid_specific "
            "matches first, then the rest by similarity score (changed functions; review "
            'the scores). Example: "fid_full"'
        )
    ),
]
Threshold = Annotated[
    float,
    Field(
        ge=0.3,
        le=1.0,
        description="fuzzy: lowest similarity score (0-1) accepted. Example: 0.75",
    ),
]
SIG_PAGE = 2000
# A fuzzy pair is kept only if it beats the next-best candidate for either side
# by this much; close calls are left unmatched rather than guessed.
FUZZY_MARGIN = 0.05
DEFAULT_THRESHOLD = 0.75
MAX_DIFF_OPS = 500
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


def _ratio(a: float, b: float) -> float:
    return 1.0 if a == b else 1.0 - abs(a - b) / max(a, b)


def _jaccard(a: list, b: list) -> float | None:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return None
    return len(sa & sb) / len(sa | sb)


def _multiset_overlap(a: list, b: list) -> float:
    if not a and not b:
        return 1.0
    from collections import Counter  # noqa: PLC0415

    ca, cb = Counter(a), Counter(b)
    return sum((ca & cb).values()) / max(len(a), len(b))


def similarity(a: dict, b: dict) -> float:
    """0-1 similarity of two function signatures (export_function_signatures).

    Shape counts (25%), callee/string/constant sets (45%, over the sets either
    side has) and address-free block hashes (30%). With no sets on either side
    the set share moves to the other two, so leaf functions can still match.
    """
    numeric = (
        0.35 * _ratio(a["instructions"], b["instructions"])
        + 0.25 * _ratio(a["blocks"], b["blocks"])
        + 0.20 * _ratio(a["edges"], b["edges"])
        + 0.20 * _ratio(a["calls"], b["calls"])
    )
    parts = [
        (0.5, _jaccard(a["callees"], b["callees"])),
        (0.3, _jaccard(a["strings"], b["strings"])),
        (0.2, _jaccard(a["constants"], b["constants"])),
    ]
    present = [(w, v) for w, v in parts if v is not None]
    structural = _multiset_overlap(a["block_hashes"], b["block_hashes"])
    if not present:
        return round(0.4 * numeric + 0.6 * structural, 4)
    sets = sum(w * v for w, v in present) / sum(w for w, _ in present)
    return round(0.25 * numeric + 0.45 * sets + 0.30 * structural, 4)


def match_fuzzy(
    source: list[dict], target: list[dict], threshold: float, margin: float = FUZZY_MARGIN
) -> list[dict]:
    """One-to-one fuzzy matches, best score first, each clearly ahead of its rivals."""
    target_sorted = sorted(target, key=lambda t: t["instructions"])
    sizes = [t["instructions"] for t in target_sorted]
    import bisect  # noqa: PLC0415

    scored: list[tuple[float, int, int]] = []
    best_for: dict[tuple[str, int], list[float]] = defaultdict(list)
    for si, s_sig in enumerate(source):
        n = s_sig["instructions"]
        lo = bisect.bisect_left(sizes, n / 2)
        hi = bisect.bisect_right(sizes, n * 2)
        for ti in range(lo, hi):
            score = similarity(s_sig, target_sorted[ti])
            if score >= threshold:
                scored.append((score, si, ti))
                best_for[("s", si)].append(score)
                best_for[("t", ti)].append(score)

    def runner_up(key: tuple[str, int]) -> float:
        values = sorted(best_for[key], reverse=True)
        return values[1] if len(values) > 1 else 0.0

    taken_s, taken_t, out = set(), set(), []
    for score, si, ti in sorted(scored, reverse=True):
        if si in taken_s or ti in taken_t:
            continue
        second = max(runner_up(("s", si)), runner_up(("t", ti)))
        if score - second < margin and second > 0:
            continue
        taken_s.add(si)
        taken_t.add(ti)
        s_sig, t_sig = source[si], target_sorted[ti]
        out.append(
            {
                "source": {"address": s_sig["address"], "name": s_sig["name"]},
                "target": {
                    "address": t_sig["address"],
                    "name": t_sig["name"],
                    "is_default_name": t_sig["is_default_name"],
                },
                "score": score,
                "second_best": second,
                "method": "fuzzy",
            }
        )
    return out


async def _signatures(pool, database: str, names: str) -> list[dict]:
    items: list[dict] = []
    offset = 0
    while True:
        page = await _call(
            pool,
            database,
            "export_function_signatures",
            {"names": names, "offset": offset, "limit": SIG_PAGE},
        )
        items.extend(page["items"])
        if not page.get("has_more"):
            return items
        offset += SIG_PAGE


async def find_matches(
    pool,
    source_db: str,
    target_db: str,
    algorithm: str,
    source_names: str,
    target_names: str,
    threshold: float,
) -> dict:
    """Exact (unique-hash) matches, plus fuzzy ones for algorithm="fuzzy"."""
    exact_algo = "fid_specific" if algorithm == "fuzzy" else algorithm
    source = await _hashes(pool, source_db, exact_algo, source_names)
    target = await _hashes(pool, target_db, exact_algo, target_names)
    matches, ambiguous, too_small = match_unique(source, target)
    for m in matches:
        m["method"] = "exact"
    fuzzy_count = 0
    if algorithm == "fuzzy":
        done_s = {m["source"]["address"] for m in matches}
        done_t = {m["target"]["address"] for m in matches}
        s_sigs = [
            x
            for x in await _signatures(pool, source_db, source_names)
            if x["address"] not in done_s
        ]
        t_sigs = [
            x
            for x in await _signatures(pool, target_db, target_names)
            if x["address"] not in done_t
        ]
        fuzzy = match_fuzzy(s_sigs, t_sigs, threshold)
        fuzzy_count = len(fuzzy)
        matches = sorted(matches + fuzzy, key=lambda m: m["target"]["address"])
    return {
        "matches": matches,
        "ambiguous": ambiguous,
        "too_small": too_small,
        "source_hashed": len(source),
        "target_hashed": len(target),
        "fuzzy": fuzzy_count,
    }


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
        threshold: Threshold = DEFAULT_THRESHOLD,
        offset: Annotated[int, Field(ge=0, description="Skip this many matches. Example: 0")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=5000, description="Most matches to return. Example: 200")
        ] = 200,
    ) -> dict:
        """Find the same functions in two open databases (e.g. two builds).

        Read-only. Use before propagate_documentation to see what would match.
        A hash counts only when it occurs exactly once in each database;
        repeated hashes are counted in ambiguous and never matched. fuzzy adds
        one-to-one similarity matches for the rest, each at least threshold and
        clearly ahead of its next-best candidate. Returns {algorithm, matched,
        fuzzy, matches: [{source: {address, name}, target: {address, name,
        is_default_name}, method, hash | score, second_best}] (one page, by
        target address), has_more, ambiguous, source_too_small, source_hashed,
        target_hashed}.
        """
        found = await find_matches(
            pool,
            source_database,
            target_database,
            algorithm,
            source_names,
            target_names,
            threshold,
        )
        matches = found["matches"]
        return {
            "algorithm": algorithm,
            "matched": len(matches),
            "fuzzy": found["fuzzy"],
            "matches": matches[offset : offset + limit],
            "has_more": offset + limit < len(matches),
            "ambiguous": found["ambiguous"],
            "source_too_small": found["too_small"],
            "source_hashed": found["source_hashed"],
            "target_hashed": found["target_hashed"],
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
        threshold: Threshold = DEFAULT_THRESHOLD,
    ) -> dict:
        """Copy names, prototypes and comments to the matching functions of another database.

        Use when a new build or a related binary contains functions you already
        documented. Matches named source functions as match_functions does (by
        unique hash, or also by similarity with algorithm="fuzzy"), copies the data types their prototypes and locals
        use, then applies everything to the target as ONE change: one undo step
        "MCP: propagate from <source>"; any error rolls all of it back. Save the
        target afterwards. Returns {matched, applied: {field: count}, skipped:
        [{address, field, reason}], types_added, ambiguous, dry_run, undo_name,
        revision}.
        """
        found = await find_matches(
            pool, source_database, target_database, algorithm, "named", "all", threshold
        )
        matches, ambiguous = found["matches"][:max_functions], found["ambiguous"]
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
            "fuzzy": found["fuzzy"],
            "applied": report["applied"],
            "skipped": report["skipped"],
            "types_added": imported["added"],
            "ambiguous": ambiguous,
            "dry_run": dry_run,
            "undo_name": result.get("undo_name"),
            "revision": result.get("revision"),
        }

    @mcp.tool(annotations={"title": "Diff Functions Across Databases", "readOnlyHint": True})
    async def diff_functions_across(
        database_a: Annotated[str, Field(description='First database. Example: "app_v1"')],
        address_a: Annotated[
            str, Field(description='Function in database_a. Example: "parse_packet"')
        ],
        database_b: Annotated[str, Field(description='Second database. Example: "app_v2"')],
        address_b: Annotated[str, Field(description='Function in database_b. Example: "0x401230"')],
    ) -> dict:
        """Diff a function in one database against one in another.

        Use after match_functions to see what changed between builds (a fuzzy
        match, or a patched copy); diff_functions compares two functions within
        one database. Branch targets become instruction indexes and calls become
        callee names, so moved code compares equal. Returns {a, b, similarity,
        a_instructions, b_instructions, ops: [{kind, a, b}], truncated}.
        """
        import difflib  # noqa: PLC0415

        a = await _call(pool, database_a, "_normalized_instructions", {"address": address_a})
        b = await _call(pool, database_b, "_normalized_instructions", {"address": address_b})
        la, lb = a["lines"], b["lines"]
        matcher = difflib.SequenceMatcher(a=la, b=lb, autojunk=False)
        ops = [
            {
                "kind": tag,
                "a": la[i1:i2] if tag != "equal" else [f"... {i2 - i1} equal"],
                "b": lb[j1:j2] if tag != "equal" else [],
            }
            for tag, i1, i2, j1, j2 in matcher.get_opcodes()
        ]
        return {
            "a": {"database": database_a, "address": a["address"], "name": a["name"]},
            "b": {"database": database_b, "address": b["address"], "name": b["name"]},
            "similarity": round(matcher.ratio(), 4),
            "a_instructions": len(la),
            "b_instructions": len(lb),
            "ops": ops[:MAX_DIFF_OPS],
            "truncated": len(ops) > MAX_DIFF_OPS,
        }
