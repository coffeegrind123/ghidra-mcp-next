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
        "fid_specific",
        "fid_full",
        "exact_instructions",
        "exact_bytes",
        "exact_mnemonics",
        "fuzzy",
        "vt",
        "bsim",
    ],
    Field(
        description=(
            "How to match. fid_specific (default) keeps operand constants: fewest false "
            "matches. fid_full masks constants, so it also matches code relinked at other "
            "addresses. exact_bytes requires identical bytes. fuzzy: exact fid_specific "
            "matches first, then the rest by similarity score (changed functions; review "
            "the scores). vt: Ghidra Version Tracking, identical code and identical "
            "symbol names as seeds, then "
            "matches through matched callers, callees and data. bsim: the same seeds, "
            "then BSim decompiler similarity, pairs under confidence 10 dropped (slow; "
            "finds about 3x what fuzzy finds, with more wrong pairs). vt and bsim open a Version Tracking "
            "session on the target, which clears its undo history. "
            'Example: "fid_full"'
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
SessionName = Annotated[
    str,
    Field(
        description=(
            "Name for the Version Tracking session on the target; an open session of "
            'that name and source is reused. Example: "v1_to_v2"'
        )
    ),
]
SaveSource = Annotated[
    bool,
    Field(
        description=(
            "Save the source first if it has unsaved changes (VT reads its saved "
            "state); false refuses instead. Example: true"
        )
    ),
]


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
    if algorithm in VT_ALGORITHMS:
        return await _vt_find_matches(
            pool, source_db, target_db, algorithm, source_names, target_names
        )
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
        "source_items": source,
        "target_items": target,
    }


VT_ALGORITHMS = ("vt", "bsim")
# BSim pairs below this confidence are dropped (accepted exact seeds are kept).
# Measured on two liblzma build pairs with debug-symbol truth: every pair under
# 10 was wrong (11 of 11), and none above it was lost (context/matching-measurements.md).
# 10 is also BSim's own default seed threshold.
BSIM_MIN_CONFIDENCE = 10.0
MATCH_SESSION = "match_functions"


def _names_ok(is_default: bool, names: str) -> bool:
    return names == "all" or (names == "named") != is_default


async def vt_prepare(
    pool, source_db: str, target_db: str, session_name: str, save_source: bool, replace: bool
) -> dict:
    """Open VT session *session_name* in the target worker, the source read from disk.

    The target worker reads the source's SAVED state from its project, so a
    source with unsaved changes is saved first (save_source) or refused.
    """
    from re_mcp_ghidra.exceptions import GhidraError  # noqa: PLC0415

    if source_db == target_db:
        raise GhidraError("Source and target are the same database.", error_type="InvalidArguments")
    info = await _call(pool, source_db, "_vt_source_info", {})
    if info["changed"]:
        if not save_source:
            raise GhidraError(
                f"{source_db} has unsaved changes, and Version Tracking reads its saved "
                "state. Save it (save_database) or pass save_source=true.",
                error_type="UnsavedSource",
            )
        await _call(pool, source_db, "save_database", {"comment": "before version tracking"})
    return await _call(
        pool,
        target_db,
        "_vt_open",
        {
            "source_project": info["project"],
            "source_program": info["program"],
            "session_name": session_name,
            "replace": replace,
        },
    )


async def _vt_find_matches(
    pool, source_db: str, target_db: str, algorithm: str, source_names: str, target_names: str
) -> dict:
    await vt_prepare(pool, source_db, target_db, MATCH_SESSION, True, True)
    found = await _call(
        pool, target_db, "_vt_match", {"session_name": MATCH_SESSION, "algorithm": algorithm}
    )
    kept = [
        p
        for p in found["pairs"]
        if algorithm != "bsim"
        or p["status"] == "accepted"
        or p["confidence"] >= BSIM_MIN_CONFIDENCE
    ]
    matches = [
        {
            "source": {"address": p["source"], "name": p["source_name"]},
            "target": {
                "address": p["destination"],
                "name": p["destination_name"],
                "is_default_name": p["destination_is_default_name"],
            },
            "method": algorithm,
            "correlators": p["correlators"],
            "score": round(p["similarity"], 4),
            "confidence": round(p["confidence"], 4),
        }
        for p in kept
        if _names_ok(p["source_is_default_name"], source_names)
        and _names_ok(p["destination_is_default_name"], target_names)
    ]
    return {
        "matches": matches,
        "ambiguous": 0,
        "too_small": 0,
        "source_hashed": 0,
        "target_hashed": 0,
        "fuzzy": 0,
        "session": MATCH_SESSION,
        "runs": found["runs"],
        "low_confidence_dropped": len(found["pairs"]) - len(kept),
    }


FACTS_PAGE = 2000
UNMATCHED_SHOWN = 50


async def _facts(pool, database: str, addresses: list[str], body_bytes: bool) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for i in range(0, len(addresses), FACTS_PAGE):
        page = await _call(
            pool,
            database,
            "_function_facts",
            {"addresses": addresses[i : i + FACTS_PAGE], "body_bytes": body_bytes},
        )
        out.update({f["address"]: f for f in page["items"]})
    return out


def classify_changes(
    matches: list[dict], src_facts: dict[str, dict], dst_facts: dict[str, dict]
) -> tuple[list[dict], int]:
    """Changed pairs, most changed first, and the number of identical pairs.

    A pair changed when its hashes differ (a fuzzy match: "code"), its callees
    differ ("callees": catches a swapped call target with otherwise identical
    code), its body size differs ("size"), or, when body digests were taken,
    its bytes differ ("bytes": address-dependent, so noisy on relinked
    images; an unreadable body counts as differing). A callee that is itself
    matched compares as its pair, so renaming it on one side (or changing its
    code) does not make its callers look changed; others compare by name, or
    by Function ID hash when unnamed.
    """
    to_target = {m["source"]["address"]: m["target"]["address"] for m in matches}
    matched_targets = set(to_target.values())

    def keyed(callees: list[dict], side: str) -> dict[str, str]:
        out = {}
        for c in callees:
            if side == "source" and c["address"] in to_target:
                key = "pair:" + to_target[c["address"]]
            elif side == "target" and c["address"] in matched_targets:
                key = "pair:" + c["address"]
            else:
                key = c["identity"]
            out[key] = c["name"]
        return out

    changed, identical = [], 0
    for m in matches:
        a = src_facts.get(m["source"]["address"], {})
        b = dst_facts.get(m["target"]["address"], {})
        kinds = []
        if m.get("method") == "fuzzy":
            kinds.append("code")
        ka, kb = keyed(a.get("callees", []), "source"), keyed(b.get("callees", []), "target")
        added = sorted(kb[k] for k in kb.keys() - ka.keys())
        removed = sorted(ka[k] for k in ka.keys() - kb.keys())
        if added or removed:
            kinds.append("callees")
        size_delta = b.get("size", 0) - a.get("size", 0)
        if size_delta:
            kinds.append("size")
        if "body" in a and "body" in b and (a["body"] is None or a["body"] != b["body"]):
            kinds.append("bytes")
        if not kinds:
            identical += 1
            continue
        changed.append(
            {
                "source": m["source"],
                "target": m["target"],
                "similarity": m.get("score", 1.0) if m.get("method") == "fuzzy" else 1.0,
                "change_types": kinds,
                "size_delta": size_delta,
                "callees_added": added,
                "callees_removed": removed,
            }
        )
    changed.sort(
        key=lambda c: (
            c["similarity"],
            -len(c["change_types"]),
            -(len(c["callees_added"]) + len(c["callees_removed"])),
            -abs(c["size_delta"]),
            c["target"]["address"],
        )
    )
    return changed, identical


def unmatched(items: list[dict], matched: set[str]) -> dict:
    rest = [i for i in items if i["address"] not in matched]
    return {
        "total": len(rest),
        "too_small": sum(1 for i in rest if i.get("too_small")),
        "items": [{"address": i["address"], "name": i["name"]} for i in rest[:UNMATCHED_SHOWN]],
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
        is_default_name}, method, hash | score, second_best | correlators}] (one page, by
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
            **{k: found[k] for k in ("session", "low_confidence_dropped") if k in found},
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

    @mcp.tool(annotations={"title": "Diff Strings", "readOnlyHint": True})
    async def diff_strings(
        source_database: Annotated[str, Field(description='The older build. Example: "app_v1"')],
        target_database: Annotated[str, Field(description='The newer build. Example: "app_v2"')],
        what: Annotated[
            Literal["strings", "data"],
            Field(
                description=(
                    "strings: defined string values; data: other defined data as "
                    'type=value (pointers by target name). Example: "strings"'
                )
            ),
        ] = "strings",
        limit: Annotated[
            int, Field(ge=1, le=5000, description="Most values per side. Example: 200")
        ] = 200,
    ) -> dict:
        """List strings (or defined data) added or removed between two builds.

        Use with diff_programs to spot new URLs, commands, error messages,
        keys or protocol constants. Values are compared as a multiset,
        ignoring addresses. Returns {what, source_total, target_total, added:
        [{value, count}], removed: [{value, count}], added_total,
        removed_total}; added and removed each hold at most limit values.
        """
        from collections import Counter  # noqa: PLC0415

        a = Counter(
            (await _call(pool, source_database, "_defined_values", {"what": what}))["values"]
        )
        b = Counter(
            (await _call(pool, target_database, "_defined_values", {"what": what}))["values"]
        )
        added = sorted((b - a).items())
        removed = sorted((a - b).items())
        return {
            "what": what,
            "source_total": sum(a.values()),
            "target_total": sum(b.values()),
            "added": [{"value": v, "count": n} for v, n in added[:limit]],
            "removed": [{"value": v, "count": n} for v, n in removed[:limit]],
            "added_total": len(added),
            "removed_total": len(removed),
        }

    @mcp.tool(annotations={"title": "Diff Programs", "readOnlyHint": True})
    async def diff_programs(
        source_database: Annotated[str, Field(description='The older build. Example: "app_v1"')],
        target_database: Annotated[str, Field(description='The newer build. Example: "app_v2"')],
        include_body_bytes: Annotated[
            bool,
            Field(
                description=(
                    "Also flag pairs whose raw bytes differ (address-dependent: noisy "
                    "when the image was relinked). Example: false"
                )
            ),
        ] = False,
        threshold: Threshold = DEFAULT_THRESHOLD,
        offset: Annotated[int, Field(ge=0, description="Skip this many changes. Example: 0")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=5000, description="Most changes to return. Example: 100")
        ] = 100,
    ) -> dict:
        """Summarise what changed between two builds, function by function.

        Use to triage a patch or a new version: matches every function
        (match_functions with algorithm fuzzy), then flags each pair whose
        code (hash), callees, size or optionally bytes differ; diff_functions_across
        shows one pair in detail. Changes are ranked least similar first.
        Unmatched functions are new, removed, too small to hash or ambiguous;
        they are listed, not guessed. Returns {matched: {identical, changed},
        changes: [{source, target, similarity, change_types, size_delta,
        callees_added, callees_removed}] (one page), has_more, source_unmatched,
        target_unmatched: {total, too_small, items}, analysis_warning}.
        """
        found = await find_matches(
            pool, source_database, target_database, "fuzzy", "all", "all", threshold
        )
        matches = found["matches"]
        src = await _facts(
            pool, source_database, [m["source"]["address"] for m in matches], include_body_bytes
        )
        dst = await _facts(
            pool, target_database, [m["target"]["address"] for m in matches], include_body_bytes
        )
        changed, identical = classify_changes(matches, src, dst)
        warning = None
        for name, items in (
            (source_database, found["source_items"]),
            (target_database, found["target_items"]),
        ):
            tiny = sum(1 for i in items if i.get("size", 0) <= 1)
            if not items or tiny * 2 > len(items):
                warning = (
                    f"{name}: most functions have bodies of 1 byte or none; run "
                    "auto-analysis (wait_for_analysis) before diffing."
                )
        return {
            "matched": {"identical": identical, "changed": len(changed)},
            "changes": changed[offset : offset + limit],
            "has_more": offset + limit < len(changed),
            "source_unmatched": unmatched(
                found["source_items"], {m["source"]["address"] for m in matches}
            ),
            "target_unmatched": unmatched(
                found["target_items"], {m["target"]["address"] for m in matches}
            ),
            "analysis_warning": warning,
        }

    @mcp.tool(annotations={"title": "Diff Functions Across Databases", "readOnlyHint": True})
    async def diff_functions_across(
        database_a: Annotated[str, Field(description='First database. Example: "app_v1"')],
        address_a: Annotated[
            str, Field(description='Function in database_a. Example: "parse_packet"')
        ],
        database_b: Annotated[str, Field(description='Second database. Example: "app_v2"')],
        address_b: Annotated[str, Field(description='Function in database_b. Example: "0x401230"')],
        level: Annotated[
            Literal["instructions", "decompiled"],
            Field(
                description=(
                    "instructions: normalised instruction lines; decompiled: C lines, "
                    'decompiler artifacts separated. Example: "decompiled"'
                )
            ),
        ] = "instructions",
        include_artifacts: Annotated[
            bool,
            Field(
                description=(
                    "decompiled only: also show hunks that differ only by renumbered "
                    "variables or string labels. Example: false"
                )
            ),
        ] = False,
    ) -> dict:
        """Diff a function in one database against one in another.

        Use after match_functions to see what changed between builds (a fuzzy
        match, or a patched copy); diff_functions compares two functions within
        one database. instructions: branch targets become instruction indexes
        and calls become callee names, so moved code compares equal.
        decompiled: C lines with load addresses masked; hunks that only
        renumber auto variables or move string labels go to suppressed.
        Returns {a, b, level, similarity, a_instructions, b_instructions, ops
        (instructions), hunks and suppressed (decompiled), truncated}.
        """
        import difflib  # noqa: PLC0415

        if level == "decompiled":
            from re_mcp_ghidra.cdiff import diff_c  # noqa: PLC0415

            a = await _call(pool, database_a, "_decompiled_lines", {"address": address_a})
            b = await _call(pool, database_b, "_decompiled_lines", {"address": address_b})
            d = diff_c(a["lines"], b["lines"], include_artifacts)
            return {
                "a": {"database": database_a, "address": a["address"], "name": a["name"]},
                "b": {"database": database_b, "address": b["address"], "name": b["name"]},
                "level": level,
                "similarity": d["similarity"],
                "a_instructions": d["a_lines"],
                "b_instructions": d["b_lines"],
                "ops": [],
                "hunks": d["hunks"],
                "suppressed": d["suppressed"],
                "truncated": d["truncated"],
            }

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
            "level": level,
            "similarity": round(matcher.ratio(), 4),
            "a_instructions": len(la),
            "b_instructions": len(lb),
            "ops": ops[:MAX_DIFF_OPS],
            "truncated": len(ops) > MAX_DIFF_OPS,
        }

    @mcp.tool(annotations={"title": "Version Track"})
    async def version_track(
        source_database: SourceDb,
        target_database: TargetDb,
        correlators: Annotated[
            list[
                Literal[
                    "exact_bytes",
                    "exact_instructions",
                    "exact_mnemonics",
                    "symbol_name",
                    "similar_symbol_name",
                    "duplicate_symbol_name",
                    "exact_data",
                    "similar_data",
                    "duplicate_data",
                    "duplicate_function",
                    "function_reference",
                    "data_reference",
                    "combined_reference",
                    "bsim",
                ]
            ],
            Field(
                min_length=1,
                description=(
                    "Ghidra correlators to run, in order. Reference correlators only find "
                    "matches next to ACCEPTED ones: accept first (apply_version_tracking), "
                    "then version_track_correlate. bsim decompiles both programs (slow). "
                    'Example: ["exact_bytes", "exact_instructions", "symbol_name"]'
                ),
            ),
        ] = ["exact_bytes", "exact_instructions", "symbol_name", "duplicate_function"],  # noqa: B006 -- pydantic copies the default
        session_name: SessionName = "default",
        save_source: SaveSource = True,
        limit: Annotated[
            int, Field(ge=1, le=5000, description="Best-view matches to return. Example: 100")
        ] = 100,
    ) -> dict:
        """Open a Ghidra Version Tracking session between two databases and correlate.

        Use to port work from one build to another with Ghidra's own matching
        and markup rules. The session lives in the TARGET database's worker
        (the source is read from its saved project) until close_version_track
        or the target closes. Opening it clears the target's undo history
        (Ghidra joins the two undo stacks). Continue on the target with
        version_track_matches, apply_version_tracking, version_track_correlate.
        Returns {session, runs: [{correlator, matches, seconds}], matches:
        {items (best view), total, has_more}, undo_history_cleared, warnings}.
        """
        opened = await vt_prepare(
            pool, source_database, target_database, session_name, save_source, False
        )
        runs = await _call(
            pool,
            target_database,
            "version_track_correlate",
            {"session_name": session_name, "correlators": correlators},
        )
        matches = await _call(
            pool,
            target_database,
            "version_track_matches",
            {"session_name": session_name, "limit": limit},
        )
        return {
            "session": session_name,
            "reused": opened["reused"],
            "runs": runs["runs"],
            "matches": matches,
            "undo_history_cleared": opened["undo_history_cleared"],
            "warnings": opened.get("warnings", []),
        }

    @mcp.tool(annotations={"title": "Auto Version Track"})
    async def auto_version_track(
        source_database: SourceDb,
        target_database: TargetDb,
        session_name: SessionName = "auto",
        save_source: SaveSource = True,
        options: Annotated[
            dict[str, bool | int | float] | None,
            Field(
                description=(
                    "Ghidra Auto Version Tracking options by name; unset ones keep "
                    "Ghidra's defaults (all correlators, implied matches, min votes 2, "
                    "max conflicts 0, function min length 10). "
                    'Example: {"Run Duplicate Function Correlator": false}'
                )
            ),
        ] = None,
        timeout_s: Annotated[
            int,
            Field(
                ge=1,
                le=3600,
                description="Give up (and keep nothing) after this many seconds. Example: 600",
            ),
        ] = 600,
    ) -> dict:
        """Run Ghidra's Auto Version Tracking: correlate, accept and apply markup in one go.

        Use to carry names, signatures and comments from a documented build to
        a new one without reviewing pairs. Ghidra accepts only well-supported
        matches and applies their markup to the TARGET as one undo step (which
        also reverts the session's statuses). Opening the session clears the
        target's undo history. Save the target afterwards. Returns {session,
        status, accepted, associations: {status: count}, seconds,
        undo_history_cleared}.
        """
        opened = await vt_prepare(
            pool, source_database, target_database, session_name, save_source, False
        )
        result = await _call(
            pool,
            target_database,
            "_vt_auto",
            {"session_name": session_name, "options": options or {}, "timeout_s": timeout_s},
        )
        return {
            "session": session_name,
            **result,
            "undo_history_cleared": opened["undo_history_cleared"],
            "warnings": opened.get("warnings", []),
        }
