# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra Version Tracking (VT) sessions inside the destination worker.

VT needs both programs in one JVM, and each database lives in its own worker.
So the session runs in the DESTINATION worker, and the source program is
opened read-only from its saved project, without taking the project lock
(``DefaultProjectData(locator, False, False)`` + ``getReadOnlyDomainObject``).
It sees only the source's SAVED state: the supervisor saves the source first.

Measured on Ghidra 12.0.3 and 12.2 (context/design.md, "Version Tracking"):

- ``VTSessionDB`` joins the destination's transaction manager
  (``addSynchronizedDomainObject``). Joining and leaving clear the
  destination's undo history; while joined, one transaction and one undo
  step cover both, so ``undo`` of an apply reverts the markup AND the
  association status. Correlate, accept and auto-VT are therefore ordinary
  atomic write tools (one "MCP: <tool>" step each); only opening and closing
  a session must run outside a transaction.
- A session stores its programs as file IDs of ONE project, so a session
  whose source lives in another project cannot be reopened from disk. Sessions
  live for the worker's lifetime and are released before the program closes.
- Reference correlators (and BSim seeding) work from ACCEPTED associations:
  on a fresh session they find nothing until exact matches are accepted.

    supervisor (no JVM)              destination worker (JVM)
    -------------------              ------------------------
    _vt_source_info  -> source worker   (project dir, program path, saved?)
    _vt_open         -> destination     VTSessionDB(src read-only, dst)
    correlate / matches / apply / auto  one undo step each on dst + VT
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from fastmcp import FastMCP
from pydantic import Field
from re_mcp.helpers import format_address, paginate, parse_address

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE, ANNO_READ_ONLY
from re_mcp_ghidra.session import session

log = logging.getLogger(__name__)

_PROGRAM_PKG = "ghidra.feature.vt.api.correlator.program"

# Our short name -> (package, factory class). BSim lives in its own module.
CORRELATORS: dict[str, tuple[str, str]] = {
    "exact_bytes": (_PROGRAM_PKG, "ExactMatchBytesProgramCorrelatorFactory"),
    "exact_instructions": (_PROGRAM_PKG, "ExactMatchInstructionsProgramCorrelatorFactory"),
    "exact_mnemonics": (_PROGRAM_PKG, "ExactMatchMnemonicsProgramCorrelatorFactory"),
    "symbol_name": (_PROGRAM_PKG, "SymbolNameProgramCorrelatorFactory"),
    "similar_symbol_name": (_PROGRAM_PKG, "SimilarSymbolNameProgramCorrelatorFactory"),
    "duplicate_symbol_name": (_PROGRAM_PKG, "DuplicateSymbolNameProgramCorrelatorFactory"),
    "exact_data": (_PROGRAM_PKG, "ExactDataMatchProgramCorrelatorFactory"),
    "similar_data": (_PROGRAM_PKG, "SimilarDataProgramCorrelatorFactory"),
    "duplicate_data": (_PROGRAM_PKG, "DuplicateDataMatchProgramCorrelatorFactory"),
    "duplicate_function": (_PROGRAM_PKG, "DuplicateFunctionMatchProgramCorrelatorFactory"),
    "function_reference": (_PROGRAM_PKG, "FunctionReferenceProgramCorrelatorFactory"),
    "data_reference": (_PROGRAM_PKG, "DataReferenceProgramCorrelatorFactory"),
    "combined_reference": (
        _PROGRAM_PKG,
        "CombinedFunctionAndDataReferenceProgramCorrelatorFactory",
    ),
    "bsim": ("ghidra.feature.vt.api", "BSimProgramCorrelatorFactory"),
}
CorrelatorName = Literal[
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
# Correlators whose one-to-one matches seed the reference and BSim correlators:
# identical code, plus identical symbol names (exported functions). Adding
# symbol_name raised vt's recall from 0.04 to 0.39 and from 0.23 to 0.49 on the
# two liblzma pairs at precision 1.0 (context/matching-measurements.md).
SEED_CORRELATORS = ("exact_bytes", "exact_instructions", "exact_mnemonics", "symbol_name")
MATCH_ALGORITHMS = {
    "vt": (*SEED_CORRELATORS, "duplicate_function", "combined_reference"),
    "bsim": (*SEED_CORRELATORS, "bsim"),
}

# A best-view pair must beat the runner-up for its source and its destination
# by this much similarity; close calls stay unmatched (same rule as fuzzy).
BEST_MARGIN = 0.05
DEFAULT_TIMEOUT_S = 600
MAX_TIMEOUT_S = 3600
MAX_APPLY_PAIRS = 20000

FIELDS = ("name", "prototype", "plate", "comments", "labels", "data_type")
# VT markup type class -> our field name (propagate_documentation's vocabulary).
MARKUP_FIELDS = {
    "FunctionNameMarkupType": "name",
    "FunctionSignatureMarkupType": "prototype",
    "PlateCommentMarkupType": "plate",
    "PreCommentMarkupType": "comments",
    "EolCommentMarkupType": "comments",
    "PostCommentMarkupType": "comments",
    "RepeatableCommentMarkupType": "comments",
    "LabelMarkupType": "labels",
    "DataTypeMarkupType": "data_type",
}

SessionName = Annotated[
    str,
    Field(
        description=(
            'Version Tracking session name (version_track_sessions lists them). Example: "v1_to_v2"'
        )
    ),
]


@dataclass
class _Live:
    """One open VT session and what it holds."""

    name: str
    vt: Any
    source: Any
    project_data: Any
    consumer: Any
    source_project: str
    source_program: str
    source_revision: int
    opened: float = field(default_factory=time.time)

    def release(self) -> None:
        # VT first: it holds both programs as a consumer.
        for step in (
            lambda: self.vt.release(self.consumer),
            lambda: self.source.release(self.consumer),
            self.project_data.close,
        ):
            try:
                step()
            except Exception:
                log.exception("Error releasing Version Tracking session %s", self.name)


_sessions: dict[str, _Live] = {}


def _key(name: str) -> str:
    return f"vt:{name}"


def _get(name: str) -> _Live:
    live = _sessions.get(name)
    if live is None:
        known = ", ".join(sorted(_sessions)) or "none"
        raise GhidraError(
            f"No Version Tracking session {name!r} on this database (open: {known}). "
            "version_track opens one.",
            error_type="NotFound",
        )
    return live


def _factory(name: str):
    import importlib  # noqa: PLC0415

    package, cls = CORRELATORS[name]
    return getattr(importlib.import_module(package), cls)()


def _display_to_short() -> dict[str, str]:
    """Factory display name ("Exact Function Bytes Match") -> our short name."""
    out = {}
    for short in CORRELATORS:
        try:
            out[str(_factory(short).getName())] = short
        except Exception:
            log.debug("correlator %s unavailable", short, exc_info=True)
    return out


def _set_options(opts, short: str, values: dict[str, Any]) -> None:
    """Set correlator options by their Ghidra names, checking names and types."""
    names = sorted(str(n) for n in opts.getOptionNames())
    for key, value in values.items():
        if key not in names:
            raise GhidraError(
                f"{short} has no option {key!r}. Its options: {', '.join(names)}.",
                error_type="InvalidArguments",
            )
        kind = str(opts.getType(key))
        try:
            if kind == "BOOLEAN_TYPE":
                opts.setBoolean(key, bool(value))
            elif kind == "INT_TYPE":
                opts.setInt(key, int(value))
            elif kind == "LONG_TYPE":
                opts.setLong(key, int(value))
            elif kind in ("DOUBLE_TYPE", "FLOAT_TYPE"):
                opts.setDouble(key, float(value))
            elif kind == "STRING_TYPE":
                opts.setString(key, str(value))
            elif kind == "ENUM_TYPE":
                constants = opts.getObject(key, None).getClass().getEnumConstants()
                chosen = next((c for c in constants if str(c.name()) == str(value)), None)
                if chosen is None:
                    choices = ", ".join(str(c.name()) for c in constants)
                    raise GhidraError(
                        f"{short} option {key!r} is one of: {choices}.",
                        error_type="InvalidArguments",
                    )
                opts.setEnum(key, chosen)
            else:
                raise GhidraError(
                    f"Option {key!r} of {short} has type {kind}, which cannot be set here.",
                    error_type="InvalidArguments",
                )
        except GhidraError:
            raise
        except Exception as exc:
            raise GhidraError(
                f"Cannot set {short} option {key!r} to {value!r}: {exc}",
                error_type="InvalidArguments",
            ) from exc


def _address(program, text: str):
    """Parse an address in *program*: hex/decimal, "SPACE:offset" as _fmt writes it
    for other spaces (imports live in EXTERNAL), or a function/label name."""
    text = str(text).strip()
    if ":" in text and not text.lower().startswith("0x"):
        spaced = program.getAddressFactory().getAddress(text)
        if spaced is not None:
            return spaced
    try:
        return (
            program.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(parse_address(str(text)))
        )
    except ValueError:
        pass
    for sym in program.getSymbolTable().getSymbols(str(text)):
        return sym.getAddress()
    raise GhidraError(
        f"{text!r} is not an address or a symbol in {program.getName()}.",
        error_type="InvalidAddress",
    )


def _fmt(program, addr) -> str:
    """Hex for *program*'s default space, Ghidra's "SPACE:offset" for any other.

    Only the offset would turn an import (EXTERNAL:00000001) into RAM 0x1,
    which then names a different place or nothing.
    """
    if addr.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace()):
        return format_address(addr.getOffset())
    return str(addr)


def _in_memory(program, text: str) -> bool:
    return _address(program, text).isMemoryAddress()


def _name_at(program, addr) -> str:
    func = program.getFunctionManager().getFunctionAt(addr)
    if func is not None:
        return str(func.getName())
    sym = program.getSymbolTable().getPrimarySymbol(addr)
    return str(sym.getName()) if sym is not None else ""


def _is_default(program, addr) -> bool:
    from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

    sym = program.getSymbolTable().getPrimarySymbol(addr)
    return sym is None or sym.getSource() == SourceType.DEFAULT


def _excluding_accepted(live: _Live):
    """Loaded memory of both programs minus the bodies of accepted associations.

    What the VT wizard's "exclude accepted matches" does: later correlators
    only look at what is still unmatched.
    """
    src, dst = live.source, session.program
    src_set = src.getMemory().getLoadedAndInitializedAddressSet()
    dst_set = dst.getMemory().getLoadedAndInitializedAddressSet()
    for assoc in live.vt.getAssociationManager().getAssociations():
        if str(assoc.getStatus()) != "ACCEPTED":
            continue
        for program, addr, is_src in (
            (src, assoc.getSourceAddress(), True),
            (dst, assoc.getDestinationAddress(), False),
        ):
            body = _body(program, addr)
            if body is None:
                continue
            if is_src:
                src_set = src_set.subtract(body)
            else:
                dst_set = dst_set.subtract(body)
    return src_set, dst_set


def _body(program, addr):
    from ghidra.program.model.address import AddressSet  # noqa: PLC0415

    func = program.getFunctionManager().getFunctionAt(addr)
    if func is not None:
        return func.getBody()
    data = program.getListing().getDataAt(addr)
    if data is not None:
        return AddressSet(data.getMinAddress(), data.getMaxAddress())
    return None


def _monitor(timeout_s: int):
    from ghidra.util.task import TaskMonitor, TimeoutTaskMonitor  # noqa: PLC0415
    from java.util.concurrent import TimeUnit  # noqa: PLC0415

    return TimeoutTaskMonitor.timeoutIn(timeout_s, TimeUnit.SECONDS, TaskMonitor.DUMMY)


def correlate(
    live: _Live,
    names: list[str],
    options: dict[str, dict[str, Any]] | None,
    exclude_accepted: bool,
    timeout_s: int,
) -> list[dict]:
    """Run correlators in order inside the open transaction. Raises on any failure."""
    from ghidra.util.exception import CancelledException  # noqa: PLC0415

    options = options or {}
    unknown = sorted(set(options) - set(names))
    if unknown:
        raise GhidraError(
            f"options given for correlators that are not run: {', '.join(unknown)}.",
            error_type="InvalidArguments",
        )
    runs = []
    monitor = _monitor(timeout_s)
    for name in names:
        _settle_accepted_cache(live.vt)
        start = time.time()
        factory = _factory(name)
        opts = factory.createDefaultOptions()
        _set_options(opts, name, options.get(name, {}))
        if exclude_accepted:
            src_set, dst_set = _excluding_accepted(live)
        else:
            src_set = live.source.getMemory().getLoadedAndInitializedAddressSet()
            dst_set = session.program.getMemory().getLoadedAndInitializedAddressSet()
        try:
            correlator = factory.createCorrelator(
                live.source, src_set, session.program, dst_set, opts
            )
            match_set = correlator.correlate(live.vt, monitor)
        except CancelledException as exc:
            raise GhidraError(
                f"Correlator {name} did not finish within timeout_s={timeout_s}; "
                "nothing was kept. Raise timeout_s (BSim decompiles every function).",
                error_type="TimeoutError",
            ) from exc
        except Exception as exc:
            raise GhidraError(
                f"Correlator {name} failed: {exc}. Nothing from this call was kept.",
                error_type="CorrelatorFailed",
            ) from exc
        runs.append(
            {
                "correlator": name,
                "matches": int(match_set.getMatchCount()),
                "seconds": round(time.time() - start, 2),
            }
        )
    return runs


def _rows(live: _Live, kind: str) -> list[dict]:
    """Every match of every match set, one row each (no cross-correlator merging)."""
    shorts = _display_to_short()
    src, dst = live.source, session.program
    rows = []
    for match_set in live.vt.getMatchSets():
        display = str(match_set.getProgramCorrelatorInfo().getName())
        corr = shorts.get(display, display)
        for match in match_set.getMatches():
            assoc = match.getAssociation()
            assoc_type = str(assoc.getType()).lower()
            if kind != "all" and assoc_type != kind:
                continue
            s_addr, d_addr = assoc.getSourceAddress(), assoc.getDestinationAddress()
            rows.append(
                {
                    "source": _fmt(src, s_addr),
                    "destination": _fmt(dst, d_addr),
                    "source_name": _name_at(src, s_addr),
                    "destination_name": _name_at(dst, d_addr),
                    "source_is_default_name": _is_default(src, s_addr),
                    "destination_is_default_name": _is_default(dst, d_addr),
                    "similarity": float(match.getSimilarityScore().getScore()),
                    "confidence": float(match.getConfidenceScore().getScore()),
                    "correlator": corr,
                    "status": str(assoc.getStatus()).lower(),
                    "type": assoc_type,
                    "source_length": int(match.getSourceLength()),
                }
            )
    return rows


def best(rows: list[dict]) -> list[dict]:
    """Merge rows per (source, destination) and keep a one-to-one subset.

    A pair is kept when it is accepted, or when its best similarity beats every
    other candidate of its source AND of its destination by BEST_MARGIN.
    Accepted pairs always win (VT blocks anything conflicting with them).
    Never emits two pairs with the same source or the same destination.
    """
    pairs: dict[tuple[str, str], dict] = {}
    for row in rows:
        key = (row["source"], row["destination"])
        cur = pairs.get(key)
        if cur is None:
            cur = {**row, "correlators": []}
            del cur["correlator"]
            pairs[key] = cur
        cur["correlators"].append(row["correlator"])
        cur["similarity"] = max(cur["similarity"], row["similarity"])
        cur["confidence"] = max(cur["confidence"], row["confidence"])

    by_src: dict[str, list[dict]] = {}
    by_dst: dict[str, list[dict]] = {}
    for pair in pairs.values():
        by_src.setdefault(pair["source"], []).append(pair)
        by_dst.setdefault(pair["destination"], []).append(pair)

    def wins(pair: dict, rivals: list[dict]) -> bool:
        others = [p for p in rivals if p is not pair]
        if any(p["status"] == "accepted" for p in others):
            return False
        if pair["status"] == "accepted":
            return True
        return all(pair["similarity"] >= p["similarity"] + BEST_MARGIN for p in others)

    out = [
        p
        for p in pairs.values()
        if wins(p, by_src[p["source"]]) and wins(p, by_dst[p["destination"]])
    ]
    out.sort(key=lambda p: p["destination"])
    return out


def _filter(
    rows: list[dict],
    correlator: str | None,
    min_similarity: float,
    min_confidence: float,
    status: str | None,
) -> list[dict]:
    out = []
    for row in rows:
        if correlator and correlator not in row.get("correlators", [row.get("correlator")]):
            continue
        if row["similarity"] < min_similarity or row["confidence"] < min_confidence:
            continue
        if status and row["status"] != status:
            continue
        out.append(row)
    return out


def _options(fields: list[str], overwrite: str):
    """VTOptions that apply exactly *fields*, with our overwrite semantics."""
    from ghidra.feature.vt.api.util import VTOptions  # noqa: PLC0415
    from ghidra.feature.vt.gui.util import VTMatchApplyChoices as C  # noqa: PLC0415
    from ghidra.feature.vt.gui.util import VTOptionDefines as D  # noqa: PLC0415

    CommentChoices = C.CommentChoices
    FunctionNameChoices = C.FunctionNameChoices
    FunctionSignatureChoices = C.FunctionSignatureChoices
    LabelChoices = C.LabelChoices
    ParameterDataTypeChoices = C.ParameterDataTypeChoices
    ReplaceDataChoices = C.ReplaceDataChoices
    SourcePriorityChoices = C.SourcePriorityChoices

    always = overwrite == "always"
    opts = VTOptions("ghidra-mcp-next")
    want = set(fields)
    opts.setEnum(
        D.FUNCTION_NAME,
        (FunctionNameChoices.REPLACE_ALWAYS if always else FunctionNameChoices.REPLACE_DEFAULT_ONLY)
        if "name" in want
        else FunctionNameChoices.EXCLUDE,
    )
    opts.setEnum(
        D.FUNCTION_SIGNATURE,
        FunctionSignatureChoices.REPLACE
        if "prototype" in want
        else FunctionSignatureChoices.EXCLUDE,
    )
    types = (
        ParameterDataTypeChoices.REPLACE
        if always
        else ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY
    )
    opts.setEnum(D.FUNCTION_RETURN_TYPE, types)
    opts.setEnum(D.PARAMETER_DATA_TYPES, types)
    opts.setEnum(
        D.PARAMETER_NAMES,
        SourcePriorityChoices.REPLACE if always else SourcePriorityChoices.REPLACE_DEFAULTS_ONLY,
    )
    comment = (
        (CommentChoices.OVERWRITE_EXISTING if always else CommentChoices.APPEND_TO_EXISTING)
        if "comments" in want
        else CommentChoices.EXCLUDE
    )
    for key in (D.PRE_COMMENT, D.END_OF_LINE_COMMENT, D.POST_COMMENT, D.REPEATABLE_COMMENT):
        opts.setEnum(key, comment)
    opts.setEnum(
        D.PLATE_COMMENT,
        (CommentChoices.OVERWRITE_EXISTING if always else CommentChoices.APPEND_TO_EXISTING)
        if "plate" in want
        else CommentChoices.EXCLUDE,
    )
    opts.setEnum(
        D.LABELS,
        (LabelChoices.REPLACE_ALL if always else LabelChoices.REPLACE_DEFAULT_ONLY)
        if "labels" in want
        else LabelChoices.EXCLUDE,
    )
    opts.setEnum(
        D.DATA_MATCH_DATA_TYPE,
        (
            ReplaceDataChoices.REPLACE_ALL_DATA
            if always
            else ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY
        )
        if "data_type" in want
        else ReplaceDataChoices.EXCLUDE,
    )
    return opts


def _association(live: _Live, src_addr, dst_addr):
    """The association for a pair; a manual match is created when VT found none."""
    from ghidra.feature.vt.api.main import (  # noqa: PLC0415
        VTAssociationType,
        VTMatchInfo,
        VTScore,
    )

    manager = live.vt.getAssociationManager()
    assoc = manager.getAssociation(src_addr, dst_addr)
    if assoc is not None:
        return assoc, False
    s_func = live.source.getFunctionManager().getFunctionAt(src_addr)
    d_func = session.program.getFunctionManager().getFunctionAt(dst_addr)
    if s_func is None or d_func is None:
        return None, False
    manual = live.vt.getManualMatchSet()
    info = VTMatchInfo(manual)
    info.setSourceAddress(src_addr)
    info.setDestinationAddress(dst_addr)
    info.setSourceLength(int(s_func.getBody().getNumAddresses()))
    info.setDestinationLength(int(d_func.getBody().getNumAddresses()))
    info.setSimilarityScore(VTScore(1.0))
    info.setConfidenceScore(VTScore(1.0))
    info.setAssociationType(VTAssociationType.FUNCTION)
    info.setTag(None)
    return manual.addMatch(info).getAssociation(), True


def _settle_accepted_cache(vt) -> None:
    """Reload VT's accepted-association cache now, outside any lock.

    Ghidra 12.2 bug: AcceptedStatusCache.isBlocked holds the session's read
    lock and, when the cache was invalidated (any undo or rolled-back
    transaction) and accepted associations exist, reloads it there; the
    reload's add() then takes the write lock. ReentrantReadWriteLock never
    upgrades read to write, so the thread waits forever, and no TaskMonitor
    is checked. It fires when a NEW association is created after an undo:
    a correlator's new match or a manual match. Measured in CI (stack dump)
    and reproduced locally on 12.2. Loading the cache here, with no lock
    held, leaves isBlocked nothing to reload. Before 12.2 the lock is a
    plain reentrant mutex and this is a harmless reload.
    """
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    try:
        manager = vt.getAssociationManagerDBM()
        field = manager.getClass().getDeclaredField("acceptedStatusCache")
        field.setAccessible(True)
        cache = field.get(manager)
        invalid = cache.getClass().getDeclaredField("invalid")
        invalid.setAccessible(True)
        if not invalid.getBoolean(cache):
            return
        load = cache.getClass().getDeclaredMethod("doLoadAcceptedAssociations", TaskMonitor.class_)
        load.setAccessible(True)
        load.invoke(cache, TaskMonitor.DUMMY)
    except Exception:
        log.warning(
            "Cannot reload VT's accepted-association cache; on Ghidra 12.2 a new "
            "association after an undo can hang",
            exc_info=True,
        )


def _markup_items(assoc):
    """The association's markup items, recomputed from the session database.

    Ghidra caches them per association object and clears that cache only when
    the association record disappears. After a rolled-back transaction or an
    undo the record survives, so the cache still says ADDED for markup that is
    gone, and a later apply silently skips it (measured on 12.0.3: dry_run,
    then apply, copied nothing). The cache field is private; reach it by
    reflection and clear it before every read.
    """
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    try:
        manager = assoc.getClass().getDeclaredField("markupManager")
        manager.setAccessible(True)
        manager.get(assoc).clearCache()
    except Exception:
        log.warning("Cannot clear VT markup cache; statuses may be stale", exc_info=True)
    return assoc.getMarkupItems(TaskMonitor.DUMMY)


def accept_and_apply(
    live: _Live, pairs: list[tuple[str, str]], fields: list[str], overwrite: str
) -> dict:
    """Accept each pair and apply its markup. Runs inside the open transaction."""
    from ghidra.feature.vt.api.main import VTAssociationStatus  # noqa: PLC0415
    from ghidra.feature.vt.api.util import VersionTrackingApplyException  # noqa: PLC0415

    _settle_accepted_cache(live.vt)
    opts = _options(fields, overwrite)
    applied: dict[str, int] = {}
    skipped: list[dict] = []
    accepted = manual = 0
    for s_text, d_text in pairs:
        src_addr = _address(live.source, s_text)
        dst_addr = _address(session.program, d_text)
        where = {
            "source": _fmt(live.source, src_addr),
            "destination": _fmt(session.program, dst_addr),
        }
        assoc, created = _association(live, src_addr, dst_addr)
        if assoc is None:
            skipped.append({**where, "reason": "VT has no such match and one side is no function"})
            continue
        manual += created
        if assoc.getStatus() != VTAssociationStatus.ACCEPTED:
            try:
                assoc.setAccepted()
            except Exception as exc:
                skipped.append({**where, "reason": f"cannot accept: {exc}"})
                continue
            accepted += 1
        for item in _markup_items(assoc):
            kind = str(item.getMarkupType().getClass().getSimpleName())
            field_name = MARKUP_FIELDS.get(kind)
            if field_name not in fields or str(item.getStatus()) != "UNAPPLIED":
                continue
            target = item.getDestinationAddress()
            if target is None or target.toString() == "NO ADDRESS":
                skipped.append({**where, "field": field_name, "reason": "no destination address"})
                continue
            action = item.getMarkupType().getApplyAction(opts)
            if action is None:
                continue
            try:
                item.apply(action, opts)
            except VersionTrackingApplyException as exc:
                skipped.append({**where, "field": field_name, "reason": str(exc.getMessage())})
                continue
            if str(item.getStatus()) in ("UNAPPLIED", "SAME"):
                continue
            applied[field_name] = applied.get(field_name, 0) + 1
    return {"accepted": accepted, "manual_matches": manual, "applied": applied, "skipped": skipped}


def auto(live: _Live, options: dict[str, Any], timeout_s: int) -> dict:
    """Ghidra's Auto Version Tracking (the AutoVersionTrackingScript defaults)."""
    from ghidra.feature.vt.api.util import VTOptions  # noqa: PLC0415
    from ghidra.feature.vt.gui.actions import AutoVersionTrackingTask  # noqa: PLC0415
    from ghidra.util.exception import CancelledException  # noqa: PLC0415

    # Unset options take the AutoVersionTrackingScript defaults (measured).
    opts = VTOptions("ghidra-mcp-next")
    for key, value in options.items():
        full = key if "." in key else f"Auto Version Tracking Options.{key}"
        if isinstance(value, bool):
            opts.setBoolean(full, value)
        elif isinstance(value, int):
            opts.setInt(full, value)
        elif isinstance(value, float):
            opts.setDouble(full, value)
        else:
            raise GhidraError(
                f"Auto Version Tracking option {key!r} needs a bool or number, got {value!r}.",
                error_type="InvalidArguments",
            )
    _settle_accepted_cache(live.vt)
    before = _status_counts(live)
    task = AutoVersionTrackingTask(live.vt, opts)
    start = time.time()
    try:
        task.run(_monitor(timeout_s))
    except CancelledException as exc:
        raise GhidraError(
            f"Auto Version Tracking did not finish within timeout_s={timeout_s}; nothing was kept.",
            error_type="TimeoutError",
        ) from exc
    after = _status_counts(live)
    return {
        "status": str(task.getStatusMsg() or ""),
        "accepted": after.get("accepted", 0) - before.get("accepted", 0),
        "associations": after,
        "seconds": round(time.time() - start, 2),
    }


def _status_counts(live: _Live) -> dict[str, int]:
    counts: dict[str, int] = {}
    for assoc in live.vt.getAssociationManager().getAssociations():
        key = str(assoc.getStatus()).lower()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _describe(live: _Live) -> dict:
    return {
        "session": live.name,
        "source_project": live.source_project,
        "source_program": live.source_program,
        "source_revision": live.source_revision,
        "match_sets": [
            {
                "correlator": str(ms.getProgramCorrelatorInfo().getName()),
                "matches": int(ms.getMatchCount()),
            }
            for ms in live.vt.getMatchSets()
            if ms.getMatchCount()
        ],
        "associations": _status_counts(live),
    }


def open_session(source_project: str, source_program: str, name: str, replace: bool) -> dict:
    """Open (or reuse) VT session *name* with the destination = this worker's program."""
    from ghidra.feature.vt.api.db import VTSessionDB  # noqa: PLC0415
    from ghidra.framework.data import DefaultProjectData  # noqa: PLC0415
    from ghidra.framework.model import DomainFile, ProjectLocator  # noqa: PLC0415
    from ghidra.program.util import GhidraProgramUtilities  # noqa: PLC0415
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415
    from java.lang import Object as JObject  # noqa: PLC0415

    existing = _sessions.get(name)
    if existing is not None:
        same = (existing.source_project, existing.source_program) == (
            source_project,
            source_program,
        )
        if same and not replace:
            return {**_describe(existing), "reused": True, "undo_history_cleared": False}
        if not replace:
            raise GhidraError(
                f"Session {name!r} already tracks {existing.source_program} from "
                f"{existing.source_project}. Pick another session name, or replace=true.",
                error_type="SessionExists",
            )
        close_session(name)

    dst = session.program
    if dst.getCurrentTransactionInfo() is not None:
        raise GhidraError(
            "A Version Tracking session cannot open while a transaction is open.",
            error_type="TransactionOpen",
        )
    if not dst.canSave():
        raise GhidraError(
            "The destination is read-only (a versioned file that is not checked out?). "
            "Version Tracking writes to it; checkout_file first.",
            error_type="ReadOnly",
        )
    if not GhidraProgramUtilities.isAnalyzed(dst):
        raise GhidraError(
            "The destination has not been auto-analyzed; correlators need analysis. "
            "Run run_auto_analysis first.",
            error_type="NotAnalyzed",
        )

    gpr = os.path.realpath(source_project)
    locator = ProjectLocator(os.path.dirname(gpr), os.path.basename(gpr).removesuffix(".gpr"))
    consumer = JObject()
    project_data = None
    src = None
    try:
        # Read-only and lock-free: the source worker keeps its project open.
        project_data = DefaultProjectData(locator, False, False)
        domain_file = project_data.getFile(source_program)
        if domain_file is None:
            raise GhidraError(f"No program {source_program} in {gpr}.", error_type="NotFound")
        src = domain_file.getReadOnlyDomainObject(
            consumer, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY
        )
        if not GhidraProgramUtilities.isAnalyzed(src):
            raise GhidraError(
                "The source has not been auto-analyzed (in its saved state). Analyze "
                "and save it first.",
                error_type="NotAnalyzed",
            )
        had_undo = bool(dst.canUndo() or dst.canRedo())
        vt = VTSessionDB(name, src, dst, consumer)
    except GhidraError:
        _release_partial(src, project_data, consumer)
        raise
    except Exception as exc:
        _release_partial(src, project_data, consumer)
        raise GhidraError(
            f"Cannot open the source {source_program} of {gpr} read-only: {exc}",
            error_type="OpenFailed",
        ) from exc

    live = _Live(
        name=name,
        vt=vt,
        source=src,
        project_data=project_data,
        consumer=consumer,
        source_project=gpr,
        source_program=source_program,
        source_revision=int(src.getModificationNumber()),
    )
    _sessions[name] = live
    session.attach(_key(name), lambda: _forget(name))
    warnings = []
    if src.getLanguageID() != dst.getLanguageID():
        warnings.append(
            f"Source language {src.getLanguageID()} differs from {dst.getLanguageID()}: "
            "byte and instruction correlators will find nothing; use bsim or symbol_name."
        )
    return {
        **_describe(live),
        "reused": False,
        "undo_history_cleared": had_undo,
        "warnings": warnings,
    }


def _release_partial(src, project_data, consumer) -> None:
    if src is not None:
        try:
            src.release(consumer)
        except Exception:
            log.exception("Error releasing source")
    if project_data is not None:
        try:
            project_data.close()
        except Exception:
            log.exception("Error closing source project data")


def _forget(name: str) -> None:
    live = _sessions.pop(name, None)
    if live is not None:
        live.release()


def close_session(name: str) -> None:
    _get(name)
    if session.program.getCurrentTransactionInfo() is not None:
        raise GhidraError(
            "A Version Tracking session cannot close while a transaction is open.",
            error_type="TransactionOpen",
        )
    session.detach(_key(name))


def register(mcp: FastMCP) -> None:
    @mcp.tool(name="_vt_source_info", annotations=ANNO_READ_ONLY, tags={"internal"})
    @session.require_open
    def vt_source_info() -> dict:
        """Internal: where this program's saved copy lives, for opening it as a VT source."""
        from ghidra.program.util import GhidraProgramUtilities  # noqa: PLC0415

        locator = session._project.getProjectLocator()
        program = session.program
        return {
            "project": os.path.join(str(locator.getLocation()), str(locator.getName()) + ".gpr"),
            "program": session._program_path,
            "changed": bool(program.isChanged()),
            "analyzed": bool(GhidraProgramUtilities.isAnalyzed(program)),
        }

    @mcp.tool(name="_vt_open", annotations=ANNO_MUTATE, tags={"internal"})
    @session.require_open
    def vt_open(
        source_project: str, source_program: str, session_name: str, replace: bool = False
    ) -> dict:
        """Internal: open a VT session with this program as destination."""
        return open_session(source_project, source_program, session_name, replace)

    @mcp.tool(name="_vt_match", annotations=ANNO_MUTATE, tags={"internal"})
    @session.require_open
    def vt_match(
        session_name: str, algorithm: Literal["vt", "bsim"], timeout_s: int = DEFAULT_TIMEOUT_S
    ) -> dict:
        """Internal: match_functions(algorithm=vt|bsim) in an open session.

        Runs the exact and symbol-name correlators, accepts their one-to-one function pairs as
        seeds (VT session status only, no markup), then the reference or BSim
        correlator, and returns the one-to-one function pairs.
        """
        live = _get(session_name)
        exact = [c for c in MATCH_ALGORITHMS[algorithm] if c in SEED_CORRELATORS]
        rest = [c for c in MATCH_ALGORITHMS[algorithm] if c not in SEED_CORRELATORS]
        runs = correlate(live, exact, None, True, timeout_s)
        seeds = [
            (p["source"], p["destination"])
            for p in best(_rows(live, "function"))
            if p["status"] == "available"
        ]
        accept_and_apply(live, seeds, [], "default_only")
        runs += correlate(live, rest, None, True, timeout_s)
        # Imports (EXTERNAL space) were seeds; they are not functions of either binary.
        pairs = [
            p
            for p in best(_rows(live, "function"))
            if _in_memory(live.source, p["source"])
            and _in_memory(session.program, p["destination"])
        ]
        return {"runs": runs, "seeds": len(seeds), "pairs": pairs}

    @mcp.tool(name="_vt_auto", annotations=ANNO_MUTATE, tags={"internal"})
    @session.require_open
    def vt_auto(
        session_name: str,
        options: dict[str, Any] | None = None,
        timeout_s: int = DEFAULT_TIMEOUT_S,
    ) -> dict:
        """Internal: Auto Version Tracking in an open session (one undo step)."""
        return auto(_get(session_name), options or {}, timeout_s)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"matching", "version_tracking"})
    @session.require_open
    def version_track_sessions() -> dict:
        """List the Version Tracking sessions open on this (destination) database.

        Sessions are opened by version_track or auto_version_track and live
        until close_version_track or until the database closes. Returns
        {sessions: [{session, source_project, source_program, source_revision,
        match_sets: [{correlator, matches}], associations: {status: count}}]}.
        """
        return {"sessions": [_describe(live) for live in _sessions.values()]}

    @mcp.tool(annotations=ANNO_MUTATE, tags={"matching", "version_tracking"})
    @session.require_open
    def version_track_correlate(
        session_name: SessionName,
        correlators: Annotated[
            list[CorrelatorName],
            Field(
                min_length=1,
                description=(
                    "Ghidra VT correlators, run in order. Exact ones (exact_bytes, "
                    "exact_instructions, exact_mnemonics, exact_data, symbol_name) compare "
                    "directly; duplicate_* pair repeated code or data; *_reference match "
                    "through ACCEPTED neighbours (accept first); bsim compares decompiler "
                    "data flow (slow: decompiles both programs). "
                    'Example: ["exact_bytes", "combined_reference"]'
                ),
            ),
        ],
        options: Annotated[
            dict[str, dict[str, Any]] | None,
            Field(
                description=(
                    "Per-correlator Ghidra options by their Ghidra names; an unknown "
                    "name fails and lists the valid ones. "
                    'Example: {"bsim": {"Confidence Threshold for a Seed": 5.0}}'
                )
            ),
        ] = None,
        exclude_accepted: Annotated[
            bool,
            Field(
                description=(
                    "Skip code and data already in accepted matches, as the VT wizard "
                    "does. Example: true"
                )
            ),
        ] = True,
        timeout_s: Annotated[
            int,
            Field(
                ge=1,
                le=MAX_TIMEOUT_S,
                description="Give up (and keep nothing) after this many seconds. Example: 600",
            ),
        ] = DEFAULT_TIMEOUT_S,
    ) -> dict:
        """Run more Version Tracking correlators in an open session.

        Use after apply_version_tracking has accepted matches, to find changed
        functions through their accepted callers, callees and data
        (combined_reference) or by decompiler similarity (bsim). One undo step;
        any failure or timeout keeps nothing and names the correlator. Returns
        {session, runs: [{correlator, matches, seconds}]}.
        """
        live = _get(session_name)
        return {
            "session": session_name,
            "runs": correlate(live, list(correlators), options, exclude_accepted, timeout_s),
        }

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"matching", "version_tracking"})
    @session.require_open
    def version_track_matches(
        session_name: SessionName,
        view: Annotated[
            Literal["best", "all"],
            Field(
                description=(
                    "best: one row per pair, merged over correlators, one-to-one (each "
                    "kept pair is accepted or clearly ahead of every rival of both its "
                    "functions). all: every match of every correlator, unmerged. "
                    'Example: "best"'
                )
            ),
        ] = "best",
        kind: Annotated[
            Literal["function", "data", "all"],
            Field(description='Match functions, data, or both. Example: "function"'),
        ] = "function",
        correlator: Annotated[
            CorrelatorName | None,
            Field(description='Only matches this correlator found. Example: "bsim"'),
        ] = None,
        min_similarity: Annotated[
            float, Field(ge=0, le=1, description="Lowest similarity score. Example: 0.8")
        ] = 0.0,
        min_confidence: Annotated[
            float,
            Field(
                ge=0,
                description=(
                    "Lowest confidence (correlator-specific scale; BSim: about "
                    "log2 odds). Example: 10"
                ),
            ),
        ] = 0.0,
        status: Annotated[
            Literal["available", "accepted", "blocked", "rejected"] | None,
            Field(description='Only matches with this status. Example: "available"'),
        ] = None,
        offset: Annotated[int, Field(ge=0, description="Skip this many rows. Example: 0")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=5000, description="Most rows to return. Example: 200")
        ] = 200,
    ) -> dict:
        """List the matches of a Version Tracking session.

        Similarity scores are per correlator and not comparable across them:
        exact and symbol correlators give 1.0, reference correlators less even
        for unchanged code. Returns {items: [{source, destination, source_name,
        destination_name, source_is_default_name,
        destination_is_default_name, similarity, confidence,
        correlator | correlators, status, type, source_length}], total,
        has_more}; sorted by destination in best view.
        """
        live = _get(session_name)
        rows = _rows(live, kind)
        if view == "best":
            rows = best(rows)
        return paginate(
            _filter(rows, correlator, min_similarity, min_confidence, status), offset, limit
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"matching", "version_tracking"})
    @session.require_open
    def apply_version_tracking(
        session_name: SessionName,
        pairs: Annotated[
            list[dict[str, str]] | None,
            Field(
                description=(
                    "Pairs to accept: {source, destination} addresses (or names). A pair "
                    "VT did not find becomes a manual match (functions only). Omit to "
                    "accept every best-view function match passing the filters below. "
                    'Example: [{"source": "0x401000", "destination": "0x402000"}]'
                )
            ),
        ] = None,
        fields: Annotated[
            list[Literal["name", "prototype", "plate", "comments", "labels", "data_type"]],
            Field(
                description=(
                    "Markup to copy from source to destination; [] only accepts. "
                    'Example: ["name", "prototype", "plate"]'
                )
            ),
        ] = list(FIELDS),  # noqa: B006 -- pydantic copies the default; never mutated
        overwrite: Annotated[
            Literal["default_only", "always"],
            Field(
                description=(
                    "default_only: replace only analysis-default names, labels and "
                    "undefined types, and append comments; always: replace the "
                    'destination\'s own work too. Example: "default_only"'
                )
            ),
        ] = "default_only",
        correlator: Annotated[
            CorrelatorName | None,
            Field(
                description='Without pairs: only matches this correlator found. Example: "exact_bytes"'
            ),
        ] = None,
        min_similarity: Annotated[
            float,
            Field(ge=0, le=1, description="Without pairs: lowest similarity. Example: 1.0"),
        ] = 1.0,
        min_confidence: Annotated[
            float, Field(ge=0, description="Without pairs: lowest confidence. Example: 0")
        ] = 0.0,
    ) -> dict:
        """Accept Version Tracking matches and copy their markup to the destination.

        Uses Ghidra's own markup rules (names, signatures, comments, labels,
        data types) with propagate_documentation's fields/overwrite vocabulary.
        One undo step covering the destination AND the session; undo reverts
        both. Pairs VT cannot accept (blocked by a conflicting accepted match)
        and markup VT refuses are listed in skipped, not fatal. Use batch with
        dry_run=true to preview. Returns {accepted, manual_matches, applied:
        {field: count}, skipped: [{source, destination, field?, reason}],
        considered}.
        """
        live = _get(session_name)
        if pairs is None:
            rows = _filter(
                best(_rows(live, "function")), correlator, min_similarity, min_confidence, None
            )
            chosen = [(r["source"], r["destination"]) for r in rows if r["status"] != "rejected"]
        else:
            bad = [p for p in pairs if not {"source", "destination"} <= set(p)]
            if bad:
                raise GhidraError(
                    f"Each pair needs source and destination; got {bad[0]}.",
                    error_type="InvalidArguments",
                )
            chosen = [(p["source"], p["destination"]) for p in pairs]
        if len(chosen) > MAX_APPLY_PAIRS:
            raise GhidraError(
                f"{len(chosen)} pairs; at most {MAX_APPLY_PAIRS} per call. Raise "
                "min_similarity, filter by correlator, or pass pairs in chunks.",
                error_type="TooMany",
            )
        return {
            **accept_and_apply(live, chosen, list(fields), overwrite),
            "considered": len(chosen),
        }

    @mcp.tool(annotations=ANNO_MUTATE, tags={"matching", "version_tracking"})
    @session.require_open
    def close_version_track(session_name: SessionName) -> dict:
        """Close a Version Tracking session and release its source program.

        Its matches and statuses are lost (sessions are not saved: their source
        lives in another project). The destination keeps all applied markup.
        Ghidra clears the destination's undo history when a session closes.
        Returns {closed}.
        """
        close_session(session_name)
        return {"closed": session_name}
