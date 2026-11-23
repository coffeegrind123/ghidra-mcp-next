# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Auto-analysis analyzers: list them, turn them on or off, set their options.

Analyzer settings live in the program's "Analyzers" options, so changes are
saved with the database. Options are named "<analyzer>" (enabled flag) and
"<analyzer>.<option>" (its settings).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE, ANNO_READ_ONLY, FilterPattern, compile_filter
from re_mcp_ghidra.session import session


class AnalyzerOption(BaseModel):
    name: str = Field(description="Option name, without the analyzer prefix.")
    type: str = Field(description="Ghidra option type, e.g. BOOLEAN_TYPE, INT_TYPE.")
    value: Any = Field(description="Current value.")
    default: Any = Field(description="Default value.")
    description: str = Field(description="What the option does.")


class AnalyzerInfo(BaseModel):
    name: str = Field(description="Analyzer name, as configure_analyzer takes it.")
    enabled: bool = Field(description="Runs during auto-analysis.")
    default_enabled: bool = Field(description="Enabled by default for this program.")
    type: str = Field(description="What triggers it, e.g. FUNCTION_ANALYZER.")
    priority: str = Field(description="Ordering priority.")
    one_time_supported: bool = Field(description="Can run alone via run_auto_analysis.")
    description: str = Field(description="What it does.")
    options: list[AnalyzerOption] = Field(description="Its settings.")


class AnalyzerList(BaseModel):
    items: list[AnalyzerInfo] = Field(description="Analyzers, by name.")
    total: int = Field(description="Number listed.")


def manager():
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # noqa: PLC0415

    mgr = AutoAnalysisManager.getAnalysisManager(session.program)
    if not list(_options().getOptionNames()):
        mgr.registerAnalyzerOptions()
    return mgr


def _options():
    from ghidra.program.model.listing import Program  # noqa: PLC0415

    return session.program.getOptions(Program.ANALYSIS_PROPERTIES)


def _plain(value: Any, kind: str) -> Any:
    """A Java option value as a JSON value, by its declared option type.

    JPype's boxed Boolean subclasses int, so a type check on the Python value
    would turn false into 0; the option type decides instead.
    """
    if value is None:
        return None
    if kind == "BOOLEAN_TYPE":
        return str(value).lower() in ("true", "1")
    if kind in ("INT_TYPE", "LONG_TYPE"):
        return int(value)
    if kind in ("DOUBLE_TYPE", "FLOAT_TYPE"):
        return float(value)
    return str(value)


def analyzer_info(name: str) -> AnalyzerInfo:
    mgr = manager()
    analyzer = mgr.getAnalyzer(name)
    if analyzer is None:
        raise GhidraError(
            f"No analyzer {name!r}. list_analyzers shows them.", error_type="NotFound"
        )
    opts = _options()
    prefix = name + "."
    sub = []
    for raw in opts.getOptionNames():
        opt = str(raw)
        if not opt.startswith(prefix):
            continue
        kind = str(opts.getType(opt))
        sub.append(
            AnalyzerOption(
                name=opt[len(prefix) :],
                type=kind,
                value=_plain(opts.getObject(opt, None), kind),
                default=_plain(opts.getDefaultValue(opt), kind),
                description=str(opts.getDescription(opt) or ""),
            )
        )
    default = bool(analyzer.getDefaultEnablement(session.program))
    return AnalyzerInfo(
        name=name,
        enabled=bool(opts.getBoolean(name, default)),
        default_enabled=default,
        type=str(analyzer.getAnalysisType()),
        priority=str(analyzer.getPriority()),
        one_time_supported=bool(analyzer.supportsOneTimeAnalysis()),
        description=str(analyzer.getDescription() or ""),
        options=sorted(sub, key=lambda o: o.name),
    )


def analyzer_names() -> list[str]:
    mgr = manager()
    names = []
    for raw in _options().getOptionNames():
        opt = str(raw)
        if "." not in opt and mgr.getAnalyzer(opt) is not None:
            names.append(opt)
    return sorted(names)


def _set_option(opts, full: str, value: Any) -> None:
    kind = str(opts.getType(full))
    try:
        if kind == "BOOLEAN_TYPE":
            opts.setBoolean(full, bool(value))
        elif kind == "INT_TYPE":
            opts.setInt(full, int(value))
        elif kind == "LONG_TYPE":
            opts.setLong(full, int(value))
        elif kind == "DOUBLE_TYPE":
            opts.setDouble(full, float(value))
        elif kind == "FLOAT_TYPE":
            opts.setFloat(full, float(value))
        elif kind == "STRING_TYPE":
            opts.setString(full, str(value))
        elif kind == "ENUM_TYPE":
            current = opts.getObject(full, None)
            opts.setEnum(full, type(current).valueOf(str(value)))
        else:
            raise GhidraError(
                f"Option {full} has type {kind}, which this tool cannot set.",
                error_type="InvalidArgument",
            )
    except GhidraError:
        raise
    except Exception as exc:
        raise GhidraError(
            f"Cannot set {full} to {value!r}: {exc}", error_type="InvalidArgument"
        ) from exc


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def list_analyzers(filter_pattern: FilterPattern = "") -> AnalyzerList:
        """List the program's auto-analysis analyzers with their settings.

        Use before configure_analyzer, or to pick analyzers for
        run_auto_analysis(analyzers=[...]). Returns {items: [{name, enabled,
        default_enabled, type, priority, one_time_supported, description,
        options: [{name, type, value, default, description}]}], total}.
        """
        filt = compile_filter(filter_pattern)
        items = [analyzer_info(n) for n in analyzer_names() if not filt or filt.search(n)]
        return AnalyzerList(items=items, total=len(items))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"analysis"})
    @session.require_open
    def configure_analyzer(
        name: Annotated[
            str, Field(description='Analyzer name from list_analyzers. Example: "Stack"')
        ],
        enabled: Annotated[
            Literal["unchanged", "on", "off"],
            Field(description='Turn it on or off for auto-analysis. Example: "off"'),
        ] = "unchanged",
        options: Annotated[
            dict[str, Any],
            Field(
                description=(
                    "Settings to change, by option name without the analyzer prefix. "
                    'Example: {"Create Local Variables": false}'
                )
            ),
        ] = {},  # noqa: B006 -- pydantic copies the default; never mutated
    ) -> AnalyzerInfo:
        """Turn an analyzer on or off and change its settings.

        Use to stop a slow or harmful analyzer, or tune one, before
        run_auto_analysis. Saved with the database. Fails with NotFound for an
        unknown analyzer or option. Returns the analyzer's updated record (as
        list_analyzers).
        """
        info = analyzer_info(name)
        opts = _options()
        if enabled != "unchanged":
            opts.setBoolean(name, enabled == "on")
        known = {o.name for o in info.options}
        for key, value in options.items():
            if key not in known:
                raise GhidraError(
                    f"{name} has no option {key!r} (has: {', '.join(sorted(known))}).",
                    error_type="NotFound",
                )
            _set_option(opts, f"{name}.{key}", value)
        manager().initializeOptions()
        return analyzer_info(name)
