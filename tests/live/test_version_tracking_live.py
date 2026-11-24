# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Version Tracking between real databases: sessions, matches, apply, undo, auto."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from tests.live.test_ghidra_live import GHIDRA, SAMPLE, pytestmark  # noqa: F401


async def _scenario(work: Path) -> dict[str, Any]:
    supervisor = Path(sys.executable).with_name("re-mcp-ghidra")
    env = {**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA}
    out: dict[str, Any] = {}
    async with Client(StdioTransport(str(supervisor), [], env=env), timeout=1800) as client:

        async def call(name: str, /, **args: Any) -> dict[str, Any]:
            result = await client.call_tool(name, args, raise_on_error=False)
            text = result.content[0].text if result.content else ""
            if result.is_error:
                return {"is_error": True, "text": text, **_maybe_json(text)}
            data = result.structured_content or {}
            return data.get("result", data) if isinstance(data, dict) else data

        async def tool(db: str, name: str, **args: Any) -> dict[str, Any]:
            return await call("call", tool=name, arguments=args, database=db)

        dbs = []
        for name in ("one", "two", "three"):
            path = work / name / "sample"
            path.parent.mkdir()
            shutil.copy(SAMPLE, path)
            db = (await call("open_database", file_path=str(path), run_auto_analysis=True))[
                "database"
            ]
            await call("wait_for_analysis", database=db)
            dbs.append(db)
        src, dst, third = dbs
        for db in dbs:
            await call("save_database", database=db)

        # A function every copy has, with a default name, to document in the source.
        pairs = (
            await call(
                "match_functions",
                source_database=src,
                target_database=dst,
                source_names="all",
                limit=5000,
            )
        )["matches"]
        pair = next(p for p in pairs if p["target"]["is_default_name"])
        addr = pair["source"]["address"]
        out["addr"] = addr
        documented = await call(
            "batch",
            database=src,
            label="document",
            ops=[
                {"tool": "rename_function", "params": {"address": addr, "new_name": "vt_open"}},
                {
                    "tool": "set_comment",
                    "params": {"address": addr, "comment": "From v1.", "comment_type": "plate"},
                },
            ],
        )
        assert documented.get("results"), documented

        # A pre-existing undo step on the target, to see it cleared.
        await tool(dst, "set_comment", address=addr, comment="pre", comment_type="eol")

        out["unsaved"] = await call(
            "version_track", source_database=src, target_database=dst, save_source=False
        )
        out["track"] = await call(
            "version_track", source_database=src, target_database=dst, session_name="s1"
        )
        out["again"] = await call(
            "version_track",
            source_database=src,
            target_database=dst,
            session_name="s1",
            correlators=["exact_data"],
        )
        out["sessions"] = await tool(dst, "version_track_sessions")
        out["all"] = await tool(
            dst, "version_track_matches", session_name="s1", view="all", limit=5000
        )
        out["best"] = await tool(dst, "version_track_matches", session_name="s1", limit=5000)
        out["bad_option"] = await tool(
            dst,
            "version_track_correlate",
            session_name="s1",
            correlators=["exact_bytes"],
            options={"exact_bytes": {"No Such Option": 1}},
        )
        out["dry"] = await call(
            "batch",
            database=dst,
            dry_run=True,
            ops=[
                {
                    "tool": "apply_version_tracking",
                    "params": {
                        "session_name": "s1",
                        "pairs": [{"source": addr, "destination": addr}],
                        "fields": ["name", "plate"],
                    },
                }
            ],
        )
        out["after_dry"] = await tool(dst, "get_function", address=addr)
        out["apply"] = await tool(
            dst,
            "apply_version_tracking",
            session_name="s1",
            pairs=[{"source": addr, "destination": addr}],
            fields=["name", "plate"],
        )
        out["applied_fn"] = await tool(dst, "get_function", address=addr)
        out["applied_comment"] = await tool(dst, "get_comment", address=addr)
        out["accepted"] = await tool(
            dst, "version_track_matches", session_name="s1", status="accepted"
        )
        out["undo"] = await call("undo", database=dst)
        out["undone_fn"] = await tool(dst, "get_function", address=addr)
        out["undone_accepted"] = await tool(
            dst, "version_track_matches", session_name="s1", status="accepted"
        )
        out["bulk"] = await tool(dst, "apply_version_tracking", session_name="s1", fields=[])
        out["ref"] = await tool(
            dst, "version_track_correlate", session_name="s1", correlators=["combined_reference"]
        )

        out["match_vt"] = await call(
            "match_functions",
            source_database=src,
            target_database=third,
            algorithm="vt",
            source_names="all",
            limit=5000,
        )
        out["match_bsim"] = await call(
            "match_functions",
            source_database=src,
            target_database=third,
            algorithm="bsim",
            source_names="all",
            limit=5000,
        )
        out["auto"] = await call("auto_version_track", source_database=src, target_database=third)
        out["auto_fn"] = await tool(third, "get_function", address=addr)

        out["close"] = await tool(dst, "close_version_track", session_name="s1")
        out["sessions_after"] = await tool(dst, "version_track_sessions")
        out["write_after"] = await tool(dst, "rename_function", address=addr, new_name="after_vt")
        out["save_after"] = await call("save_database", database=dst)
        # Closing a database with an open session releases it cleanly.
        out["close_third"] = await call("close_database", database=third)
        out["same_db"] = await call("version_track", source_database=src, target_database=src)
    return out


def _maybe_json(text: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return asyncio.run(_scenario(tmp_path_factory.mktemp("vt")))


def test_unsaved_source_is_refused(run):
    assert run["unsaved"].get("is_error"), run["unsaved"]
    assert "unsaved" in run["unsaved"]["text"].lower()


def test_version_track_opens_and_correlates(run):
    track = run["track"]
    assert not track.get("is_error"), track
    assert track["reused"] is False
    assert track["undo_history_cleared"] is True
    runs = {r["correlator"]: r["matches"] for r in track["runs"]}
    assert runs["exact_bytes"] > 0 and runs["symbol_name"] > 0
    assert track["matches"]["total"] > 0
    assert run["again"]["reused"] is True
    names = [s["session"] for s in run["sessions"]["sessions"]]
    assert names == ["s1"]


def test_best_view_is_one_to_one(run):
    best = run["best"]["items"]
    assert best
    assert len({p["source"] for p in best}) == len(best)
    assert len({p["destination"] for p in best}) == len(best)
    assert run["all"]["total"] >= len(best)
    assert all("correlators" in p for p in best)


def test_unknown_correlator_option_lists_valid_ones(run):
    assert run["bad_option"].get("is_error"), run["bad_option"]
    assert "No Such Option" in run["bad_option"]["text"]
    assert "options:" in run["bad_option"]["text"]


def test_dry_run_changes_nothing(run):
    assert not run["dry"].get("is_error"), run["dry"]
    assert run["dry"]["results"][0]["applied"].get("name") == 1
    assert run["after_dry"]["name"] != "vt_open"


def test_apply_copies_markup_and_accepts(run):
    applied = run["apply"]
    assert not applied.get("is_error"), applied
    assert applied["accepted"] == 1
    assert applied["applied"] == {"name": 1, "plate": 1}
    assert run["applied_fn"]["name"] == "vt_open"
    assert run["applied_comment"]["plate_comment"] == "From v1."
    assert any(p["source"] == p["destination"] for p in run["accepted"]["items"])


def test_undo_reverts_markup_and_status(run):
    assert run["undo"]["step"] == "MCP: apply_version_tracking"
    assert run["undone_fn"]["name"] != "vt_open"
    assert run["undone_accepted"]["total"] == 0


def test_bulk_accept_then_reference_correlator(run):
    bulk = run["bulk"]
    assert not bulk.get("is_error"), bulk
    assert bulk["accepted"] > 0 and bulk["applied"] == {}
    assert not run["ref"].get("is_error"), run["ref"]
    assert run["ref"]["runs"][0]["correlator"] == "combined_reference"


@pytest.mark.parametrize("algorithm", ["vt", "bsim"])
def test_match_functions_through_vt(run, algorithm):
    found = run[f"match_{algorithm}"]
    assert not found.get("is_error"), found
    assert found["matched"] > 0
    assert found["session"] == "match_functions"
    targets = [m["target"]["address"] for m in found["matches"]]
    assert len(set(targets)) == len(targets)
    assert any(m["source"]["address"] == m["target"]["address"] for m in found["matches"])


def test_auto_version_track_applies(run):
    auto = run["auto"]
    assert not auto.get("is_error"), auto
    assert auto["accepted"] > 0
    assert run["auto_fn"]["name"] == "vt_open"


def test_close_releases_and_target_stays_writable(run):
    assert run["close"]["closed"] == "s1"
    assert run["sessions_after"]["sessions"] == []
    assert not run["write_after"].get("is_error"), run["write_after"]
    assert not run["save_after"].get("is_error"), run["save_after"]
    assert not run["close_third"].get("is_error"), run["close_third"]


def test_same_database_is_refused(run):
    assert run["same_db"].get("is_error")
