# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra Server version control, end to end against a real server.

Starts a throwaway Ghidra Server (from GHIDRA_INSTALL_DIR) on a spare port,
adds a user, seeds a repository with one versioned program, then drives
open-from-URL, checkout, batch edit, checkin, history and undo_checkout
through one MCP session.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from tests.live.test_ghidra_live import GHIDRA, SAMPLE, pytestmark  # noqa: F401


# The server binds a base port and the next two. A fixed base can still be held
# by the previous run's server, so pick a free run of three.
def _free_base_port(start: int = 13300, stop: int = 14000) -> int:
    for base in range(start, stop, 3):
        try:
            with contextlib.ExitStack() as stack:
                for port in range(base, base + 3):
                    sock = stack.enter_context(socket.socket())
                    sock.bind(("127.0.0.1", port))
            return base
        except OSError:
            continue
    raise RuntimeError("no free port range for the test Ghidra Server")


SERVER_PORT = _free_base_port()
USER = "tester"
READER = "reader"
DEFAULT_PASSWORD = "changeme"  # what svrAdmin -add gives a new user
SEED = Path(__file__).with_name("seed_server.py")
STARTUP_TIMEOUT_S = 120


def _wait_for(log: Path, pattern: str, proc: subprocess.Popen) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_S
    while time.monotonic() < deadline:
        if log.exists() and re.search(pattern, log.read_text(errors="replace")):
            return
        if proc.poll() is not None:
            break
        time.sleep(1)
    raise RuntimeError(f"Ghidra Server never logged {pattern!r}:\n{log.read_text()[-3000:]}")


@pytest.fixture(scope="module")
def ghidra_server(tmp_path_factory: pytest.TempPathFactory):
    work = tmp_path_factory.mktemp("server")
    repos = work / "repositories"
    repos.mkdir()
    ghidra = Path(GHIDRA)
    java = shutil.which("java", path=os.path.join(os.environ.get("JAVA_HOME", ""), "bin")) or "java"
    frag = ghidra / "Ghidra/Features/GhidraServer/data/classpath.frag"
    classpath = ":".join(
        line.split("=", 1)[1].replace("${ghidra_home}", str(ghidra))
        for line in frag.read_text().splitlines()
        if "=" in line
    )
    log = work / "server.log"
    proc = subprocess.Popen(
        [
            java,
            "-Djava.net.preferIPv4Stack=true",
            f"-Djava.io.tmpdir={work}",
            "-cp",
            classpath,
            "ghidra.server.remote.GhidraServer",
            "-ip",
            "127.0.0.1",
            f"-p{SERVER_PORT}",
            "-a0",
            "-u",
            str(repos),
        ],
        stdout=log.open("w"),
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for(log, r"Registered Ghidra Server", proc)
        conf = work / "server.conf"
        conf.write_text(f"ghidra.repositories.dir={repos}\n")
        subprocess.run(
            [
                str(ghidra / "support/launch.sh"),
                "fg",
                "jdk",
                "svrAdmin",
                "512M",
                "-Djava.awt.headless=true",
                "ghidra.server.ServerAdmin",
                str(conf),
                "-add",
                USER,
            ],
            check=True,
            capture_output=True,
            timeout=STARTUP_TIMEOUT_S,
        )
        _wait_for(log, rf"User '{USER}' added", proc)
        subprocess.run(
            [
                str(ghidra / "support/launch.sh"),
                "fg",
                "jdk",
                "svrAdmin",
                "512M",
                "-Djava.awt.headless=true",
                "ghidra.server.ServerAdmin",
                str(conf),
                "-add",
                READER,
            ],
            check=True,
            capture_output=True,
            timeout=STARTUP_TIMEOUT_S,
        )
        _wait_for(log, rf"User '{READER}' added", proc)
        binary = work / "sample"
        shutil.copy(SAMPLE, binary)
        seeded = subprocess.run(
            [
                sys.executable,
                str(SEED),
                str(SERVER_PORT),
                USER,
                DEFAULT_PASSWORD,
                str(work / "seed"),
                str(binary),
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        assert "seeded" in seeded.stdout, seeded.stdout + seeded.stderr
        yield work
    finally:
        proc.terminate()
        proc.wait(timeout=30)


async def _scenario(work: Path) -> dict[str, Any]:
    env = {
        **os.environ,
        "GHIDRA_INSTALL_DIR": GHIDRA,
        "GHIDRA_MCP_SERVER_USER": USER,
        "GHIDRA_MCP_SERVER_PASSWORD": DEFAULT_PASSWORD,
        "GHIDRA_MCP_SHARED_PROJECTS": str(work / "shared"),
    }
    supervisor = Path(sys.executable).with_name("re-mcp-ghidra")
    out: dict[str, Any] = {}

    async with Client(StdioTransport(str(supervisor), [], env=env), timeout=900) as client:

        async def call(name: str, /, **args: Any) -> dict[str, Any]:
            result = await client.call_tool(name, args, raise_on_error=False)
            text = result.content[0].text if result.content else ""
            if result.is_error:
                return {"is_error": True, **json.loads(text)}
            data = result.structured_content or {}
            return data.get("result", data) if isinstance(data, dict) else data

        url = f"ghidra://127.0.0.1:{SERVER_PORT}/testrepo/bins/sample"
        db = (await call("open_database", file_path=url, run_auto_analysis=True))["database"]
        await call("wait_for_analysis", database=db)

        async def tool(name: str, /, **params: Any) -> dict[str, Any]:
            return await call("call", tool=name, arguments=params, database=db)

        out["before"] = await tool("get_version_state")
        out["save_readonly"] = await call("save_database", database=db)
        out["checkout"] = await tool("checkout_file")
        first = (await tool("list_functions", limit=1))["items"][0]
        out["first"] = first
        op = {
            "tool": "rename_function",
            "params": {"address": first["start"], "new_name": "vc_named"},
        }
        out["edit"] = await call("batch", database=db, ops=[op], label="vc")
        out["checkin"] = await tool("checkin_file", comment="named via mcp")
        out["history"] = await tool("get_version_history")
        discard = {**op, "params": {**op["params"], "new_name": "discarded"}}
        await call("batch", database=db, ops=[discard])
        out["undo_checkout"] = await tool("undo_checkout")
        out["after_undo"] = await tool("get_function", address=first["start"])
        await call("close_database", database=db)

        # Repository management and sharing a local program.
        server = f"127.0.0.1:{SERVER_PORT}"
        out["created"] = await call(
            "call", tool="create_repository", arguments={"server": server, "name": "shared"}
        )
        out["create_again"] = await call(
            "call", tool="create_repository", arguments={"server": server, "name": "shared"}
        )
        out["repos"] = await call("call", tool="list_repositories", arguments={"server": server})

        local = work / "local" / "sample"
        local.parent.mkdir()
        shutil.copy(SAMPLE, local)
        ldb = (await call("open_database", file_path=str(local), run_auto_analysis=True))[
            "database"
        ]
        await call("wait_for_analysis", database=ldb)
        lfirst = (await call("call", tool="list_functions", arguments={"limit": 1}, database=ldb))[
            "items"
        ][0]
        await call(
            "batch",
            database=ldb,
            ops=[
                {
                    "tool": "rename_function",
                    "params": {"address": lfirst["start"], "new_name": "shared_name"},
                }
            ],
        )
        out["added"] = await call(
            "call",
            tool="add_to_repository",
            database=ldb,
            arguments={"repository": f"ghidra://{server}/shared/imports", "comment": "from local"},
        )
        out["add_again"] = await call(
            "call",
            tool="add_to_repository",
            database=ldb,
            arguments={"repository": f"ghidra://{server}/shared/imports"},
        )
        out["in_batch"] = await call(
            "batch",
            database=ldb,
            ops=[
                {"tool": "add_to_repository", "params": {"repository": f"ghidra://{server}/shared"}}
            ],
        )
        out["files"] = await call(
            "call",
            tool="list_repository_files",
            arguments={"repository": f"ghidra://{server}/shared"},
        )
        await call("close_database", database=ldb)

        sdb = (await call("open_database", file_path=out["added"]["url"]))["database"]
        await call("wait_for_analysis", database=sdb)
        out["users"] = await call("call", tool="list_server_users", arguments={"server": server})
        shared = f"ghidra://{server}/shared"
        out["grant"] = await call(
            "call",
            tool="set_repository_permission",
            arguments={"repository": shared, "user": READER, "access": "read_only"},
        )
        out["revoke"] = await call(
            "call",
            tool="set_repository_permission",
            arguments={"repository": shared, "user": READER, "access": "none"},
        )
        out["last_admin"] = await call(
            "call",
            tool="set_repository_permission",
            arguments={"repository": shared, "user": USER, "access": "write"},
        )

        cdb = (await call("open_database", file_path=f"ghidra://{server}/testrepo/bins/sample"))[
            "database"
        ]
        await call("wait_for_analysis", database=cdb)
        await call("call", tool="checkout_file", arguments={}, database=cdb)
        await call("close_database", database=cdb)
        repo_url = f"ghidra://{server}/testrepo"
        out["checkouts"] = await call(
            "call", tool="list_repository_checkouts", arguments={"repository": repo_url}
        )
        held = out["checkouts"]["checkouts"][0]
        out["terminated"] = await call(
            "call",
            tool="terminate_checkout",
            arguments={"program": f"{repo_url}{held['path']}", "checkout_id": held["checkout_id"]},
        )
        out["after_terminate"] = await call(
            "call", tool="list_repository_checkouts", arguments={"repository": repo_url}
        )

        out["shared_func"] = await call(
            "call", tool="get_function", arguments={"address": lfirst["start"]}, database=sdb
        )
    return out


@pytest.fixture(scope="module")
def run(ghidra_server: Path) -> dict[str, Any]:
    return asyncio.run(_scenario(ghidra_server))


def test_server_program_opens_read_only(run):
    assert run["before"]["versioned"] is True
    assert run["before"]["read_only"] is True
    assert run["save_readonly"]["error_type"] == "ReadOnly"


def test_checkout_makes_it_writable(run):
    assert run["checkout"]["checked_out"] is True
    assert run["checkout"]["can_save"] is True
    assert run["edit"]["applied"] is True


def test_checkin_creates_a_version(run):
    assert run["checkin"]["version"] == 2
    versions = run["history"]["versions"]
    assert [v["version"] for v in versions] == [1, 2]
    assert versions[-1]["comment"] == "named via mcp"


def test_undo_checkout_discards_later_changes(run):
    assert run["undo_checkout"]["checked_out"] is False
    assert run["after_undo"]["name"] == "vc_named"


def test_create_and_list_repositories(run):
    assert run["created"]["repository"] == "shared"
    assert run["create_again"]["error_type"] == "AlreadyExists"
    assert {"testrepo", "shared"} <= set(run["repos"]["repositories"])


def test_add_local_program_to_repository(run):
    added = run["added"]
    assert added["url"].endswith("/shared/imports/sample")
    assert added["version"] == 1
    assert run["add_again"]["error_type"] == "AlreadyExists"
    assert run["in_batch"]["error_type"] == "InvalidOp"
    paths = [f["path"] for f in run["files"]["files"]]
    assert "/imports/sample" in paths
    assert "/imports" in run["files"]["folders"]


def test_shared_copy_keeps_annotations(run):
    assert run["shared_func"]["name"] == "shared_name"


def test_server_users_and_permissions(run):
    assert "users" in run["users"], run["users"]
    assert {USER, READER} <= set(run["users"]["users"])
    assert {"user": READER, "access": "read_only"} in run["grant"]["acl"]
    assert READER not in [e["user"] for e in run["revoke"]["acl"]]
    assert run["last_admin"]["is_error"] is True


def test_list_and_terminate_checkouts(run):
    assert "checkouts" in run["checkouts"], run["checkouts"]
    held = run["checkouts"]["checkouts"]
    assert len(held) == 1 and held[0]["user"] == USER
    assert run["terminated"]["terminated"] == held[0]["checkout_id"]
    assert run["after_terminate"]["checkouts"] == []
