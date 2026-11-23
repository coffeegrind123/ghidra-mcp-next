# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Repository-level Ghidra Server operations, run in a short-lived process.

The supervisor has no JVM, and these operations need no open database, so
the management tools (list_repositories, create_repository,
list_repository_files) run ``python -m re_mcp_ghidra.server_admin <cmd>``.
The result is the last stdout line, prefixed with :data:`RESULT_PREFIX` so
JVM and Ghidra log output before it is ignored.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from re_mcp_ghidra.exceptions import GhidraError

RESULT_PREFIX = "GHIDRA_MCP_RESULT "
# JVM start-up plus a server round trip; a slow server gets this long.
ADMIN_TIMEOUT_S = 180


async def run_admin(*args: str) -> dict:
    """Run one admin command in a subprocess; return its result or raise its error."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "re_mcp_ghidra.server_admin",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=dict(os.environ),
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), ADMIN_TIMEOUT_S)
    except TimeoutError:
        proc.kill()
        raise GhidraError(
            f"Ghidra Server command timed out after {ADMIN_TIMEOUT_S}s.",
            error_type="TimeoutError",
        ) from None

    lines = [
        line[len(RESULT_PREFIX) :]
        for line in stdout.decode(errors="replace").splitlines()
        if line.startswith(RESULT_PREFIX)
    ]
    if not lines:
        tail = stderr.decode(errors="replace")[-1500:]
        raise GhidraError(
            f"Ghidra Server command failed (exit {proc.returncode}): {tail}",
            error_type="Failed",
        )
    body = json.loads(lines[-1])
    if "error" in body:
        raise GhidraError(body["error"], error_type=body.get("error_type", "Failed"))
    return body


def _emit(body: dict) -> None:
    print(RESULT_PREFIX + json.dumps(body), flush=True)


def main() -> None:
    import re_mcp_ghidra  # noqa: PLC0415

    command, *args = sys.argv[1:]
    try:
        re_mcp_ghidra.bootstrap()
        from re_mcp_ghidra import server_projects as sp  # noqa: PLC0415
        from re_mcp_ghidra.server_url import (  # noqa: PLC0415
            parse_server_address,
            parse_server_url,
        )

        if command == "list-repositories":
            host, port = parse_server_address(args[0])
            server = sp.connect(host, port)
            _emit({"server": f"{host}:{port}", "repositories": sp.repository_names(server)})
        elif command == "create-repository":
            host, port = parse_server_address(args[0])
            server = sp.connect(host, port)
            name = args[1]
            if name in sp.repository_names(server):
                raise GhidraError(
                    f"Repository {name!r} already exists on {host}.", error_type="AlreadyExists"
                )
            server.createRepository(name)
            _emit(
                {
                    "server": f"{host}:{port}",
                    "repository": name,
                    "url": f"ghidra://{host}:{port}/{name}",
                    "repositories": sp.repository_names(server),
                }
            )
        elif command == "list-files":
            target = parse_server_url(args[0], require_path=False)
            folders, files = sp.list_items(sp.repository(target), target.path)
            _emit(
                {
                    "repository": f"ghidra://{target.host}:{target.port}/{target.repository}",
                    "folders": folders,
                    "files": files,
                }
            )
        else:
            raise GhidraError(f"Unknown command {command!r}", error_type="InvalidArgument")
    except GhidraError as exc:
        _emit({"error": exc.args[0], "error_type": exc.error_type})
    except Exception as exc:
        _emit({"error": f"{type(exc).__name__}: {exc}", "error_type": "Failed"})


if __name__ == "__main__":
    main()
