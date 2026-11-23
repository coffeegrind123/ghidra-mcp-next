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


# Ghidra's repository access levels (ghidra.framework.remote.User).
ACCESS_LEVELS = {"read_only": 0, "write": 1, "admin": 2}
ACCESS_NAMES = {v: k for k, v in ACCESS_LEVELS.items()}


def _acl(repo) -> list[dict]:
    return sorted(
        (
            {"user": str(u.getName()), "access": ACCESS_NAMES.get(int(u.getPermissionType()), "?")}
            for u in repo.getUserList()
        ),
        key=lambda e: e["user"],
    )


def _set_permission(repo, user: str, access: str) -> dict:
    """Merge one user's access into the repository ACL (setUserList replaces it whole)."""
    from ghidra.framework.remote import User  # noqa: PLC0415

    if access != "none" and access not in ACCESS_LEVELS:
        raise GhidraError(f"Unknown access {access!r}.", error_type="InvalidArgument")
    entries = {str(u.getName()): int(u.getPermissionType()) for u in repo.getUserList()}
    if access == "none":
        entries.pop(user, None)
    else:
        entries[user] = ACCESS_LEVELS[access]
    if ACCESS_LEVELS["admin"] not in entries.values():
        raise GhidraError(
            "That would leave the repository without an admin.", error_type="InvalidArgument"
        )
    users = [User(name, level) for name, level in sorted(entries.items())]
    repo.setUserList(users, repo.anonymousAccessAllowed())
    return {"acl": _acl(repo)}


def _checkouts(repo, folder: str) -> list[dict]:
    """Every checkout under *folder*, walked on the server (not the local project)."""
    import datetime  # noqa: PLC0415

    out = []
    pending = [folder or "/"]
    while pending:
        path = pending.pop()
        out.extend(
            {
                "path": str(item.getPathName()),
                "checkout_id": int(co.getCheckoutId()),
                "user": str(co.getUser()),
                "version": int(co.getCheckoutVersion()),
                "exclusive": str(co.getCheckoutType()) == "EXCLUSIVE",
                "date": datetime.datetime.fromtimestamp(
                    int(co.getCheckoutTime()) / 1000, tz=datetime.UTC
                ).isoformat(),
                "project": str(co.getProjectPath() or ""),
            }
            for item in repo.getItemList(path) or []
            for co in repo.getCheckouts(path, item.getName()) or []
        )
        pending.extend(path.rstrip("/") + "/" + str(s) for s in repo.getSubfolderList(path) or [])
    return sorted(out, key=lambda c: (c["path"], c["checkout_id"]))


def _terminate(repo, path: str, checkout_id: int) -> dict:
    folder, _, name = path.rpartition("/")
    folder = folder or "/"
    ids = [int(c.getCheckoutId()) for c in repo.getCheckouts(folder, name) or []]
    if checkout_id not in ids:
        raise GhidraError(
            f"No checkout {checkout_id} on {path} (has: {ids or 'none'}).", error_type="NotFound"
        )
    repo.terminateCheckout(folder, name, checkout_id, False)
    return {"path": path, "terminated": checkout_id}


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
        elif command == "list-users":
            host, port = parse_server_address(args[0])
            server = sp.connect(host, port)
            _emit(
                {"server": f"{host}:{port}", "users": sorted(str(u) for u in server.getAllUsers())}
            )
        elif command == "set-permission":
            target = parse_server_url(args[0], require_path=False)
            _emit(_set_permission(sp.repository(target), args[1], args[2]))
        elif command == "list-checkouts":
            target = parse_server_url(args[0], require_path=False)
            _emit({"checkouts": _checkouts(sp.repository(target), target.path)})
        elif command == "terminate-checkout":
            target = parse_server_url(args[0], require_path=True)
            _emit(_terminate(sp.repository(target), target.path, int(args[1])))
        else:
            raise GhidraError(f"Unknown command {command!r}", error_type="InvalidArgument")
    except GhidraError as exc:
        _emit({"error": exc.args[0], "error_type": exc.error_type})
    except Exception as exc:
        _emit({"error": f"{type(exc).__name__}: {exc}", "error_type": "Failed"})


if __name__ == "__main__":
    main()
