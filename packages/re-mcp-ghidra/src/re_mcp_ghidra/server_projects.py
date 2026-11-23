# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra Server connections and the local projects bound to repositories.

Engine-required (needs the JVM).  Used by the worker (open from a server,
add_to_repository) and by :mod:`re_mcp_ghidra.server_admin` (the
repository-level management tools, which run without an open database).
"""

from __future__ import annotations

import os

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.server_url import ServerProgram

SERVER_USER_ENV = "GHIDRA_MCP_SERVER_USER"
SERVER_PASSWORD_ENV = "GHIDRA_MCP_SERVER_PASSWORD"
# Local projects bound to Ghidra Server repositories (one per host/port/repo).
SHARED_PROJECTS_DIR = os.environ.get(
    "GHIDRA_MCP_SHARED_PROJECTS",
    os.path.join(os.path.expanduser("~"), ".local", "share", "ghidra-mcp-next", "shared"),
)


def connect(host: str, port: int):
    """Connect to a Ghidra Server with the environment's credentials."""
    from ghidra.framework.client import (  # noqa: PLC0415
        ClientUtil,
        PasswordClientAuthenticator,
    )

    user = os.environ.get(SERVER_USER_ENV) or os.environ.get("USER", "")
    password = os.environ.get(SERVER_PASSWORD_ENV)
    if password is None:
        raise GhidraError(
            f"Set {SERVER_PASSWORD_ENV} (and {SERVER_USER_ENV}) in the server's "
            "environment to connect to a Ghidra Server. Passwords are never taken "
            "as tool arguments.",
            error_type="NoCredentials",
        )
    ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(user, password))
    server = ClientUtil.getRepositoryServer(host, port, True)
    if server is None or not server.isConnected():
        raise GhidraError(
            f"Cannot connect to Ghidra Server {host}:{port} as {user!r}.",
            error_type="ServerUnavailable",
        )
    return server


def repository_names(server) -> list[str]:
    return [str(n) for n in server.getRepositoryNames()]


def repository(target: ServerProgram):
    """The connected repository adapter for *target*.

    ``getRepository`` returns an adapter even for a name that does not
    exist (connecting it then fails), so the name is checked first.
    """
    server = connect(target.host, target.port)
    names = repository_names(server)
    if target.repository not in names:
        raise GhidraError(
            f"No repository {target.repository!r} on {target.host} (has: "
            f"{', '.join(names) or 'none'}). create_repository makes one.",
            error_type="NotFound",
        )
    repo = server.getRepository(target.repository)
    repo.connect()
    return repo


def shared_project(target: ServerProgram):
    """Open (creating on first use) the local project bound to *target*'s repository."""
    from ghidra.framework.model import ProjectLocator  # noqa: PLC0415
    from ghidra.pyghidra import PyGhidraProjectManager  # noqa: PLC0415

    repo = repository(target)
    os.makedirs(SHARED_PROJECTS_DIR, exist_ok=True)
    locator = ProjectLocator(SHARED_PROJECTS_DIR, target.key)
    manager = PyGhidraProjectManager()
    if locator.exists():
        return manager.openProject(locator, False, True)
    return manager.createProject(locator, repo, False)


def list_items(repo, folder: str = "/") -> tuple[list[str], list[dict]]:
    """All folders and files under *folder* in a repository, recursively."""
    folders: list[str] = []
    files: list[dict] = []
    pending = [folder]
    while pending:
        path = pending.pop()
        folders.append(path)
        files.extend(
            {
                "path": str(item.getPathName()),
                "version": int(item.getVersion()),
                "content_type": str(item.getContentType()),
            }
            for item in repo.getItemList(path) or []
        )
        pending.extend(
            path.rstrip("/") + "/" + str(sub) for sub in repo.getSubfolderList(path) or []
        )
    return sorted(folders), sorted(files, key=lambda f: f["path"])
