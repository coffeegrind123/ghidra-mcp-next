# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Parse ghidra:// program URLs. Bootstrap-safe (no JVM)."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from re_mcp_ghidra.exceptions import GhidraError

GHIDRA_URL_SCHEME = "ghidra://"
DEFAULT_SERVER_PORT = 13100  # Ghidra Server's default RMI registry port


def parse_server_address(server: str) -> tuple[str, int]:
    """``host[:port]`` or ``ghidra://host[:port]`` -> (host, port)."""
    parts = urlsplit(server if "://" in server else f"ghidra://{server}")
    if not parts.hostname:
        raise GhidraError(
            f"Not a Ghidra Server address: {server!r}. Expected host[:port].",
            error_type="InvalidArgument",
        )
    return parts.hostname, parts.port or DEFAULT_SERVER_PORT


@dataclass(frozen=True)
class ServerProgram:
    """``ghidra://host[:port]/repository/folder/program`` (path ``"/"`` for a repository)."""

    host: str
    port: int
    repository: str
    path: str  # program path inside the repository, starting with "/"

    @property
    def key(self) -> str:
        """Filesystem-safe name for the local project bound to this repository."""
        return f"{self.host}_{self.port}_{self.repository}".replace(":", "_")


def parse_server_url(url: str, *, require_path: bool = True) -> ServerProgram:
    """Parse ``ghidra://host[:port]/repository[/folder/program]``.

    With *require_path* false, the path may be absent (it is then ``"/"``):
    a URL naming just a repository, or a folder in one.
    """
    parts = urlsplit(url)
    segments = [s for s in parts.path.split("/") if s]
    if (
        parts.scheme != "ghidra"
        or not parts.hostname
        or not segments
        or (require_path and len(segments) < 2)
    ):
        shape = "folder/program" if require_path else "[folder/...]"
        raise GhidraError(
            f"Not a Ghidra Server URL: {url!r}. Expected ghidra://host[:port]/repository/{shape}.",
            error_type="InvalidArgument",
        )
    return ServerProgram(
        host=parts.hostname,
        port=parts.port or DEFAULT_SERVER_PORT,
        repository=segments[0],
        path="/" + "/".join(segments[1:]),
    )
