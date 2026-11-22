# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Multi-database supervisor for re-mcp backends.

Spawns one worker subprocess per open database and proxies MCP tool calls
and resource reads to the appropriate worker via the ``WorkerPoolProvider``.

All tools except management tools (``open_database``, ``close_database``,
``save_database``, ``list_databases``, ``wait_for_analysis``,
``list_targets``) require the ``database`` parameter (the stem ID
returned by ``open_database`` or ``list_databases``).

The supervisor never imports backend-specific modules directly — it loads
the backend via the :class:`Backend` protocol.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated

from fastmcp import FastMCP
from fastmcp.server.context import Context
from pydantic import Field

if TYPE_CHECKING:
    from fastmcp.server.auth.auth import AuthProvider
    from fastmcp.server.lifespan import Lifespan
    from fastmcp.server.server import LifespanCallable

from re_mcp.backend import Backend, get_backend
from re_mcp.context import notify_resources_changed, try_get_session_id
from re_mcp.transforms import ToolTransform, run_with_heartbeat
from re_mcp.worker_provider import (
    WorkerPoolProvider,
    parse_result,
    require_success,
)

log = logging.getLogger(__name__)

_HANDLED_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP")

DATABASE_DESCRIPTION = 'Database id from open_database or list_databases. Example: "server_dll"'


# ---------------------------------------------------------------------------
# ProxyMCP
# ---------------------------------------------------------------------------


_UNSET: object = object()


class ProxyMCP(FastMCP):
    """MCP server that proxies tool calls to per-database worker processes."""

    def __init__(
        self,
        *,
        backend: type[Backend],
        auth: AuthProvider | None = None,
        lifespan: LifespanCallable | Lifespan | None | object = _UNSET,
    ):
        info = backend.info()
        transform = ToolTransform(
            pinned=info.pinned_tools,
            env_prefix=info.env_prefix,
        )
        super().__init__(
            info.display_name,
            instructions=backend.build_instructions(transform),
            on_duplicate="error",
            lifespan=self._lifespan_signal_handlers if lifespan is _UNSET else lifespan,
            auth=auth,
        )
        self._backend = backend
        self._backend_info = info
        self._transform = transform
        self._worker_pool = WorkerPoolProvider(backend=backend)
        self.add_provider(self._worker_pool)
        self._register_generic_management_tools()
        backend.register_management_tools(self, self._worker_pool)
        self._register_supervisor_resources()
        backend.register_prompts(self)
        self._declare_explicit_required()
        self.add_transform(transform)

    def _declare_explicit_required(self) -> None:
        """Give every supervisor tool schema an explicit ``"required"`` array.

        Pydantic omits ``required`` when every parameter has a default, which
        leaves a client to guess whether they are optional.  The schemas are
        live dicts, so adding ``"required": []`` after registration sticks.
        (``_components`` is private to FastMCP; this is the one place that
        reaches into it.)
        """
        for component in self.local_provider._components.values():
            params = getattr(component, "parameters", None)
            if isinstance(params, dict) and params.get("type") == "object":
                params.setdefault("required", [])

    @property
    def worker_pool(self) -> WorkerPoolProvider:
        return self._worker_pool

    @staticmethod
    @asynccontextmanager
    async def _lifespan_signal_handlers(_app: FastMCP) -> AsyncIterator[None]:
        loop = asyncio.get_running_loop()
        _install_signal_handlers(loop)
        try:
            yield
        finally:
            for sig_name in _HANDLED_SIGNALS:
                sig = getattr(signal, sig_name, None)
                if sig is not None:
                    with contextlib.suppress(NotImplementedError, OSError, ValueError):
                        loop.remove_signal_handler(sig)

    # ------------------------------------------------------------------
    # Generic management tools
    # ------------------------------------------------------------------

    def _register_generic_management_tools(self):
        pool = self._worker_pool

        @self.tool(annotations={"title": "Close Database"})
        async def close_database(
            database: Annotated[str, Field(description=DATABASE_DESCRIPTION)],
            save: Annotated[
                bool,
                Field(description="Save unsaved changes before closing. Example: true"),
            ] = True,
            force: Annotated[
                bool,
                Field(
                    description=(
                        "Close even if this session did not open the database. Example: false"
                    )
                ),
            ] = False,
        ) -> dict:
            """Close a database and stop its worker process.

            Use when finished with a binary, or before opening many others. Saves
            first unless save=false. When another session still uses the database,
            only this session detaches and the worker keeps running.

            Returns {status: "closed" | "detached", database, saved}.
            """
            worker = pool.resolve_worker(database)
            result = await pool.close_for_session(
                worker, try_get_session_id(), save=save, force=force
            )
            if result.get("status") != "detached":
                await notify_resources_changed()
            return result

        @self.tool(annotations={"title": "Save Database"})
        async def save_database(
            database: Annotated[str, Field(description=DATABASE_DESCRIPTION)],
            comment: Annotated[
                str,
                Field(
                    description=(
                        "Note stored with this save in the program's history. "
                        'Example: "named packet handlers"'
                    )
                ),
            ] = "",
            force: Annotated[
                bool,
                Field(
                    description=(
                        "Save even if this session did not open the database. Example: false"
                    )
                ),
            ] = False,
            ctx: Context | None = None,
        ) -> dict:
            """Write the program's changes to its Ghidra project on disk.

            Nothing a tool, batch or execute changes reaches disk until this runs
            (close_database also saves). Large programs can take minutes; progress
            is reported every 5 s. A versioned (Ghidra Server) file must be checked
            out first, or this fails with ReadOnly.

            Returns {status: "saved", path, revision, database}.
            """
            worker = pool.resolve_worker(database)
            if not force:
                pool.check_attached(worker, try_get_session_id())

            params: dict = {"comment": comment} if comment else {}
            proxy_task = asyncio.create_task(pool.proxy_to_worker(worker, "save_database", params))
            await run_with_heartbeat(proxy_task, ctx)
            result = proxy_task.result()
            result_data = parse_result(result)
            result_data["database"] = worker.database_id
            require_success(result, result_data, "Save failed")
            return result_data

        @self.tool(annotations={"title": "List Databases", "readOnlyHint": True})
        async def list_databases() -> dict:
            """List the databases open in this server.

            Use to recover database ids, or to see whether one is still opening or
            analyzing. Returns {databases: [{database, file_path, state, opening,
            analyzing, attached, ...}]}.
            """
            return pool.build_database_list(caller_session_id=try_get_session_id())

        @self.tool(annotations={"title": "Wait for Analysis", "readOnlyHint": True})
        async def wait_for_analysis(
            database: Annotated[
                str,
                Field(
                    description=(
                        "Database id from open_database; required unless databases is "
                        'given. Example: "server_dll"'
                    )
                ),
            ] = "",
            databases: Annotated[
                list[str],
                Field(
                    description=(
                        "Several database ids: returns as soon as ONE is ready; call "
                        'again for the rest. Example: ["server_dll", "client_dll"]'
                    ),
                ),
            ] = [],  # noqa: B006 -- read only; a list default keeps the schema free of anyOf
        ) -> dict:
            """Block until a database has finished opening (and auto-analysis, if asked).

            Call after open_database, before any other tool on that database: other
            tools are refused while it opens. Returns {status: "ready", database,
            processor, function_count, ...}, or the failure that stopped it.
            """
            if databases:
                return await pool.wait_for_ready_multi(databases)
            return await pool.wait_for_ready(database)

        @self.tool(annotations={"title": "List Targets", "readOnlyHint": True})
        async def list_targets() -> dict:
            """List the processor languages and compiler specs this Ghidra supports.

            Use when open_database's auto-detection picks the wrong processor (raw
            firmware, unusual formats): pass the language id and compiler spec id it
            returns. Returns {languages: [{id, processor, endian, size, variant,
            description, compiler_specs: [{id, name}]}]}.
            """
            return self._backend.list_targets()

    # ------------------------------------------------------------------
    # Supervisor-owned resources
    # ------------------------------------------------------------------

    def _register_supervisor_resources(self):
        pool = self._worker_pool
        scheme = self._backend_info.uri_scheme

        @self.resource(
            f"{scheme}://databases",
            description="All open databases with worker status (supervisor-level)",
        )
        async def databases_resource() -> str:
            return json.dumps(pool.build_database_list(include_state=True), separators=(",", ":"))

        transform = self._transform
        header = self._backend.api_stub_header()

        @self.resource(
            f"{scheme}://api/tools.pyi",
            name="tool_api",
            description=(
                "Every tool as a typed Python stub with its full documentation: the "
                "signatures batch ops and execute's tools.<name>(...) take."
            ),
            mime_type="text/x-python",
        )
        async def tool_api_resource(ctx: Context) -> str:
            from re_mcp.transforms import render_api_stub  # noqa: PLC0415

            return render_api_stub(await transform.get_tool_catalog(ctx), header)


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """Register signal handlers on the running event loop."""

    def _handler(sig: signal.Signals) -> None:
        log.info("Received %s; initiating shutdown", sig.name)
        loop.stop()

    for sig_name in _HANDLED_SIGNALS:
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, _handler, sig)
        except (NotImplementedError, OSError, ValueError):
            log.debug("Could not install handler for %s", sig_name, exc_info=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    import argparse  # noqa: PLC0415

    from re_mcp import configure_logging, get_version  # noqa: PLC0415

    backend_name = os.environ.get("RE_MCP_BACKEND")

    parser = argparse.ArgumentParser(
        prog="re-mcp",
        description="Reverse-engineering MCP server",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    parser.add_argument(
        "--backend",
        default=backend_name,
        help="Backend name (auto-detected if only one is installed)",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser(
        "proxy",
        help="Stdio proxy to a persistent HTTP daemon",
    )

    serve_cmd = sub.add_parser("serve", help="Start persistent streamable HTTP daemon")
    serve_cmd.add_argument("--port", type=int, default=0, help="Port to bind (0 = auto)")
    serve_cmd.add_argument("--host", default="127.0.0.1", help="Host to bind (default 127.0.0.1)")

    def _nonneg_int(value: str) -> int:
        n = int(value)
        if n < 0:
            raise argparse.ArgumentTypeError("must be >= 0")
        return n

    serve_cmd.add_argument(
        "--idle-timeout",
        type=_nonneg_int,
        default=0,
        help="Auto-shutdown after N seconds with no connections (0 = disabled).",
    )

    sub.add_parser(
        "stdio",
        help="Direct stdio mode — workers die on disconnect (default when no command given)",
    )
    sub.add_parser("stop", help="Stop the running daemon")
    sub.add_parser("backends", help="List installed backends")

    args = parser.parse_args()

    if args.command == "backends":
        from re_mcp.backend import discover_backends  # noqa: PLC0415

        backends = discover_backends()
        if not backends:
            print("No backends installed.")
        else:
            for name in sorted(backends):
                info = backends[name].info()
                print(f"  {name}: {info.display_name}")
        return

    try:
        backend = get_backend(args.backend)
    except RuntimeError as exc:
        parser.error(str(exc))

    if args.command == "serve":
        from re_mcp.daemon import serve  # noqa: PLC0415

        serve(backend=backend, host=args.host, port=args.port, idle_timeout=args.idle_timeout)
    elif args.command == "stop":
        from re_mcp.proxy import stop  # noqa: PLC0415

        if stop(backend=backend):
            print("Daemon stopped.")
        else:
            print("No daemon is running.")
    elif args.command == "proxy":
        from re_mcp.proxy import main as proxy_main  # noqa: PLC0415

        proxy_main(backend=backend)
    else:
        configure_logging(env_prefix=backend.info().env_prefix)
        ProxyMCP(backend=backend).run(transport="stdio")


if __name__ == "__main__":
    main()
