# Architecture

## Overview

RE-MCP is a reverse-engineering server for Ghidra that communicates over the Model Context Protocol (MCP). It uses the headless [pyghidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra) API to expose binary analysis capabilities as structured tool calls that LLMs can invoke.

The project is a monorepo with two packages:
- **`re-mcp-core`** (`packages/re-mcp-core/src/re_mcp/`) — generic MCP supervisor infrastructure (transport, worker management, tool transforms, the batch and execute meta tools)
- **`re-mcp-ghidra`** (`packages/re-mcp-ghidra/src/re_mcp_ghidra/`) — Ghidra-specific backend (pyghidra bootstrap, tools, resources, prompts)

The server supports three transport modes:

```
# Default: direct stdio (single-session, workers die on disconnect)
LLM Client  <──stdio──>  ProxyMCP (re_mcp.supervisor)
                              └── WorkerPoolProvider
                                    ├──stdio──>  Worker 1
                                    └──stdio──>  Worker 2

# Proxy mode: stdio proxy → persistent HTTP daemon (workers survive reconnects)
LLM Client  <──stdio──>  Proxy (re_mcp.proxy)  <──HTTP──>  Daemon (re_mcp.daemon)
                                                                │
                                                            ProxyMCP (re_mcp.supervisor)
                                                                │
                                                                └── WorkerPoolProvider
                                                                      ├──stdio──>  Worker 1
                                                                      └──stdio──>  Worker 2
```

The **default mode** (`<backend>` or `<backend> stdio`) runs the supervisor directly over stdio — workers die when the client disconnects. This is the simplest mode, widely supported across MCP clients.

The **proxy mode** (`<backend> proxy`) runs a stdio-to-HTTP proxy that auto-spawns a persistent background daemon. The daemon runs `ProxyMCP` (from `re_mcp.supervisor`) over streamable HTTP with bearer token authentication, so worker processes and database state survive client reconnections. The proxy bridges stdio MCP messages bidirectionally to the daemon.

The **serve mode** (`<backend> serve`) runs the daemon directly (used by the proxy's auto-spawn, or for manual daemon management).

The **stop command** (`<backend> stop`) gracefully shuts down a running daemon.

For single-database usage, there is one worker. Multiple workers are spawned when `open_database` is called multiple times (the default keeps previously opened databases open).

## Design Decisions

### Why headless APIs over GUI plugins?

pyghidra runs Ghidra's analysis engine as a library within a normal Python process — no GUI, no X11/display dependencies. This has several advantages:

- Process lifecycle is controlled by the server, not the GUI
- Direct function calls instead of script injection
- Runs on headless machines (CI, SSH, containers)

The trade-off is that the backend is **thread-affine**: all API calls must happen on the same thread that initialized the engine (the JVM start for pyghidra). Each worker process handles a single database; the supervisor routes requests to the correct worker via stdio pipes.

### Why FastMCP?

[FastMCP](https://gofastmcp.com) provides a decorator-based API for defining MCP tools. Each tool is a plain Python function with type annotations — FastMCP handles JSON schema generation, argument validation, and transport.

### Persistent daemon architecture

The default stdio mode is the simplest transport — stdio is widely supported across MCP clients, requires no port management or auth, and ties process lifecycle to the client session. The trade-off is that when the client disconnects (e.g. the user closes their editor), the supervisor and all worker processes die, losing database state and analysis progress.

The proxy mode solves this with a persistent HTTP daemon behind a stdio proxy.

The daemon (`re_mcp.daemon`) runs `ProxyMCP` over FastMCP's streamable HTTP transport with bearer token authentication. It writes a state file containing the host, bound port, bearer token, PID, and version. The state file location is platform-specific: `~/Library/Application Support/<backend>/daemon.json` on macOS, `$XDG_STATE_HOME/<backend>/daemon.json` (defaulting to `~/.local/state/<backend>/daemon.json`) on Linux, and `%LOCALAPPDATA%\<backend>\daemon.json` on Windows (where `<backend>` is `re-mcp-ghidra`). The state file is created atomically with restricted permissions (0o600) and cleaned up on shutdown.

The proxy (`re_mcp.proxy`) is the entry point for `<backend> proxy` mode. It checks for an existing daemon via the state file and process liveness, spawns one if needed (with a file lock to prevent races between concurrent clients), and bridges stdio MCP messages to the daemon's HTTP endpoint using `mcp.client.streamable_http`. The daemon process is fully detached (new session on Unix, `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` on Windows) so it survives the proxy's exit.

When auto-spawned by the proxy, the daemon enables idle auto-shutdown (default 300 seconds, configurable via `<PREFIX>IDLE_TIMEOUT`). An `_idle_monitor` coroutine runs alongside the uvicorn server, polling every 10 seconds. When uvicorn has no active connections, the provider has no registered MCP sessions, no worker calls are in flight, and no proxy keepalive is active — all for the idle timeout duration — the monitor sets `server.should_exit = True` to trigger a graceful shutdown. The provider's lifespan then terminates all workers via `shutdown_all()`, and the daemon's `finally` block removes the state file. The idle timer resets whenever activity resumes. Daemons started manually via `<backend> serve` do not enable idle shutdown by default (`--idle-timeout=0`); pass `--idle-timeout=N` to opt in.

Security: the bearer token is a 256-bit random hex string generated per daemon lifetime. Only the spawning proxy and the daemon know the token. The daemon binds to `127.0.0.1` by default; binding to non-loopback addresses emits a warning.

### Backend protocol

Each backend implements the `Backend` protocol (defined in `re_mcp.backend`), which provides:

- **`info()`** — returns a `BackendInfo` dataclass with the backend name, display name, URI scheme, worker module, pinned/management tool sets, environment variable prefix, and state directory name.
- **`build_instructions()`** — generates LLM-facing instructions describing the backend's capabilities and workflows.
- **`register_management_tools()`** — registers backend-specific management tools (e.g. Ghidra's `open_database` with `language`/`compiler_spec`).
- **`register_prompts()`** — registers MCP prompt templates for guided workflows.
- **`canonical_path()`** — computes a dedup key for a database path, used by `WorkerPoolProvider` to prevent duplicate workers for the same database.
- **`list_targets()`** — lists available analysis targets (processors, languages, etc.) for the backend.

Backends are discovered via `re_mcp.backends` entry points, allowing new backends to be added as separate packages.

### Main-thread execution

The backend is thread-affine: all engine API calls must happen on the main OS thread. The MCP event loop runs on a background thread (a Python thread with `daemon=True`, not to be confused with the persistent HTTP daemon), while the main thread runs a `MainThreadExecutor` work queue.

The backend's `Server` subclass (`GhidraServer`) wraps every sync tool and resource function registered via `@mcp.tool()` or `@mcp.resource()` into an `async def` that dispatches the call to the main thread via `call_ghidra` (an alias for `dispatch_to_main`, backed by `MainThreadExecutor`). FastMCP sees an async function and skips its own threadpool, so all engine API calls land on the main thread while the MCP server remains responsive. Async tool functions run on the event-loop thread and must use the dispatch function for individual engine API calls.

### Engine bootstrap

Each backend provides a `bootstrap()` function (in `<backend>.__init__`) that initializes the analysis engine before any engine-specific imports. Only worker processes call `bootstrap()` — the supervisor never does.

**Ghidra:** `bootstrap()` starts the JVM via pyghidra's `HeadlessPyGhidraLauncher` before any Ghidra Java classes are imported.

### Session singleton

Each backend has a `Session` class (in `<backend>.session`) that manages the database connection within each worker process:

```python
session = Session()  # module-level singleton (one per worker process)
```

Key behaviors:
- Each worker process handles one database (the backend uses global state that requires isolation)
- `session.require_open` is a decorator that raises `BackendError` if no database is open. Since `BackendError` subclasses FastMCP's `ToolError`, FastMCP automatically returns `isError=True` with the message as text content
- The worker's `main()` function calls `session.close(save=True)` in its `finally` block on shutdown

### Multi-database supervisor and provider architecture

The supervisor uses FastMCP's native Provider system to expose worker tools and resources through the standard provider chain, rather than overriding `list_tools()`, `call_tool()`, etc.

**`ProxyMCP`** (`re_mcp.supervisor`) subclasses `FastMCP`. It creates a `WorkerPoolProvider` and calls `self.add_provider(worker_pool)`. Generic management tools (`close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`) are registered by the supervisor; backend-specific management tools (e.g. Ghidra's `open_database` with `language`/`compiler_spec`) are registered by the backend via `register_management_tools()`. Prompts and the database list resource are also registered directly on the supervisor — they do not require database state and are served by FastMCP's internal local provider.

A `ToolTransform` (a `CatalogTransform` subclass defined in `re_mcp.transforms`) is applied at the server level. It pins a set of common analysis tools (e.g. `list_functions`, `decompile_function`, `list_strings`) alongside five meta-tools:

- `search_tools` — regex discovery over all non-pinned tools.
- `get_schema` — parameter schemas and return shapes for tools by name.
- `execute` — Python 3 against the Ghidra API and every tool, run in the worker in one transaction (forwards to the worker's internal `_execute`; see `context/design.md`).
- `batch` — up to 100 tool calls in one transaction with `$N` references, `if_revision`, `operation_id` and `dry_run` (forwards to the worker's internal `_batch`).
- `call` — lightweight proxy for calling any tool by name, including hidden tools not in the client tool list.

Tools not in the pinned set are hidden from the tool listing but callable via `call`, `batch`, or `execute`.

Management tools delegate to `WorkerPoolProvider` methods for worker lifecycle and are session-aware: `close_database` delegates to `close_for_session()`, which atomically detaches and conditionally terminates under `_lock`; `save_database` checks attachment before proceeding. Most management tools use `try_get_session_id()` (from `re_mcp.context`) to get the session ID without exposing a `ctx` parameter in the tool schema. `save_database` is the one exception — it accepts `ctx` for heartbeat progress notifications during long saves (FastMCP strips `ctx` from the JSON schema automatically).

**`WorkerPoolProvider`** (`re_mcp.worker_provider`) implements FastMCP's `Provider` interface. It manages worker subprocesses (each via a `fastmcp.Client` with `StdioTransport`) and exposes their tools and resources through the provider chain:

- `_list_tools()` / `_get_tool()` return `RoutingTool` instances — `Tool` subclasses constructed from bootstrapped MCP tool schemas. Each `RoutingTool` has the `database` parameter injected into its JSON schema at construction and preserves `output_schema` for structured output passthrough.
- `_list_resource_templates()` / `_get_resource_template()` return `RoutingTemplate` instances — `ResourceTemplate` subclasses that override `_read()` to extract `database` from params, resolve the worker, reconstruct the backend URI, and proxy the read via `client.read_resource_mcp()`. All worker resources (both fixed resources and templates) are exposed as templates with a `{database}` prefix in the URI.
- `RoutingTool.run()` pops `database` from arguments, resolves the target worker, implicitly attaches the current session (if a `Context` is available), and delegates to `proxy_to_worker()` (which tracks active calls via `worker.dispatch()` and calls `worker.client.call_tool_mcp()`). The result is enriched with `database` and returned as a `ToolResult`, or raised as a `ToolError`. Error handling (worker crashes, timeouts) is contained within `proxy_to_worker()`.
- `lifespan()` shuts down all workers on exit.
- `check_attached(worker, session_id)` raises `BackendError` if the session is not attached to the worker (pass-through when session ID is `None` or the worker has no tracked sessions for backward compatibility).
- `close_for_session(worker, session_id, save, force)` atomically checks attachment, detaches, and conditionally terminates under `_lock` — prevents races where a concurrent `attach()` from `RoutingTool.run()` could sneak in between detach and terminate.
- `detach_all(session_id, terminate=True)` detaches a session from all workers under `_lock`. When `terminate=True` (default), workers whose session set becomes empty are shut down; `terminate=False` detaches for bookkeeping only (used by the disconnect callback). Falls back to `shutdown_all()` when session ID is `None`.
- `build_database_list(include_state, caller_session_id)` returns all open databases with metadata and a `session_count` per entry; when `caller_session_id` is provided, each entry also includes an `attached` flag.

Tool/resource schemas are bootstrapped lazily from a temporary worker on first access. `RoutingTool` and `RoutingTemplate` both set `task_config = TaskConfig(mode="optional")`.

All tools except management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`) require the `database` parameter (the stem ID returned by `open_database` or `list_databases`).

#### Background analysis

`spawn_worker()` returns immediately. The worker subprocess, database open, and optional auto-analysis all run in a background `asyncio.Task` (`_background_spawn`). The initial response includes `"opening": true`, and callers must call `wait_for_analysis` to block until the database is ready for tool calls.

When `run_auto_analysis=True`, `_background_spawn` chains into a second task (via `Worker.start_analysis()`) that dispatches `wait_for_analysis` through the normal proxy path once the open completes. While that task runs, `list_databases` reports `"analyzing": true` for the worker.

While background analysis is running, every worker tool except `wait_for_analysis` is rejected by `RoutingTool.run()` — the analysis engine is occupied. `wait_for_analysis` awaits the background task directly rather than making a redundant proxy call.

After analysis completes, worker metadata (function count, etc.) is refreshed via `get_database_info`, and MCP log and resource-list-changed notifications are sent if an `mcp_session` is available. Clients should call `wait_for_analysis` on the database to block until completion rather than polling `list_databases`. Background spawn and analysis tasks are cancelled during worker shutdown.

#### Per-worker concurrency

Because the backend uses a single-threaded, global-state analysis engine, requests to the same worker are serialized by the worker's single-threaded MCP transport. The `dispatch()` async context manager tracks active call count and activity timestamps. Requests to *different* workers run fully in parallel. The `Worker.state` property derives the effective state (BUSY/IDLE) from the `_active_calls` counter rather than requiring manual state transitions.

Crashed workers are detected on-demand when tool calls or resource reads encounter connection errors (`ClosedResourceError`, `EndOfStream`, `BrokenPipeError`/`OSError`, `McpError` with connection-closed code) — `proxy_to_worker()` and `RoutingTemplate._read()` call `mark_worker_dead()` to clean up.

#### Session tracking

Workers track which MCP sessions are using them via `attach(session_id)` / `detach(session_id)` / `is_attached(session_id)` / `session_count`. Sessions are attached implicitly when a tool or resource is accessed (via `attach_current_session()`, called from `RoutingTool.run()` and `RoutingTemplate._read()`) and explicitly on `open_database`.

`close_database` delegates to `close_for_session()`, which atomically checks attachment, detaches, and conditionally terminates under `_lock`. When other sessions are still using the database, it returns a `detached` status instead of terminating. `save_database` and `close_database` check attachment before proceeding (unless `force=True`).

When an MCP session disconnects, a cleanup callback registered on the session's exit stack automatically detaches the session from all workers (via `detach_all(terminate=False)`). Workers are **not** terminated on disconnect — in Claude Code's multi-agent architecture all agents share one MCP session, so a session cycle would otherwise kill databases still in active use. Termination happens only via an explicit `close_database` call, `open_database(keep_open=False)`, or supervisor shutdown.

#### Configuration environment variables

Settings use the `GHIDRA_MCP_` environment variable prefix. The list below uses `<PREFIX>` as a placeholder.

- `<PREFIX>MAX_WORKERS` — maximum simultaneous databases (clamped to 1-8 when set; unlimited when unset)
- `<PREFIX>LOG_LEVEL` — logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`); defaults to `WARNING`, output goes to stderr
- `<PREFIX>LOG_DIR` — directory that receives per-run log files. When set, each component tees Python logging to `<dir>/<run_id>-<label>.log` (labels: `daemon`, `proxy`, `supervisor` for direct stdio mode), each worker to `<dir>/<run_id>-worker-<db>.log`, and each worker's raw stderr is captured to `<dir>/<run_id>-worker-<db>.stderr` (catches pre-logging output and C-level crashes). `<run_id>` is a timestamp generated once per supervisor start. When unset, logs go only to stderr (inherited by workers).
- `<PREFIX>IDLE_TIMEOUT` — idle auto-shutdown timeout in seconds for auto-spawned daemons (default `300`). Set to `0` to disable. When the daemon has no active HTTP connections, no MCP sessions, no in-flight worker calls, and no proxy keepalive for this duration, it shuts down gracefully. Only affects daemons spawned by the proxy; `<backend> serve` defaults to `0` (use `--idle-timeout=N` to override)
- `<PREFIX>DISABLE_EXECUTE` — hides the `execute` meta-tool (Python against the Ghidra API) when set to `1`, `true`, `yes`, or `on`
- `<PREFIX>DISABLE_BATCH` — hides the `batch` meta-tool when set to `1`, `true`, `yes`, or `on`
- `<PREFIX>DISABLE_TOOL_SEARCH` — disables server-side progressive tool disclosure when set to `1`, `true`, `yes`, or `on`. All tools become directly visible and callable; `search_tools` and `get_schema` meta-tools are removed. Useful with clients that provide their own tool deferral (e.g. Claude Code).

Backend-specific:
- `GHIDRA_INSTALL_DIR` — path to the Ghidra installation directory (auto-detected when unset)

### Error handling convention

Tools return Pydantic model instances on success (FastMCP serializes these automatically). On failure, they raise a `BackendError` subclass (`GhidraError`). `BackendError` subclasses FastMCP's `ToolError`, so FastMCP catches it and returns `isError=True` with the error text as content — tools never return error dicts directly.

`BackendError.__str__` returns a JSON object with `error`, `error_type`, and optional detail fields (e.g. `available_variables`, `valid_types`). This keeps the MCP error text machine-parseable while preserving a structured error taxonomy. Common error types include:

- `NoDatabase` — no database is open
- `InvalidAddress` — could not parse/resolve address
- `NotFound` — function, type, or symbol not found
- `DecompilationFailed` — decompilation error
- `InvalidArgument` — bad parameter value
- `Cancelled` — operation cancelled via cooperative cancellation

Individual tools define additional error types specific to their domain (e.g. `ParseError`, `DecodeFailed`, `SetCommentFailed`).

Mutation tools return the previous state of modified items (e.g. `old_comment`, `old_type`, `old_bytes`, `old_flags`) alongside the new values, enabling undo tracking and change verification by the LLM.

### Address resolution

Addresses are the most common parameter type. The `parse_address` function in backend helpers accepts multiple formats to minimize friction for LLM callers. Resolution order:

1. `"0x401000"` — hex with `0x` prefix (unambiguous, tried first)
2. `"4198400"` — decimal (all-digit strings are always decimal)
3. `"main"` — symbol name (resolved via the backend's name database)
4. `"4010a0"` — bare hex fallback (last resort; reached only when the string is not pure digits and is not a known symbol)

Symbol names are checked before bare hex so that names like `add`, `dead`, or `cafe` resolve to the named symbol rather than being parsed as hexadecimal. Use the `0x` prefix for explicit hex (e.g. `0xADD` instead of `add`).

Higher-level helpers build on this. The backend provides:
- `resolve_address(addr)` → `int` (raises `BackendError` on failure)
- `resolve_function(addr)` → function object (raises `BackendError`)

Each raises the backend's error type on failure, so tool implementations avoid manual error-checking.

### Pagination

List-returning tools use `paginate(items, offset, limit)`, `paginate_iter(items, offset, limit)`, or `async_paginate_iter(items, offset, limit)` from the helpers module. `paginate_iter` consumes a generator one item at a time rather than building a full list; after collecting the requested page it reads ahead up to `_COUNT_AHEAD` items beyond the page end to compute `has_more` and an approximate `total` — if the iterator has more items beyond that budget, `total` reflects items seen so far and `has_more` is `True`. `async_paginate_iter` dispatches the entire iteration to the main thread (required by the thread-affine engine). Tools that build lists eagerly use `paginate` instead. All three produce the same response shape:

```python
{
    "items": [...],
    "total": 1500,
    "offset": 0,
    "limit": 100,
    "has_more": True
}
```

The default limit is 100 for most tools. Some tools use smaller defaults: 50 for batch decompilation/disassembly export and memory block listing, 20 for `find_code_by_string`. There is no hard cap — callers can request larger pages when needed.

## Module Organization

### `re-mcp-core` modules (`packages/re-mcp-core/src/re_mcp/`)

| Module | Role |
|--------|------|
| `supervisor.py` | Main entry point — creates `ProxyMCP(FastMCP)` with `WorkerPoolProvider`, registers generic management tools. CLI dispatches to direct stdio (default), proxy, daemon, or stop mode |
| `daemon.py` | Persistent streamable HTTP daemon — runs `ProxyMCP` with bearer token auth and state file for proxy discovery. Workers survive client reconnections |
| `proxy.py` | Stdio-to-HTTP bridge — auto-spawns the daemon if needed, then forwards MCP messages bidirectionally between stdio and the daemon's HTTP endpoint |
| `worker_provider.py` | `WorkerPoolProvider(Provider)` — manages worker subprocesses, exposes tools via `RoutingTool(Tool)` and resources via `RoutingTemplate(ResourceTemplate)` through the native provider chain |
| `backend.py` | `Backend` protocol and `BackendInfo` dataclass — the Ghidra backend implements this and registers via `re_mcp.backends` entry points |
| `context.py` | `try_get_context()`, `try_get_session_id()`, and `notify_resources_changed()` — FastMCP context helpers with no backend dependencies, used by supervisor modules |
| `exceptions.py` | `BackendError(ToolError)` — base structured error type for all backends |
| `server.py` | `MainThreadExecutor` work queue and `BackendServer(FastMCP)` — subclassed by each backend to dispatch sync tools/resources to the main thread |
| `helpers.py` | Backend-agnostic utilities — address parsing/formatting, pagination (`paginate`, `paginate_iter`, `async_paginate_iter`), `dispatch_to_main` main-thread dispatch, MCP annotation presets, `Annotated` parameter type aliases (`Address`, `Offset`, `Limit`, `FilterPattern`, `HexBytes`), filter compilation |
| `models.py` | Shared Pydantic models (e.g. `PaginatedResult`) used across backends |
| `transforms.py` | `ToolTransform(CatalogTransform)` — pins common tools, adds `search_tools`, `get_schema`, `execute`, `batch`, and `call` meta-tools, hides the rest from listing (callable via `call`/`batch`/`execute`) |
| `_process.py` | Platform-aware process utilities (`pid_alive`, `pid_exit_code`, `IS_WINDOWS`) — stdlib only, no backend dependencies |
| `__init__.py` | `configure_logging()`, `ensure_run_id()`, `resolve_log_file()`, `get_version()` — shared infrastructure utilities |

### `re-mcp-ghidra` modules (`packages/re-mcp-ghidra/src/re_mcp_ghidra/`)

| Module | Role |
|--------|------|
| `backend.py` | `GhidraBackend` — implements the `Backend` protocol; registers `open_database`, Ghidra-specific LLM instructions, and target listing |
| `server.py` | Worker entry point (`re-mcp-ghidra-worker`) — creates `GhidraServer` (a `BackendServer` subclass), auto-discovers and registers all tool modules from `tools/`, runs stdio transport |
| `session.py` | Database session singleton (per worker), `require_open` decorator |
| `exceptions.py` | `GhidraError(BackendError)` — Ghidra-specific structured error type |
| `helpers.py` | Address parsing, formatting, pagination, resolution helpers, MCP annotation presets, `Annotated` parameter type aliases, `call_ghidra` main-thread dispatch |
| `models.py` | Re-exports shared Pydantic models from `re_mcp.models` for convenient single-source imports |
| `transforms.py` | Ghidra-specific tool visibility constants — `PINNED_TOOLS` and `MANAGEMENT_TOOLS` frozensets |
| `resources.py` | MCP resources — read-only, cacheable context endpoints |
| `programmable.py` | Worker side of `batch` and `execute`: tool registry, `$N` references, the single outer transaction, guards and replay |
| `project_index.py` | Reads a `.gpr` project's file index without a JVM (`list_project_files`) |
| `server_url.py` | Parses `ghidra://host[:port]/repository/path` URLs (no JVM) |
| `server_projects.py` | Ghidra Server connections and the local projects bound to repositories |
| `server_admin.py` | Repository commands run in a short-lived JVM process for the supervisor's repository tools |
| `prompts/` | MCP prompt stub (no prompts registered yet) |
| `__init__.py` | Lazy `bootstrap()` to start pyghidra/JVM, plus `find_ghidra_dir()` for Ghidra installation discovery |
| `_cli.py` | Convenience CLI entry point — `re-mcp-ghidra` is equivalent to `re-mcp --backend ghidra` |

### Tool modules

The backend has a `tools/` directory of tool modules, all following the same pattern:

```python
from fastmcp import FastMCP

from <backend>.helpers import ANNO_READ_ONLY, Address, Limit, Offset
from <backend>.session import session

def register(mcp: FastMCP):
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"domain"})
    @session.require_open
    def my_tool(address: Address, offset: Offset = 0, limit: Limit = 100) -> MyToolResult:
        """Tool description for LLM consumption.

        Args:
            address: Address of the thing.
        """
        # Implementation using backend-specific APIs
        return MyToolResult(result="...")
```

Key conventions:
- Backend-specific imports are top-level (safe because the worker calls `bootstrap()` before importing tool modules). Tool modules are auto-discovered via `pkgutil.iter_modules` — any `tools/*.py` with a `register(mcp)` function is loaded automatically
- `@session.require_open` is applied to all worker tools that need a database
- Every tool has MCP annotations (`ANNO_READ_ONLY`, `ANNO_MUTATE`, `ANNO_MUTATE_NON_IDEMPOTENT`, or `ANNO_DESTRUCTIVE`) and `tags=` for categorical grouping.
- Use `Annotated` type aliases (`Address`, `Offset`, `Limit`, `FilterPattern`, `HexBytes`) for parameter types — they embed descriptions and validation constraints directly into the JSON schema.
- Tool docstrings are sent to the LLM as tool descriptions — they should be clear and concise
- Tools that accept addresses use `resolve_address` or `resolve_function` from helpers

### Tool module grouping

Each module in `tools/` registers the tools of one domain. `docs/tools.md` lists every tool
with its description.

- **Program and lifecycle:** `database.py`, `analysis.py`, `documentation.py`, `undo.py`, `program_ops.py` (internal `_batch` / `_execute`)
- **Functions:** `functions.py`, `function_type.py`, `function_flags.py`, `function_ranges.py`, `frames.py`, `decompiler.py`, `decompiler_tokens.py`, `export.py`
- **Code and data:** `patching.py`, `assemble.py`, `data.py`, `data_definitions.py`, `memory_blocks.py`, `image_base.py`, `operands.py`, `operand_format.py`, `processor.py`, `register_values.py`, `cfg.py`, `switches.py`, `address_info.py`
- **Symbols and references:** `names.py`, `xrefs.py`, `xref_edits.py`, `imports_exports.py`, `entry_points.py`, `demangle.py`, `search.py`, `comments.py`, `bookmarks.py`, `colors.py`, `program_tree.py`
- **Types:** `types.py`, `data_type_lookup.py`, `structs.py`, `enums.py`, `c_source.py`, `function_id.py`
- **Scripts and servers:** `scripts.py`, `versioning.py`
- **Utility:** `utility.py`

## Resources

MCP resources provide read-only context about the open database. They are defined in each backend's `resources.py` and reserved for genuinely static or aggregate data that benefits from caching:

- **Static binary data** — imports, exports, entry points (baked into the binary, stable), each with a regex search variant
- **Aggregate snapshot** — statistics (function/memory block/entry point/string/name counts, code coverage)

The supervisor also owns one resource (`<scheme>://databases`) that lists all open databases with worker state.

### Resource proxying

Worker resources are exposed through `RoutingTemplate` instances in `WorkerPoolProvider`. Each `RoutingTemplate` stores the original worker URI template as `_backend_uri_template` and presents a prefixed version with `{database}` to clients (e.g. `ghidra://db/imports{?offset,limit}` becomes `ghidra://{database}/db/imports{?offset,limit}`). At read time, `_read()` pops `database` from the params to resolve the worker, then reconstructs the backend URI from the stored template with the remaining params. The supervisor's own database list resource is registered directly on the `FastMCP` server and served by FastMCP's internal local provider — the provider chain handles routing automatically.

## Prompts

MCP prompts provide guided analysis workflow templates. The Ghidra backend has a stub `prompts/` package with no prompts registered yet. Prompts are registered on the supervisor by the backend (via `register_prompts()`). Workers do not register or handle prompts.

## Adding a New Tool

1. Create `packages/re-mcp-ghidra/src/re_mcp_ghidra/tools/newtool.py` with a `register(mcp: FastMCP)` function
2. Define tool functions inside `register()` using `@mcp.tool()` and `@session.require_open`
3. Add `annotations=` (`ANNO_READ_ONLY`, `ANNO_MUTATE`, `ANNO_MUTATE_NON_IDEMPOTENT`, or `ANNO_DESTRUCTIVE`) and `tags=` to `@mcp.tool()`
4. Use `Annotated` type aliases for parameters: `Address`, `Offset`, `Limit`, `FilterPattern`, `HexBytes` (from core helpers)
5. Tool modules are auto-discovered — any `tools/*.py` with a `register()` function is loaded automatically
6. Use helpers from `helpers.py` — `resolve_address`, `resolve_function`, `paginate`, etc.
7. Return Pydantic model instances on success; raise the backend's error type on failure (do not return error dicts)
8. Add any new third-party imports to the `known-third-party` list in `pyproject.toml` under `[tool.ruff.lint.isort]`
