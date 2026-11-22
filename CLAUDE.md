# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

ghidra-mcp-next: headless Ghidra MCP server (fork of jtsylve/re-mcp, Ghidra only). Python + FastMCP, stdio and streamable HTTP transports, pyghidra.

Design: `context/design.md` (transactions, batch, execute, measured Ghidra behaviour), `context/renames.md` (tool names vs upstream).

- Never open programs through `GhidraProject`: it holds a transaction open (deferred aborts, no undo, save fails). Use `session.open` / pyghidra's project API, and `session.analyze` for auto-analysis.
- `batch` / `execute` run in the worker (`re_mcp_ghidra.programmable`) as one main-thread job in one transaction. A tool that manages its own transaction or the worker goes in `NOT_IN_TRANSACTION`.
- Tools whose name starts with `_` are internal: never listed, searched or callable through `call`.
- Every tool and parameter needs a description (`Annotated[..., Field(description="... Example: ...")]`) that says when to use it and what it returns. Check with `/mcp-audit`; `.mcpgraderc.json` holds the accepted exceptions. Regenerate `docs/tools.md` with `scripts/gen_tools_doc.py`.
- Live tests (`tests/live`, real Ghidra and a throwaway Ghidra Server) run in CI on Ghidra 12.0.3 and 12.1.4.

## Commands

```bash
uv sync                              # Install dependencies
uv run ghidra-mcp-next               # Run the server (direct stdio mode; alias re-mcp-ghidra)
GHIDRA_INSTALL_DIR=/opt/ghidra uv run pytest tests/live   # Against real Ghidra
uv run ruff check packages/          # Lint
uv run ruff format packages/         # Format
uv run ruff check --fix packages/    # Lint with auto-fix
```

Pre-commit hooks run REUSE compliance checks, ruff lint (with `--fix --exit-non-zero-on-fix`), ruff format, and pytest on commit.

## Architecture

See `docs/architecture.md` for full details. The project is a monorepo with two packages:

- **`re-mcp-core`** (`packages/re-mcp-core/src/re_mcp/`): generic MCP supervisor infrastructure — `supervisor.py`, `daemon.py`, `proxy.py`, `worker_provider.py`, `backend.py`, `server.py`, `context.py`, `exceptions.py`, `helpers.py`, `models.py`, `sandbox.py`, `transforms.py`, `_process.py`
- **`re-mcp-ghidra`** (`packages/re-mcp-ghidra/src/re_mcp_ghidra/`): Ghidra-specific backend — `backend.py`, `server.py`, `session.py`, `helpers.py`, `exceptions.py`, `models.py`, `transforms.py`, `_cli.py`, `tools/`, `resources.py`, `prompts/`

Key points for editing:

- **Supervisor** (`re_mcp.supervisor`): entry point, `ProxyMCP(FastMCP)` + `WorkerPoolProvider`. Registers generic management tools (`close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`); each backend registers `open_database` via `backend.py`. Management tools use `try_get_session_id()` (from `re_mcp.context`). Most omit `ctx` from their signature; `save_database` is the exception (it accepts `ctx` for heartbeat progress notifications, but FastMCP strips it from the JSON schema).
- **Backend** (`re_mcp_ghidra.backend`): implements the `Backend` protocol — register `open_database`, prompts, backend-specific instructions, and target listing. Discovered via `re_mcp.backends` entry points.
- **Worker provider** (`re_mcp.worker_provider`): `WorkerPoolProvider(Provider)`, `RoutingTool(Tool)`, `RoutingTemplate(ResourceTemplate)`, `Worker` dataclass. Session-scoped ownership under `_lock` — `close_for_session()` and `detach_all()` are atomic. `ensure_session_cleanup()` registers a disconnect callback on the MCP session's exit stack.
- **Workers** (`re_mcp_ghidra.server`): one per database, stdio transport. Entry point: `re-mcp-ghidra-worker`.
- **Bootstrap-safe modules** (importable without `bootstrap()`): all `re_mcp` modules, plus `<backend>.exceptions`, `<backend>.models`, `<backend>.transforms`, `<backend>.prompts/`. The supervisor never imports backend-engine-required modules.
- **Engine-required modules**: `<backend>.helpers`, `<backend>.session`, `<backend>.tools/`, `<backend>.resources`. Backend-specific imports — only loaded in worker processes.
- `@session.require_open` (no parens) — decorator on nearly every tool
- All tools return Pydantic models on success; raise `BackendError` subclass on failure (`GhidraError`)

## Adding a New Tool

1. Create `packages/<backend>/src/<backend_pkg>/tools/newtool.py` with a `register(mcp: FastMCP)` function
2. Define tool functions inside `register()` using `@mcp.tool()` and `@session.require_open`
3. Add `annotations=` (`ANNO_READ_ONLY`, `ANNO_MUTATE`, `ANNO_MUTATE_NON_IDEMPOTENT`, or `ANNO_DESTRUCTIVE`) and `tags=` to `@mcp.tool()`
4. Use `Annotated` type aliases for parameters: `Address`, `Offset`, `Limit`, `FilterPattern`, `HexBytes` (from core helpers)
5. Tool modules are auto-discovered — any `tools/*.py` with a `register()` function is loaded automatically
6. Use helpers from `helpers.py` — `resolve_address`, `resolve_function`, `paginate`, etc.
7. Return Pydantic model instances on success; raise the backend's error type on failure (do not return error dicts)
8. Add any new third-party imports to the `known-third-party` list in `pyproject.toml` under `[tool.ruff.lint.isort]`

## Lint / Style

- ruff configured in `pyproject.toml` — line-length 100, target py312
- isort knows `pyghidra`, `ghidra`, `java`, `fastmcp`, and `mcp` modules as third-party (configured in `[tool.ruff.lint.isort]`)
