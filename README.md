# ghidra-mcp-next

A headless Ghidra MCP server that an agent can program against: a small fixed tool
list, the whole API discoverable on demand, and changes that are atomic, guarded and
safe to retry.

Forked from [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp) (its Ghidra backend),
reduced to Ghidra only and rebuilt around transactions.

## What it does differently

- **Atomic batches.** `batch` runs up to 100 tool calls as one Ghidra transaction.
  If any call fails, nothing changes, and the error names the failing op. A
  successful batch is one undo step named `MCP: <label>`. Later ops can use earlier
  results: `"$0.start"`, `"handler_${1.address}"`.
- **Real code mode.** `execute` runs Python 3 (CPython through pyghidra) against the
  Ghidra API and every tool (`tools.rename_function(...)`), in one transaction, with a
  read-only mode, a timeout and capped output.
- **Guards.** `if_revision` refuses to act on a program that changed since you read
  it. `operation_id` makes a retried write return the stored result instead of
  applying twice.
- **Small catalog.** 22 tools are listed. About 120 more are found with
  `search_tools` and called through `call`, `batch` or `execute`, and
  `ghidra://api/tools.pyi` serves all of them as typed Python signatures. The
  catalog costs ~6k tokens per request, and both the listed tools and the full
  catalog score A 100 on [mcpgrade](https://github.com/coffeegrind123/mcpgrade)'s
  code-mode profile.
- **Projects and servers.** It opens binaries, programs inside existing `.gpr`
  projects, and programs on a Ghidra Server (`ghidra://host/repo/path`) with
  checkout, checkin, history and undo-checkout.
- **Scripts.** `run_ghidra_script` runs existing Java or Python GhidraScripts in
  one transaction.

Opening programs without `GhidraProject` is what makes rollback, undo and save
work. `GhidraProject` holds a transaction open on every program it opens, which
makes aborts deferred, undo impossible and save fail. See
[`context/design.md`](context/design.md) for the measured behaviour.

## Requirements

- Ghidra 12.0 or newer (CI tests 12.0.3 and 12.1.4)
- JDK 21 (a JDK, not a JRE, to compile Java GhidraScripts)
- Python 3.12+ and [uv](https://docs.astral.sh/uv/)

## Install

```bash
git clone https://github.com/coffeegrind123/ghidra-mcp-next
cd ghidra-mcp-next
uv sync
```

## Configure (Claude Code)

```json
{
  "mcpServers": {
    "ghidra": {
      "type": "stdio",
      "command": "/path/to/ghidra-mcp-next/.venv/bin/ghidra-mcp-next",
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra_12.0.3_PUBLIC",
        "JAVA_HOME": "/opt/jdk-21"
      }
    }
  }
}
```

## Working with it

```text
open_database(file_path="/work/fw.bin", run_auto_analysis=true)  -> {database: "fw_bin"}
wait_for_analysis(database="fw_bin")
decompile_function(database="fw_bin", address="0x401000")
batch(database="fw_bin", label="name the parser", ops=[
  {"tool": "rename_function", "params": {"address": "0x401000", "new_name": "parse_packet"}},
  {"tool": "set_function_prototype", "params": {"address": "0x401000",
     "type_string": "int parse_packet(byte *buf, uint len)"}},
  {"tool": "set_comment", "params": {"address": "0x401000", "comment": "Entry of the parser",
     "comment_type": "plate"}}])
save_database(database="fw_bin")
```

```python
# execute: rename every small unnamed function, as one undo step
from ghidra.program.model.symbol import SourceType
n = 0
for f in program.getFunctionManager().getFunctions(True):
    if f.getName().startswith("FUN_") and f.getBody().getNumAddresses() < 16:
        f.setName("stub_" + f.getName()[4:], SourceType.USER_DEFINED)
        n += 1
return n
```

| Source | `open_database` arguments |
|---|---|
| A binary | `file_path="/path/bin"`: imported into `/path/ghidra_projects/` |
| An existing project | `file_path="/path/proj.gpr", program="/folder/prog"` (`list_project_files` lists them) |
| A Ghidra Server | `file_path="ghidra://host[:port]/repository/folder/prog"`, then `checkout_file` before editing |

Every tool is listed in [docs/tools.md](docs/tools.md).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | auto-detected | Ghidra installation |
| `GHIDRA_MCP_SERVER_USER` / `GHIDRA_MCP_SERVER_PASSWORD` | `$USER` / unset | Ghidra Server credentials. Never accepted as tool arguments. |
| `GHIDRA_MCP_SHARED_PROJECTS` | `~/.local/share/ghidra-mcp-next/shared` | Local projects bound to server repositories |
| `GHIDRA_MCP_SCRIPT_DIRS` | unset | Extra GhidraScript directories (`:`-separated), searched before `~/ghidra_scripts` and Ghidra's own |
| `GHIDRA_MCP_DISABLE_EXECUTE` | unset | `1` removes `execute` (arbitrary Python in the server) |
| `GHIDRA_MCP_DISABLE_BATCH` | unset | `1` removes `batch` |
| `GHIDRA_MCP_DISABLE_TOOL_SEARCH` | unset | `1` lists every tool instead of 22 plus search |
| `GHIDRA_MCP_MAX_WORKERS` | unlimited | Most databases open at once (1-8) |
| `GHIDRA_MCP_LOG_LEVEL` / `GHIDRA_MCP_LOG_DIR` | `WARNING` / unset | Logging |

`execute` and `run_ghidra_script` run arbitrary code with the server's
privileges. The server listens on stdio by default; `serve` binds HTTP to
`127.0.0.1` with a bearer token.

## Development

```bash
uv run ruff check packages tests && uv run ruff format --check packages tests
uv run pytest                                        # unit tests; live ones skip
GHIDRA_INSTALL_DIR=/opt/ghidra uv run pytest tests/live   # against real Ghidra
GHIDRA_INSTALL_DIR=/opt/ghidra uv run python scripts/gen_tools_doc.py
```

`tests/live` drives the real server through MCP: transactions, rollback, undo,
save and reopen, scripts, and a throwaway Ghidra Server for version control.

## License

Dual-licensed under the [MIT License](LICENSES/MIT.txt) and
[Apache License 2.0](LICENSES/Apache-2.0.txt), as upstream.

© 2026 Joe T. Sylve, Ph.D. (upstream re-mcp) and ghidra-mcp-next contributors.

*Ghidra is developed by the NSA. This project is not affiliated with or endorsed
by the NSA.*
