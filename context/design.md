# ghidra-mcp-next design

Fork of jtsylve/re-mcp, Ghidra only. Goal: a headless Ghidra MCP server an agent can
*program against*: a small fixed tool list, the full API discoverable on demand, and
writes that are atomic, guarded and replay-safe.

## Measured Ghidra behaviour this design rests on

Probed on Ghidra 12.0.3 / JDK 21 / pyghidra 3.1.0 (`scratchpad probe`, 2026-11-22):

| Fact | Consequence |
|---|---|
| `GhidraProject.openProgram/importProgram` keep a "Batch Processing" transaction open on the program for its whole life. | Every transaction we start is nested inside it: an abort is deferred, `undo()` throws "Can not undo while transaction is open", and `save` fails ("Unable to lock due to active transaction", upstream #55). **Never open programs through `GhidraProject`.** |
| Opening with `pyghidra.open_project` + `program_loader()` + `consume_program` leaves no transaction held. | Use these. |
| Outer `endTransaction(id, False)` rolls back everything, including nested transactions that were committed. | A batch is one outer transaction; tool functions keep their own (nested) transactions unchanged. |
| A nested `endTransaction(id, False)` poisons the outer one: the outer commit returns `False` and nothing is kept. | Batch must treat "outer commit returned False" as a failure, and report it. |
| A committed outer transaction is one undo step named by its description; `undo()` removes it. | Undo step name = `MCP: <label>`. |
| `getModificationNumber()` increases on every transaction, **including aborted ones**. | `revision` = modification number. Every result (success or failure) returns the current `revision`, so an agent never holds a stale one after a rollback. |

## Tool surface

Listed (always visible, ≤ 25): lifecycle (`open_database`, `close_database`,
`list_databases`, `wait_for_analysis`, `save_database`, `list_targets`), the core
read loop (`decompile_function`, `list_functions`, `get_xrefs_to`, ... the pinned set),
and the meta tools:

| Tool | Role |
|---|---|
| `search_tools` | Regex search over every hidden tool (name, description, tags). |
| `get_schema` | Signatures and parameter docs for named tools. |
| `call` | Call one hidden tool. |
| `batch` | Ordered ops, ONE transaction, `$N` references, guards. Below. |
| `execute` | Python against the Ghidra API and the tool functions. Below. |

Everything else (~130 tools) is reached through `search_tools` + `call`/`batch`/`execute`.

## `batch`

Runs **inside the worker**, as one main-thread job, so no other request can interleave
with it and every op shares one `Program` transaction.

```
batch(database, ops=[{tool, params}], label="", if_revision=None,
      operation_id=None, dry_run=False) -> {results, revision, undo_name}
```

- ≤ 100 ops (`maxItems`).
- `"$N.path"` in any param string is replaced by the value at `path` in op N's result
  (`$0.address`, `$2.items.0.name`). A whole-string reference keeps the JSON type;
  `"${N.path}"` interpolates inside a longer string. `$$` escapes a literal `$`.
- Opens `MCP: <label>` (default: the op tool names), runs ops in order, commits.
  First failing op → abort → **nothing changed**; error carries `op_index`, `tool`,
  `error_type`, message and the current `revision`.
- `if_revision`: refuse with `target_changed` if the modification number differs.
- `operation_id`: results of the last 256 successful writes are kept per worker; a
  repeat returns the stored result with `replayed: true` and does not run again.
- `dry_run`: run everything, then abort. Validates a plan and returns what it would do.
- Lifecycle tools and meta tools are rejected inside a batch (`invalid_op`).

## `execute`

Also inside the worker, on the main thread.

```
execute(database, code, read_only=False, label="", timeout_s=30, if_revision=None,
        operation_id=None) -> {result, stdout, revision, truncated}
```

- Python 3 (CPython via pyghidra/JPype, not Jython). The body is a function body:
  `return` gives the result (JSON-serialisable; Java objects are `str()`-ed).
- Globals: `program` (also `currentProgram`), `flat` (FlatProgramAPI), `monitor`,
  `toAddr`, `decompile(func_or_addr) -> str`, `tools.<name>(**params)` (every tool,
  returning the same dict the MCP tool returns), and the `ghidra`/`java` packages.
- Same transaction model as `batch`: one undo step, exception → rollback.
  `read_only=True` always aborts, so a read-only script cannot change the program.
- `timeout_s` (≤ 600) is enforced between Python lines (trace hook); a single long
  Java call can overrun it. stdout capped at 64 KiB, result at 256 KiB (`truncated`).
- Off with `GHIDRA_MCP_DISABLE_EXECUTE=1`.

Upstream's `execute` (RestrictedPython in the supervisor that can only chain
`invoke`) is replaced: it cannot touch the Ghidra API, which is what the agent needs.

## Projects

- `open_database(file_path=...)` imports a binary into `<dir>/ghidra_projects/<name>`
  (upstream behaviour, now via `program_loader`).
- `open_database(project="/path/X.gpr", program="/folder/prog")` opens a program
  inside an **existing** project, no import.
- `list_project_files(project=...)` lists a project's folders/programs (supervisor-side
  read via a worker-less helper is not possible without a JVM; it runs in a worker).

## Ghidra Server

Programs opened from a shared (server-backed) project support `checkout`, `checkin`,
`undo_checkout`, `get_version_history`. Auth: `GHIDRA_MCP_SERVER_USER` /
`GHIDRA_MCP_SERVER_PASSWORD` via Ghidra's headless client authenticator.

## Scripts

`run_ghidra_script(path, args)` runs any GhidraScript (Java or Python) on the open
program via `pyghidra.ghidra_script`'s mechanism, inside a transaction like `execute`.

## Naming

Tool, module, model and field names use Ghidra's terms (memory block, data type,
program tree, prototype, decompiler tokens, function ranges). The rename list lives in
`context/renames.md` with the reason for each.

## Grading

`/mcp-audit` with the code-mode profile; target grade A. Exceptions go in
`.mcpgraderc.json` with reasons.

## Version Tracking (Ghidra VT)

Measured on Ghidra 12.0.3 and 12.2 (probes p1-p3, 2026-11-23):

| Fact | Consequence |
|---|---|
| VT needs both programs in one JVM; a second process cannot `open_project` a locked project, but `DefaultProjectData(locator, False, False)` + `getReadOnlyDomainObject` can, and sees only the SAVED state. | The session lives in the DESTINATION worker; the supervisor saves the source first (`save_source`) or refuses (`UnsavedSource`). |
| `VTSessionDB(...)` joins the destination's transaction manager (`addSynchronizedDomainObject`). Joining and leaving clear the destination's undo history. | `_vt_open` and `close_version_track` are `NOT_IN_TRANSACTION`; results report `undo_history_cleared`; descriptions say so. |
| While joined, a destination transaction IS a VT transaction: one undo step covers markup and association status; `undo` reverts both. A rollback reverts both. | Correlate, accept/apply and auto-VT are ordinary atomic write tools (batchable, `dry_run` works). |
| Shared undo names read `"<file>: <description>"`, one line per object changed; a VT-only step has no program line. | `programmable.step_name` strips it, for `undo`/`redo` and batch's `undo_name`. |
| A session stores source and destination as file IDs of ONE project; reopening a saved session whose source is in another project fails ("Source program is missing"). | Sessions are in memory, per worker lifetime, released (VT first) before the program closes or reopens (`session.attach`). |
| Reference correlators find nothing until matches are ACCEPTED. | `match_functions(algorithm="vt"/"bsim")` accepts the one-to-one exact matches as seeds (VT status only, no markup), then runs `combined_reference` / `bsim`. |
| Ghidra caches markup items per association and clears them only when the association record disappears. After a rollback or undo the record survives, so items still read ADDED and a later apply copied nothing. | `_markup_items` clears that private cache (reflection on `markupManager`) before each read. Test: dry_run, then apply. |
| AutoVersionTrackingTask runs fine inside our open transaction (one undo step); unset VTOptions take the AutoVersionTrackingScript defaults. | `auto_version_track` = open + `_vt_auto`. |
| `/bin/true`: BSim correlator ~8.5 s (decompiles every function of both programs); exact correlators < 0.5 s. | `timeout_s` on correlate/auto (TimeoutTaskMonitor); a timeout keeps nothing. |

Not yet measured: a source opened from a Ghidra Server (shared) project. The worker
reads the shared project's local directory read-only; a versioned file that is not
checked out may have no local content, in which case `_vt_open` fails with
`OpenFailed` and the message from Ghidra.
