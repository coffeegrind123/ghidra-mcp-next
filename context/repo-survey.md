# Survey of other Ghidra MCP projects

What we took from each project, what we might take, and what we left. One section per
repo: the commit read, then PORT (wanted, missing), MAYBE (with the measurement that
decides it) and SKIP items. Ported items name the commit that landed them.

## bethington/ghidra-mcp

Read at 8dbbb1f677166fe483d605f925d60da080e448f2 (7.1.0, 2026-11-20). Full spec:
`context/handoff-bethington-spec.md` (local only). **Done.**

Ported (every one with live tests against real Ghidra):

| What | Commit |
|---|---|
| parse_c_source / parse_type_declaration kept only the last declared type (bug found by comparison; CParser storing mode) | e1d932f |
| Documentation propagation: get_function_hashes (FID, VT hashers), get/apply_function_documentation, match_functions, propagate_documentation (.gdt type transfer, one undo step) | f0bcbfc |
| Direct write calls get their own transaction (found while porting) | 1adeae5 |
| set_variable_storage, set_flow_override, clear_flow_and_repair, create_label, delete_label | 46470be |
| list_analyzers, configure_analyzer, run_auto_analysis(analyzers=[...]) | 8badfef |
| Data type categories, rename, clone (copy), consolidate (replaceDataType), find_data_type_uses | 6a30ce2 |
| Ghidra Server users, repository permissions (merged ACL), server-side checkout listing, terminate by id | 285dc03 |
| get_function_metrics (dominator loops), analyze_call_graph, find_code_gaps, get_function_pcode, analyze_dataflow, diff_functions | 91998c4 |
| Equates, function tags, set_function_class / list_class_members, wildcard search_bytes | 5cf8e7a |
| Fuzzy matching (export_function_signatures, one-to-one with margin), diff_functions_across | 4cb6a65 |

Measured and skipped:
- Thunk no-return chain walk: on Ghidra 12.0.3, `setNoReturn` on a thunk sets it on the
  thunked function and both read the same, so the walk is unnecessary.
- Plate comments survive `set_function_prototype` (measured earlier); upstream's
  ordering rule does not apply.

Still MAYBE (decide by demand): analyze_data_region, list_data_by_xrefs, BSim as the
fuzzy engine, rule-driven API/IOC scans, program options, resize_struct, .gzf export,
list_shadowed_globals, partition_program. SKIP: ~28 tools (covered, stubs, broken, GUI,
debugger, emulation).

Upstream flaws not to copy: CALL_EXT hash collisions and offset-based jump targets in
the function hash, name-based callee matching in fuzzy match, many-to-one bulk matches,
partial commits in merge, the stub find_dead_code, substring malware heuristics.
