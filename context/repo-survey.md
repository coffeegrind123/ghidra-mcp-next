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

## cyberkaida/reverse-engineering-assistant (ReVa)

Read at 4bfae31a758639cab4d80704bc8884b508beacac (2026-11-17). Full spec:
`context/handoff-reva-spec.md` (local only). **In progress.**

Ported:

| What | Commit |
|---|---|
| Import addresses lost their EXTERNAL space; get_xrefs_to on an import found nothing (bug found by comparison) | b50f76c |
| Failed Python GhidraScripts committed their changes on 12.0/12.1 (bug found by comparison) | 399e07c |
| decompile_function line numbers, per-line addresses, paging | e3ba0fb |
| find_constant_uses (all operand objects), search_comments, find_function_candidates | 345c655 |
| run_ghidra_script time limit with rollback, file-backed capped output | d2feb48 |
| Not-found errors list close names; "code but no function" hint | b71a870 |
| set_decompiler_comment(line=) places comments by decompiled line | ea039c0 |
| get_call_graph direction/depth/cycle markers/truncation; find_common_callers (counts imports) | 89d28fd |
| analyze_dataflow typed, located stops (parameter/slot, global, load, call_result, store, call_arg, return); operand constants no longer origins; find_variable_accesses; ReVa dataflow fixture | eafc50e, d7e614e |
| Namespace-qualified names resolve ("Dog::vtable") | 0fe18a0 |
| analyze_vtable, find_vtables_containing, find_vtable_callers (adjacent-table merge fixed, pure-virtual gap kept, typed/offset_only confidence); ReVa C++ fixture | 61dd391 |
| diff_functions / diff_functions_across level="decompiled" with artifact classes (var-renumber, string-label) | bc1d5b2 |
| Signature export pages overlapped (found while reading the matcher for diff_programs) | a3a524d |
| diff_programs (code/callees/size/bytes change types, unmatched listed, analysis warning) | 3b8ccac |
| diff_strings (strings, or defined data as type=value, multiset across builds) | a9a7f70 |
| diff_programs: callees compared through the match (rename/edit of a callee no longer flags its callers; found by CI) | 50315d3 |
| list_names source/type/external/default-name filters; list_functions tag/untagged/default names; get_function thunk_target | 6ca5f77 |
| set_bookmark type; list_bookmarks type/category/regex/range filters and categories | 9d659f8 |
| find_import_references (direct, thunk, IAT/GOT pointer); list_imports original_name and ordinal | 1917602 |

Left: MAYBE and SKIP lists in the spec (list_strings include_referencing_functions,
get_comments over a range, inter-procedural dataflow, VT correlators).

## cellebrite-labs/ghidra-rpc

Read at fa3866243dcfcbc876baa7b13ae0deac2c443cd8 (0.3.0). Full spec:
`context/handoff-ghidra-rpc-spec.md` (local only). README says MIT; no LICENSE file.
**In progress.**

Ported:

| What | Commit |
|---|---|
| get_xrefs_to follows thunks (with the address-space fix) | b50f76c |
| Ghidra 12.2 removed DataTypeManager.remove(dt, monitor); CI now tests 12.2 | ff45bce |
| One shared decompiler per program with the program's options (~14x faster) | 44d238c |
| search_decompiled with resume cursor and revision-keyed cache | 83065f2 |
| Context registers, relocations, set_function_thunk | 345c655 |
| decompile timeout_s | e3ba0fb |
| Decompiler variable edits by storage, verified read-back, edit_decompiler_variables (atomic); EditDisplaced for the measured silent neighbour deletion | 1af139e |

Found while testing 12.2 (not from either repo): Ghidra 12.2 clients reject a Ghidra
Server's self-issued certificate; GHIDRA_MCP_SERVER_CACERTS / _TRUST_LOOPBACK (bf97d1c).

Left: Version Tracking run
inside the destination worker (source opened read-only from its saved project) and BSim
as a fuzzy engine, both gated on the precision/recall measurement in the spec §3.5;
MAYBE items in the spec.
