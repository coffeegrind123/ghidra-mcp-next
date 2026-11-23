# Tool renames and removals from upstream

Upstream's tool names came from another disassembler's vocabulary. An agent
working in Ghidra looks for Ghidra's terms (memory block, data type, program
tree, prototype), so tools, modules, models and result fields carry those
names. Upstream is dormant and this fork has no users of the old names, so
nothing is aliased. This server is Ghidra only.

| Old (upstream) | New | Why |
|---|---|---|
| get_ctree | get_decompiler_tokens | Ghidra has no ctree; it returns the ClangToken tree |
| find_ctree_calls | find_decompiled_calls | same |
| list_function_chunks | list_function_ranges | Ghidra functions have an address set, not chunks |
| append_function_tail | add_function_range | same |
| remove_function_tail | remove_function_range | same |
| create_segment | create_memory_block | Ghidra: memory blocks |
| delete_segment | delete_memory_block | same |
| set_segment_name | rename_memory_block | same |
| set_segment_permissions | set_memory_block_permissions | same |
| get_segments | list_memory_blocks | same; list_* for paginated listings |
| get_byte_flags | get_code_unit | Ghidra: the code unit at an address |
| get_local_type | get_data_type | Ghidra: data type manager, no "local types" |
| delete_local_type | delete_data_type | same |
| list_local_types | list_data_types | same |
| parse_source_declarations | parse_c_source | says what it takes |
| make_data / make_string / make_array | create_data / create_string / create_array | Ghidra: "Create data" |
| make_code | disassemble_at | Ghidra: Disassemble |
| undefine | clear_code_units | Ghidra: Clear Code Bytes |
| rename_address | rename_symbol | renames or creates the symbol at an address |
| rebase_program | set_image_base | Ghidra: Set Image Base |
| list_folders / create_folder / rename_folder / delete_folder | list_program_tree / create_program_tree_folder / rename_program_tree_folder / delete_program_tree_folder | "folder" is ambiguous with project folders |
| patch_asm | patch_instruction | says what it patches |
| export_all_pseudocode / export_all_disassembly | decompile_functions / disassemble_functions | they return, not export |
| get_imports / get_exports / get_entry_points / get_strings / get_bookmarks | list_imports / list_exports / list_entry_points / list_strings / list_bookmarks | paginated listings are list_* |
| get_function_type / set_function_type | get_function_prototype / set_function_prototype | Ghidra: function prototype/signature |

Removed:

| Tool | Why |
|---|---|
| list_regvars, rename_regvar | Same as list_decompiler_variables / rename_decompiler_variable (a register-variable concept Ghidra does not have) |
| take_snapshot, list_snapshots | Ghidra has no in-database snapshots; take_snapshot was save_database, list_snapshots returned a placeholder |
| generate_signatures | Returned "not available in Ghidra" |
| load_bytes_from_memory | Same as patch_bytes |

Tool modules (file names in `re_mcp_ghidra/tools/`):

| Old | New |
|---|---|
| ctree | decompiler_tokens |
| nalt | address_info |
| dirtree | program_tree |
| func_flags | function_flags |
| makedata | data_definitions |
| operand_repr | operand_format |
| srclang | c_source |
| typeinf | data_type_lookup |
| entry_manip | entry_points |
| xref_manip | xref_edits |
| chunks | function_ranges |
| segments | memory_blocks |
| rebase | image_base |
| regfinder | register_values |
| signatures | function_id |

Result fields and parameters: `segment_count` → `memory_block_count`; `ctree` →
`tokens`; `chunks` / `chunk_count` → `ranges` / `range_count`; `tail_address` →
`range_address`; `tail_start` / `tail_end` → `range_start` / `range_end`. Error types:
`MakeDataFailed` → `CreateDataFailed`, `UndefineFailed` → `ClearFailed`,
`RebaseFailed` → `SetImageBaseFailed`.
