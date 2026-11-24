# Function matching: precision and recall (spec §3.5)

Measured 2026-11-23 on Ghidra 12.0.3 / JDK 21, through the MCP server
(`match_functions`, `auto_version_track`). Harness: a client script that opens
both builds, names every source function from its `-dbgsym` symbol table (a
documented source), leaves the target as shipped (exported names only), runs one
method, and scores the pairs.

- Truth: a pair is correct when both addresses carry the same debug-symbol name,
  and that name occurs exactly once in each build.
- Scored: source functions of at least 10 instructions whose name is unique in
  both builds. Recall = correct / scored; precision = correct / scored pairs
  returned.
- Corpus: Debian `liblzma5` + `liblzma5-dbgsym` (downloaded, nothing compiled):
  5.4.1-1+deb12u1 -> 5.8.1-1+deb13u2 (large gap: three minor versions, a
  compiler change), and 5.8.1-1+deb13u2 -> 5.8.4-1 (close pair).
- Seconds are the matching call only, on a shared, memory-pressed machine;
  compare them within a row set, not across runs.

## 5.4.1 -> 5.8.1 (267 scored functions)

| Method | Pairs | Correct | Wrong | Precision | Recall | Seconds |
|---|---|---|---|---|---|---|
| fid_specific | 7 | 7 | 0 | 1.000 | 0.026 | 48.2 (incl. warm-up) |
| fuzzy | 73 | 72 | 1 | 0.986 | 0.270 | 5.4 |
| vt | 11 | 11 | 0 | 1.000 | 0.041 | 1.5 |
| bsim (no cut) | 240 | 235 | 5 | 0.979 | 0.880 | 17.5 |
| auto_version_track | 91 | 91 | 0 | 1.000 | 0.341 | 3.4 |

## 5.8.1 -> 5.8.4 (296 scored functions)

| Method | Pairs | Correct | Wrong | Precision | Recall | Seconds |
|---|---|---|---|---|---|---|
| fid_specific | 43 | 43 | 0 | 1.000 | 0.145 | 2.6 |
| fuzzy | 65 | 65 | 0 | 1.000 | 0.220 | 11.5 |
| vt | 69 | 69 | 0 | 1.000 | 0.233 | 1.6 |
| bsim (no cut) | 251 | 242 | 9 | 0.964 | 0.818 | 18.6 |
| auto_version_track | 132 | 130 | 2 | 0.985 | 0.439 | 7.5 |

## BSim by confidence

| Cut | 5.4->5.8 precision / recall | 5.8.1->5.8.4 precision / recall |
|---|---|---|
| none | 0.979 / 0.880 | 0.964 / 0.818 |
| >= 10 | 0.987 / 0.880 | 0.988 / 0.818 |
| >= 15 | 0.996 / 0.843 | 0.985 / 0.662 |
| >= 60 | 0.992 / 0.479 | 1.000 / 0.382 |

All 11 BSim pairs under confidence 10 were wrong; no correct pair was under 10.
The wrong pairs left at >= 10 are mostly identical-body functions
(`block_decoder_end` / `lzip_decoder_end`, `index_stream_end` /
`index_tree_node_end`: same code, so no matcher can tell them apart by body)
plus `lzma_crc32` and `get_progress`.

## Decisions

- **fuzzy stays the default fuzzy engine.** The spec's rule was "adopt bsim if
  it beats fuzzy on recall at >= equal precision". Recall: bsim 3-4x higher on
  both pairs. Precision at the >= 10 cut: 0.987 vs 0.986 on the large gap
  (passes), 0.988 vs 1.000 on the close pair (fails).
- **`algorithm="bsim"` drops pairs under confidence 10** (`BSIM_MIN_CONFIDENCE`
  in `matching.py`), keeping accepted exact seeds. Re-measured with the cut in
  the server: 238 pairs, 3 wrong, 0.987 / 0.880 (large gap); 245 pairs, 3 wrong,
  0.988 / 0.818 (close pair). Precision up, recall unchanged.
- `vt` (exact seeds, then `combined_reference`) was only as good as its seeds:
  4% recall across the large gap, where few functions are byte-identical.
  **Seeding also from `symbol_name`** (identical names: the exported functions)
  fixed that. Re-measured, vt / bsim precision / recall:

  | Pair | vt before | vt after | bsim before | bsim after |
  |---|---|---|---|---|
  | 5.4.1 -> 5.8.1 | 1.000 / 0.041 | 1.000 / 0.390 | 0.987 / 0.880 | 0.988 / 0.899 |
  | 5.8.1 -> 5.8.4 | 1.000 / 0.233 | 1.000 / 0.493 | 0.988 / 0.818 | 0.996 / 0.831 |

  vt now beats fuzzy on both pairs (precision 1.000 vs 0.986 / 1.000; recall
  1.4x and 2.2x). It is not made the default: it opens a VT session on the
  target, which clears the target's undo history, and two library pairs are a
  small sample. bsim still misses the precision rule on the close pair (0.996 vs
  1.000).
- `auto_version_track` is the most precise way to carry names automatically, but
  it applies markup on its own judgement (2 wrong of 132 on the close pair).

Not measured yet: a cross-compiler pair (gcc vs clang, CI-built only), and a
larger library (thousands of functions) for BSim's runtime.
