# Performance notes

Benchmarked against a VirusTotal sample set spanning formats (ELF ARM/x86-64,
Mach-O arm64, PE32/PE32+) and sizes. Wall-clock measured end-to-end
(`-f <sample> -o output`), single-threaded.

## Headline: cost scales with function count, not file size

| format            | functions | unsafe | seconds |
|-------------------|----------:|-------:|--------:|
| ELF ARM (stripped)|         5 |      0 |    0.34 |
| PE32              |        10 |      0 |    0.40 |
| Mach-O arm64      |        38 |      0 |    0.54 |
| PE32              |        81 |      0 |    0.67 |
| PE32              |        92 |      0 |    0.98 |
| ELF x86-64 PIE    |    23,195 |  1,655 |   36.20 |
| Mach-O arm64      |   200,943 |    105 |  400.84 |

A 30 MB binary with few functions is sub-second; a smaller binary with 200k
functions takes minutes. The driver is the per-function work, not bytes on disk.

## Where the time goes

For the 23,195-function ELF: `r2 open + aaa` alone is **29.5 s** (it hits the
`anal.timeout=30` cap), and the per-function detection loop is the remaining
~6.7 s. Two cost centres:

1. **`aaa`** — bounded by `anal.timeout` (constants.py `DECOMPILER_TIMEOUT=30`).
2. **Per-function loop** — one `axffj @ <addr>` r2pipe round-trip per function
   (~0.3–1.8 ms each). On function-dense binaries this dominates: the 200k-func
   Mach-O spends ~370 s here.

## Rejected: inverted xref scan

Asking "who calls each banned symbol" (`axtj @ sym.imp.<name>`, bounded by the
handful of banned imports present) instead of "what does each function call"
(one query per function) measured **13x faster** on the 23k-func ELF
(0.58 s vs 7.46 s). It was **not adopted**: the result set diverged from the
per-function model (2162 vs 1645 functions flagged; 736 only-inverted, 219
only-current). For a security detector, silently changing what gets flagged is
unacceptable without ground-truth equivalence work. `axj` (a single global
xref dump) returns empty on this r2 build, so there is no drop-in
result-preserving batch query either.

## Rejected: skip functions with call-graph outdegree == 0

`aflj` reports `outdegree` (call-graph out-edges), and 45% of the 23k-func ELF
have outdegree 0 — tempting to skip their `axffj` query. **Unsafe**: outdegree
counts edges to analysed *functions*, not to imports, so a thunk that only calls
`sym.imp.strcpy` has outdegree 0 yet a banned CALL xref. Measured 15 such
functions on the 23k ELF — skipping them would drop real detections.

## Rejected: batched / chunked single-roundtrip axffj

Collapsing the N per-function `axffj` queries into one piped r2 command
(`axffj @ a; ?e MARKER; ...`, parsed back per function) measured **3.3–3.8x
faster** and is identical by construction. **Not adopted: it does not survive
scale.** With a marker scheme that parses cleanly for 3 functions, batches of
200–1000 functions come back from `r2.cmd()` with the `?e` markers missing
entirely (0 parsed of 23k) — r2pipe's handling of large multi-command strings is
unreliable, and the failure is silent (it would yield zero detections, not an
error). This is an r2pipe interface limitation, not a parser bug. Shipping
output-parsing whose correctness depends on input size is unacceptable for a
security detector.

## Bottom line

For the common case `aaa` dominates and is already capped by `anal.timeout`.
The per-function loop only dominates on pathological function-dense binaries
(200k+). The optimization space has been investigated exhaustively — inverted
scan, outdegree skip, lighter analysis, batched/chunked queries, the global
`axj` dump (empty on this r2 build), and r2 `anal.threads` (absent in 6.1.8) —
and **every avenue is either result-changing or unreliable at scale**. The
per-function `axffj` model is kept as-is.

**Only remaining real lever** (a dedicated project, not a quick change): a
custom r2 plugin / native batch primitive that returns all functions' call
xrefs in one reliable round-trip, or sharding the loop across worker r2
processes that load a saved analysis project (`Po`) instead of re-running `aaa`.

## Robustness note: r2 can die mid-scan on huge binaries

On the 200k-function Mach-O under memory pressure, the r2 child process was
SIGKILL'd partway through the per-function loop (`axffj @ <addr>` →
"Process terminated unexpectedly"). The tool catches the per-function error and
continues, so it returns a partial count without raising — one run reported 82
unsafe where an unpressured run found 105. The detections are still correct,
just incomplete. Surfacing "scan truncated, N functions unanalyzed" to the
analyst (rather than a silently-partial count) is worthwhile future work; it
needs a truncation flag threaded through the result/summary DTO, so it was not
rushed here. Tested r2 build (6.1.8) exposes no `anal.threads` knob, so the
orphaned `r2pipe_threads` config could not be wired to in-r2 parallelism and
was removed instead.
