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

## Rejected: batched single-roundtrip axffj

Collapsing the N per-function `axffj` queries into one piped r2 command
(`s addr; axffj; ...` with delimiters) measured **3.9x faster** on the
23k-func ELF (1.28 s vs 5.03 s, identical semantics in principle). Not adopted:
reliably splitting r2's concatenated command output back into per-function JSON
is fragile (the prototype mis-parsed every record), and for most binaries the
loop is not the bottleneck anyway — `aaa` is.

## Bottom line

For the common case `aaa` dominates and is already capped by `anal.timeout`.
The per-function loop only dominates on pathological function-dense binaries
(200k+). No simple, result-preserving, maintainable speedup is available there
without validation work that would risk changing what a security tool flags, so
the per-function `axffj` model is kept as-is.

**Future work:** make the inverted scan provably equivalent (filter to
`type==CALL`, reconcile symbol sources) before swapping, or parallelize the
per-function loop across worker r2 instances for very large binaries (net win
only when loop time >> the repeated `aaa` cost).

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
