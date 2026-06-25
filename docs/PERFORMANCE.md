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

**Future work:** make the inverted scan provably equivalent (filter to
`type==CALL`, reconcile symbol sources) before swapping, or parallelize the
per-function loop across worker r2 instances for very large binaries (net win
only when loop time >> the repeated `aaa` cost).
