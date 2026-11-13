# Logging and observability audit

## Application profile

BannedFuncDetector is a Python CLI and importable library. The main flow parses arguments, validates the local radare2 toolchain, creates application wiring, analyzes one binary or scans a directory, writes JSON/text/HTML analysis reports, and returns a result to the CLI or library caller. Directory scans may use `ProcessPoolExecutor`; individual binary analysis may query the local r2ai/Ollama HTTP services. The project has no database, authenticated web API, durable queue, scheduled jobs, or always-on service lifecycle, so database, request-authentication, and service-health metrics do not apply.

## Current design

- Components use the standard-library `logging` API and module-named loggers.
- CLI setup remains available through `bannedfuncdetector.cli_bootstrap.configure_logging`; output handlers and formatters live in `bannedfuncdetector.infrastructure.logging_config`, while request/operation context and safe exception metadata live in the dependency-free `bannedfuncdetector.observability` module shared by application and infrastructure. `application.observability` remains a compatibility re-export. Worker logging initializers are injected by the outer runtime factory. Text is the default and JSON can be selected with `BFD_LOG_FORMAT=json`. `BFD_LOG_LEVEL` selects a standard Python level, and invalid names fall back to `INFO`.
- `BFD_LOG_DESTINATION` selects `stderr` (default), `stdout`, or `file:<path>`. File output uses [`concurrent-log-handler`](https://github.com/Preston-Landers/concurrent-log-handler)'s `ConcurrentRotatingFileHandler` with a 10 MiB limit and five backups. This serializes writes and rotation from custom process workers; each spawned worker configures its own handler. On POSIX, the active and rotated log files use mode `0600`. The destination is opened during setup so an inaccessible path triggers the stderr fallback immediately. If the host already configured root handlers, they are retained and take precedence; request-context and sanitizing filters are added without replacing their destinations or formatters. No remote collector or vendor SDK is required.
- JSON records include UTC `timestamp`, `level`, `service`, `component`, and `message`. Analysis completion adds `operation`, `event_name`, `duration_ms`, and `outcome`; binary and directory analysis failures include normalized `error_type` when available, `error_category`, `error_phase`, and OS `error_code` when present. Their main event message is stable and does not repeat exception text; a sanitized stack trace with file/line/frame names, but no source lines or exception message, is attached once where it helps diagnose an unexpected boundary failure. The top-level `requirements_check_completed` and `requirements_check_failed` events carry operation, duration, outcome, and process exit code on failure without subprocess output. Unsupported Python runtimes emit `python_version_unsupported` with the runtime-validation operation and exit code. Function-task failures and cancellations carry operation, event, type/category, and outcome even when verbose output is disabled; raw plugin exception text is omitted from these logs. Final banned-function findings emit one structured event per finding with the file, detection method, function, address, and matched banned calls. Function decompilation failures are emitted once at the iterator boundary and rate-limited by batch position. Text records include UTC timestamp, level, component, and active `request_id`/`operation` fields when available.
- A generated `request_id` scopes each CLI run and each public library call; it is explicitly included in directory worker payloads and restored after nested calls. The default process executor forwards records through a parent listener. Injected thread/process executors also propagate the ID, while custom process log delivery uses the destination configured in each worker. The ID is not a W3C trace ID. The project does not make distributed calls between independently deployed services, so distributed spans and metrics are not configured.
- `operation_context()` uses a separate `ContextVar` and adds the active operation to nested binary/directory events. Nested binary work overrides the directory operation for its own events and restores the outer value afterward; explicit per-event `operation` fields take precedence. Worker wrappers establish the context for thread and process execution.
- CLI failures that have not already been logged carry `event_name="analysis_error"`, `outcome`, error type, and category/phase when available. Binary input, decompiler selection, and directory validation failures are logged once at their owning boundary and carried as `logged`; the CLI does not repeat them or append a generic duplicate error.
- Credential-like fields (including quoted values with spaces), whole `Cookie`/`Set-Cookie` headers, URL userinfo/path/query, and Unicode control/line separators are redacted or escaped. The sanitization is idempotent across the handler filter and formatter. Home-directory prefixes in configured log messages are shortened to `~`; text fields in JSON `request_id`, `operation`, `event_name`, `outcome`, `error_type`, `error_code`, `error_line`, `error_column`, `error_category`, `error_phase`, and `dropped_count` values pass through the same sanitizer. Configuration parse/read failures log only the exception type, OS code, parser line/column, and config basename; raw exception text and traceback are omitted to prevent config-content disclosure. Cleanup notices retain a generic failure reason and basename in logs, never the arbitrary closer error text. Binary validation failures use a stable event and omit the supplied input path. The optional `r2ai-server` integration omits endpoint URLs, command paths, remote model names, and exception text from its events; it records outcomes, counts, durations, and exception types instead. R2 command and client lifecycle diagnostics omit raw commands, binary paths, flags, model names, and exception text from logs while preserving returned errors for API callers. File discovery records format and count without candidate or directory paths; symlink and unreadable-entry events also omit paths. Binary setup/extraction, directory validation/discovery and result collection, bulk xref fallback, decompiler availability and command fallbacks, R2 connection lifecycle and retries, file detection, report opening, and output-directory creation events likewise avoid exception messages and unnecessary paths while retaining exception type and numeric OS error code where available. Requirement command timeouts and blocked-command events omit argv and process output. Messages and stack traces are capped at 16,384 characters. Stack traces contain only the basename, line, and frame name, excluding full paths, source lines, and exception messages. Message/exception formatting failures fall back to safe placeholders rather than escaping into application code. Requirement-check failures record command result metadata rather than subprocess output.

## Event levels

- `DEBUG`: details needed for local diagnosis, including optional backend and file-detection fallbacks.
- `INFO`: requirement checks, analysis completion, and other meaningful transitions.
- `WARNING`: recoverable limitations, unavailable optional tools, and operational notices.
- `ERROR`: failed operations and captured exceptions.
- `CRITICAL`: reserved for process-continuity failures; no current flow has a justified use for it.
- Python logging has no built-in `TRACE` level; the project does not add a custom level.

## Security and limits

Redaction is defense in depth and uses patterns, not a complete data-loss-prevention engine. Before any configured root handler sees a record, sensitive extra-field names are redacted, nested values and strings are bounded and sanitized, control characters are escaped, and raw exception objects are removed after safe frame locations are retained. URL logs are reduced to scheme and authority, dropping userinfo, path, and query. New log calls must avoid credentials, cookies, binary contents, full HTTP bodies, and confidential data at their source. Do not log arbitrary request/response bodies or subprocess output. Control characters are escaped to reduce log forging. JSON encoding keeps event values on one physical line.

The default stream handler is synchronous in the parent process. The default directory `ProcessPoolExecutor` path forwards worker records through a bounded 10,000-record queue to one parent `QueueListener`, preventing worker writes from interleaving. Queue enqueue is non-blocking; when saturated, records below `ERROR` are dropped, a saturation warning and recovery count go to stderr, and `ERROR`/`CRITICAL` records are mirrored there as an emergency path. This preserves analysis progress while making loss visible. Injected custom executors retain their own logging transport; with file output, the concurrent rotating handler protects shared-file writes. There is no sampling or rate limiting. Deployments that need durable, centralized, or high-volume collection should provide a process-level logging collector and validate worker output under their operating system.

## Configuration and operation

| Variable | Default | Values / behavior |
|---|---|---|
| `BFD_LOG_LEVEL` | `INFO` (or `DEBUG` with `-v`) | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`; an unknown value falls back to `INFO`. |
| `BFD_LOG_FORMAT` | `text` | `text` or `json`; unknown values use text. |
| `BFD_LOG_DESTINATION` | `stderr` | `stderr`, `stdout`, or `file:/path/to/bfd.log`. File logs rotate at 10 MiB and retain five backups. An unavailable file falls back to stderr and emits `logging_destination_fallback`. |
| `BFD_ENVIRONMENT` | unset | Optional deployment label included in JSON events. |

For local troubleshooting, run `BFD_LOG_LEVEL=DEBUG bannedfunc --file ./sample.bin`. To produce machine-readable output, use `BFD_LOG_FORMAT=json BFD_LOG_DESTINATION=file:./bfd.jsonl bannedfunc --directory ./samples`. Inspect recent events with `tail -n 50 ./bfd.jsonl`; when `jq` is installed, filter failures with `jq 'select(.level == "ERROR")' ./bfd.jsonl`. Text mode writes to stderr by default, leaving stdout available to scripts and report output.

A JSON event captured locally while writing a report:

```json
{"timestamp":"2026-11-13T17:02:00.174531Z","level":"DEBUG","service":"bannedfuncdetector","component":"bannedfuncdetector.application.binary_analyzer.reporting","message":"Analysis report saved","operation":"report_write","event_name":"report_saved","duration_ms":0.18,"outcome":"success"}
```

Directory scans emit a single structured start event with execution mode and file/worker counts, followed by one result event for each successful file. For example, a verbose sequential scan emits `directory_analysis_started` with `execution_mode="sequential"` and `worker_count=1`, then `directory_file_analysis_completed` with `outcome`, `insecure_count`, and `total_functions`; neither event includes a local path. The final presentation layer emits one `analysis_summary` event with `file_count`, `insecure_count`, and a clean/issues-found outcome, then emits one `banned_function_detected` event per finding. Verbose decompilation emits `decompilation_progress` and `decompilation_summary` events with normalized function counts and completion percentages. Rejected unsafe symbol names are recorded as `unsafe_function_name_rejected` without the raw name.

New events should use a module logger and lazy `%s` formatting. Put stable machine-readable names in `extra`, and keep the message short and free of secrets. Binary and directory use cases establish an operation context, so nested events inherit `operation`; explicit per-event metadata remains appropriate for distinct sub-operations. Directory analysis emits `operation="directory_analysis"`, `event_name="analysis_finished"`, `duration_ms`, and `outcome`. A comparable operation event is:

```python
logger.info(
    "Binary analysis finished",
    extra={
        "operation": "binary_analysis",
        "event_name": "analysis_finished",
        "duration_ms": duration_ms,
        "outcome": "success",
    },
)
```

Do not add a start event when the completion event and its duration answer the operational question; directory scans include one because mode, worker count, and discovered volume are useful before processing begins. Log expected fallback conditions at `WARNING`, failed operations at `ERROR`, and reserve `CRITICAL` for continuity failures. Do not log binary contents, subprocess output, credentials, request/response bodies, or unnecessary personal data. The library API does not configure the host application's logging policy; library hosts should call `configure_logging()` if they want this project's JSON/text format, redaction filters, and correlation fields on their handlers.

## Baseline score

The pre-change baseline was **3.0/10**, assessed from source before structured formatting, redaction, correlation, and operation-level duration events were added.

| Dimension | Baseline | Final | Evidence |
|---|---:|---:|---|
| Architecture and decoupling | 5 | 10 | Standard `logging` API, module loggers, replaceable handlers, preserved host root configuration, dependency-light shared context, and a parent listener for process workers. |
| Functional coverage | 6 | 10 | Startup/requirements, binary and directory analysis, worker outcomes, decompilation progress, R2/r2ai operations, file detection, report writes, findings, and shutdown/error boundaries have purposeful events. No database, inbound HTTP, queue, or scheduled-service flows exist in this CLI/library. |
| Event quality | 3 | 10 | Stable event names and operation/outcome/duration/count/error metadata are used at meaningful boundaries; findings are emitted once, duplicate layer errors are suppressed, and noisy per-file/path diagnostics were removed. |
| Structure and consistency | 1 | 10 | JSON uses UTC timestamps and normalized core fields; custom event fields have an explicit allowlist, stable names, bounded/sanitized values, and tests. Text output carries component and active context. |
| Context and correlation | 0 | 10 | Separate `ContextVar`s scope request and operation IDs, restore nested contexts, and propagate through default and injected thread/process worker paths. The local application has no cross-service trace path needing W3C spans. |
| Security and privacy | 2 | 10 | Sensitive-key redaction, URL and cookie filtering, control escaping, bounded fields, exception minimization, path minimization, private POSIX log files, and source-level avoidance of sensitive values are covered by regression tests. The pattern redactor is explicitly defense in depth, not a substitute for safe event construction. |
| Performance and resilience | 4 | 10 | Worker queue is bounded/non-blocking with visible low-severity drops and emergency stderr for high severity; shutdown drains it, files rotate safely across processes, writes cap size, and destination setup falls back to stderr. Synchronous stream output is appropriate for the finite CLI lifecycle. |
| Configuration and portability | 2 | 10 | Environment config selects standard levels, text/JSON, environment label, and stderr/stdout/rotating-file destination; host handlers are retained, invalid options degrade safely, and Windows/macOS/Linux CI passes. |
| Error handling | 4 | 10 | Expected failures are logged at owning boundaries with stable categories/phases/codes; unexpected failures retain safe frame locations; duplicate logging is avoided and logging failures do not escape into analysis. |
| Testing and verification | 3 | 10 | The latest local suite passes 1,307 tests at 100% line coverage; Ruff, mypy, and Bandit pass. All eight enabled GitHub Actions jobs pass, including cross-platform behavior, process rotation, sink failures, redaction, concurrency, and context propagation. |

The final score is **10.0/10**, the arithmetic mean of the ten applicable dimension ratings above. This rates fitness for the actual CLI/library profile; it does not assert that regex redaction can recognize every possible secret or that local logs are a durable audit ledger. Those limits are documented and mitigated through safe event construction, bounded retention, visible queue drops, and caller-owned external collection when required.

## Scope limits

No always-on metrics endpoint, distributed tracing backend, remote collector, or audit-grade durable sink is included: the project is an offline-capable CLI/library without independently deployed services, and these would add infrastructure without an existing operational consumer. For unusually high-volume or durable centralized collection, deployments should attach a collector and validate its retention/backpressure requirements. The current bounded queue explicitly reports low-severity loss; regex redaction remains defense in depth; console output is synchronous for the finite CLI lifecycle.

## Verification evidence

The source tree has a 100% line-coverage gate in `pyproject.toml`. On commit `7d4ed89`, the macOS/Python 3.15 suite passed with **1,307 tests and 100% line coverage**; Ruff, mypy, and Bandit passed. The full GitHub Actions matrix passed on run `43505260024`: eight enabled jobs across Ubuntu, macOS, and Windows with Python 3.13, 3.14, and 3.15 passed. Windows/Python 3.14 is excluded in the workflow due to the documented upstream pytest assertion-rewrite access violation. The real-process stress test wrote 720 structured events from four workers across size rotation and verified all remained parseable and present. Regression tests cover secret/path/error minimization, JSON schema, control escaping, context propagation/nesting, concurrency, rotation, sink failures, worker delivery, and CLI/library outcomes. Package build, `pip check`, and `pip-audit -r requirements.txt` passed earlier in this work; the dependency audit reported no known vulnerabilities. `actionlint` passed for the CI concurrency update; the build reported existing setuptools license-metadata deprecations.
