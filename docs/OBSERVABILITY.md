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
- Credential-like fields (including quoted values with spaces), whole `Cookie`/`Set-Cookie` headers, URL userinfo/path/query, and Unicode control/line separators are redacted or escaped. The sanitization is idempotent across the handler filter and formatter. Home-directory prefixes in configured log messages are shortened to `~`; text fields in JSON `request_id`, `operation`, `event_name`, `outcome`, `error_type`, `error_code`, `error_line`, `error_column`, `error_category`, `error_phase`, and `dropped_count` values pass through the same sanitizer. Configuration parse/read failures log only the exception type, OS code, parser line/column, and config basename; raw exception text and traceback are omitted to prevent config-content disclosure. The optional `r2ai-server` integration omits endpoint URLs, command paths, remote model names, and exception text from its events; it records outcomes, counts, durations, and exception types instead. R2 command diagnostics omit the raw command and exception text. Binary setup/extraction, directory validation/discovery and result collection, bulk xref fallback, decompiler availability and command fallbacks, R2 connection lifecycle and retries, file detection, report opening, and output-directory creation events likewise avoid exception messages and unnecessary paths while retaining exception type and numeric OS error code where available. Requirement command timeouts and blocked-command events omit argv and process output. Messages and stack traces are capped at 16,384 characters. Stack traces contain only file, line, and frame names, excluding source lines and exception messages. Message/exception formatting failures fall back to safe placeholders rather than escaping into application code. Requirement-check failures record command result metadata rather than subprocess output.

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

Do not add a start event when the completion event and its duration answer the operational question. Log expected fallback conditions at `WARNING`, failed operations at `ERROR`, and reserve `CRITICAL` for continuity failures. Do not log binary contents, subprocess output, credentials, request/response bodies, or unnecessary personal data. The library API does not configure the host application's logging policy; library hosts should call `configure_logging()` if they want this project's JSON/text format, redaction filters, and correlation fields on their handlers.

## Baseline score

The pre-change baseline was **3.0/10**, assessed from source before structured formatting, redaction, correlation, and operation-level duration events were added.

| Dimension | Baseline | Current provisional | Current evidence / remaining gap |
|---|---:|---:|---|
| Architecture and decoupling | 5 | 10 | Standard `logging` handlers provide backend substitution; host root handlers are retained, and the process listener decouples worker logging from analysis code. |
| Functional coverage | 6 | 9.5 | Binary/directory boundaries add operation context to nested events; report writes, directory summary writes, and optional-service pings/model fetches carry duration. A few startup and availability events remain outside a use-case operation. |
| Event quality | 3 | 9.5 | Major success, empty, fallback, and failure outcomes carry useful operation metadata, including process exit codes without output; function decompilation errors are emitted once per rate-limit interval. Some legacy messages remain uneven. |
| Structure and consistency | 1 | 9.5 | JSON UTC schema and normalized error fields include analysis category/phase for binary and directory paths; other legacy event-specific data still remains in `message`. |
| Context and correlation | 0 | 9.5 | Request and operation contexts use separate `ContextVar`s, restore across nesting, and cross the default and injected worker wrappers; no distributed trace is needed for this local CLI flow. |
| Security and privacy | 2 | 9.5 | Credential/cookie/URL pattern redaction covers assignment syntax, quoted JSON keys (including authorization and cookie properties), and common `--secret value` flags; sanitization remains idempotent across handlers and Unicode line-separator escaping applies to configured handlers. Artifact persistence events omit paths and R2 command logs omit untrusted command text, while arbitrary sensitive values remain undetectable. |
| Performance and resilience | 4 | 9.5 | Bounded non-blocking worker queue, draining shutdown, size caps, process-safe rotation, explicit low-severity drop counts, and stderr fallback for error events; stream output remains synchronous. |
| Configuration and portability | 2 | 9 | Environment selects level, format, environment, and stream/file destination; existing host handlers remain respected. |
| Error handling | 4 | 9.5 | Duplicate directory errors are suppressed; binary and directory failures carry structured category, phase, and OS error code when available, while captured exceptions retain type and stack trace. Legacy paths still vary. |
| Testing and verification | 3 | 9.5 | 100% line coverage on the canonical Linux/Python 3.13–3.15 runs, complete CI matrix success across all eight supported OS/Python combinations, and real process and sink-failure tests. |

The current **provisional score is 9.5/10**, the arithmetic mean of the ten current dimension ratings. It is not the final score.

## Remaining work

This is an interim implementation, not a 10/10 claim. Remaining work includes completing a semantic review of legacy log events and exception paths and checking deployment-specific retention needs. Regex redaction remains heuristic; a saturated bounded queue can drop low-severity events, with the loss reported and high-severity events diverted to stderr. Redaction must not replace safe logging at the source.

## Verification evidence

The source tree has a 100% line-coverage gate in `pyproject.toml`. At revision `e72e7b0`, the full suite passed with 100% line coverage on macOS under Python 3.13, 3.14, and 3.15. At `0f0e8e8`, the full suite passed with 100% line coverage on Python 3.15; Ruff, mypy, and Bandit passed on the same source. The full suite without coverage passed on Python 3.13 and 3.14 at `a1690c9`; focused logging/output/r2ai tests passed on both at `85eeac0`, and binary/directory structured error tests passed on both at `02b41cf`. The decompilation boundary tests passed on Python 3.13 and 3.14 at `0f0e8e8`. On macOS/Python 3.15, the latest full suite passed with **1,288 tests and 100% line coverage**; Ruff, Bandit, and mypy for all 83 source files passed (mypy suppressing only the missing third-party `requests` stubs warning). The real-process stress test wrote 720 structured events from four workers across a size rotation and verified every event remained parseable and present. Integration tests verify endpoint credentials, URL paths/query, remote model strings, exception text, structured fields, home-directory redaction, quoted secrets, JSON credential/authorization/cookie values, CLI-flag secrets, cookie headers, operation-context nesting/override, config-exception-content minimization, requirement/runtime-failure events, and POSIX file modes do not leak. Package build, `pip check`, and `pip-audit -r requirements.txt` passed at `a1690c9`; the build reports existing setuptools license-metadata deprecations, and the dependency audit reported no known vulnerabilities. `actionlint` passed for the CI concurrency update in `dad8210`. The complete GitHub Actions matrix passed on commit `e050818` (run `43477464808`): all 8 enabled jobs across Ubuntu, macOS, and Windows with Python 3.13, 3.14, and 3.15 passed lint, type check, dependency audit, and platform-appropriate test suites. Windows/Python 3.14 remains excluded in the workflow due to the documented upstream pytest assertion-rewrite access violation. Changes after `e050818` are locally validated and await the next remote matrix.
