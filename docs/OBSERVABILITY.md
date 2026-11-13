# Logging and observability audit

## Application profile

BannedFuncDetector is a Python CLI and importable library. The main flow parses arguments, validates the local radare2 toolchain, creates application wiring, analyzes one binary or scans a directory, writes JSON/text/HTML analysis reports, and returns a result to the CLI or library caller. Directory scans may use `ProcessPoolExecutor`; individual binary analysis may query the local r2ai/Ollama HTTP services. The project has no database, authenticated web API, durable queue, scheduled jobs, or always-on service lifecycle, so database, request-authentication, and service-health metrics do not apply.

## Current design

- Components use the standard-library `logging` API and module-named loggers.
- CLI setup is in `bannedfuncdetector.cli_bootstrap.configure_logging`; text is the default and JSON can be selected with `BFD_LOG_FORMAT=json`. `BFD_LOG_LEVEL` selects a standard Python level, and invalid names fall back to `INFO`.
- `BFD_LOG_DESTINATION` selects `stderr` (default), `stdout`, or `file:<path>`. File output uses `RotatingFileHandler` with a 10 MiB limit and five backups. If the host already configured root handlers, they are retained and take precedence; request-context and sanitizing filters are added without replacing their destinations or formatters. No remote collector or vendor SDK is required.
- JSON records include UTC `timestamp`, `level`, `service`, `component`, and `message`. Analysis completion adds `operation`, `event_name`, `duration_ms`, and `outcome`. Exception records include a sanitized `stack_trace`. Text records include UTC timestamp, level, component, and `request_id` when one exists.
- A generated `request_id` scopes each CLI run and each public library call; it is explicitly included in directory worker payloads and restored after nested calls. The default process executor forwards records through a parent listener. Injected thread/process executors also propagate the ID, while custom process log delivery uses the destination configured in each worker. The ID is not a W3C trace ID. The project does not make distributed calls between independently deployed services, so distributed spans and metrics are not configured.
- Credential-like fields, URL userinfo/path/query, and Unicode control/line separators are redacted or escaped. Messages and stack traces are capped at 16,384 characters. Message/exception formatting failures fall back to safe placeholders rather than escaping into application code. Requirement-check failures record command result metadata rather than subprocess output.

## Event levels

- `DEBUG`: details needed for local diagnosis, including optional backend and file-detection fallbacks.
- `INFO`: requirement checks, analysis completion, and other meaningful transitions.
- `WARNING`: recoverable limitations, unavailable optional tools, and operational notices.
- `ERROR`: failed operations and captured exceptions.
- `CRITICAL`: reserved for process-continuity failures; no current flow has a justified use for it.
- Python logging has no built-in `TRACE` level; the project does not add a custom level.

## Security and limits

Redaction is defense in depth and uses patterns, not a complete data-loss-prevention engine. URL logs are reduced to scheme and authority, dropping userinfo, path, and query. New log calls must avoid credentials, cookies, binary contents, full HTTP bodies, and confidential data at their source. Do not log arbitrary request/response bodies or subprocess output. Control characters are escaped to reduce log forging. JSON encoding keeps event values on one physical line.

The default stream handler is synchronous in the parent process. The default directory `ProcessPoolExecutor` path forwards worker records through a bounded 10,000-record queue to one parent `QueueListener`, preventing worker writes from interleaving. The standard `QueueHandler` is non-blocking; a saturated queue may drop records. Injected custom executors retain their own logging behavior. There is no sampling or rate limiting. Deployments that need durable, centralized, or high-volume collection should provide a process-level logging collector and validate worker output under their operating system.

## Baseline score

The pre-change baseline was **3.0/10**, assessed from source before structured formatting, redaction, correlation, and operation-level duration events were added.

| Dimension | Baseline | Current provisional | Current evidence / remaining gap |
|---|---:|---:|---|
| Architecture and decoupling | 5 | 9 | Standard `logging`, serialized configuration, and parent queue listener; no pluggable backend protocol. |
| Functional coverage | 6 | 8 | Binary/directory outcomes include duration; some lower-level events still lack operation fields. |
| Event quality | 3 | 8 | Exceptions and outcomes carry useful context and error type; legacy messages remain unstructured. |
| Structure and consistency | 1 | 9 | JSON UTC schema and normalized text fields; most legacy event-specific data still remains in `message`. |
| Context and correlation | 0 | 9 | CLI and library IDs cross worker payloads; custom executors must supply their own transport. |
| Security and privacy | 2 | 9 | Credential/cookie/URL pattern redaction and Unicode line-separator escaping apply to configured handlers; arbitrary sensitive values remain undetectable. |
| Performance and resilience | 4 | 8 | Bounded worker queue, draining shutdown, size caps, and rotation; custom multi-process file output is not serialized. |
| Configuration and portability | 2 | 9 | Environment selects level, format, environment, and stream/file destination; existing host handlers remain respected. |
| Error handling | 4 | 9 | Duplicate directory errors are suppressed; handled directory exceptions retain type and stack trace, while legacy paths still vary. |
| Testing and verification | 3 | 9 | 100% line coverage plus real process and sink-failure tests; cross-platform CI results remain unverified. |

The current **provisional score is 8.7/10**, the arithmetic mean of the ten current dimension ratings. It is not the final score.

## Remaining work

This is an interim implementation, not a 10/10 claim. Remaining work includes reviewing all legacy log events and exception paths, stress-testing concurrent output and file rotation from custom process executors, confirming deployment retention needs, and getting CI results on each supported OS. The standard rotating file handler is not process-safe when multiple custom workers write to the same file. Regex redaction remains heuristic; the bounded default queue intentionally drops records under pressure to keep analysis non-blocking.

## Verification evidence

The source tree has a 100% line-coverage gate in `pyproject.toml`. At revision `e72e7b0`, the full suite passed with 100% line coverage on macOS under Python 3.13, 3.14, and 3.15; Ruff, mypy, Bandit, and package build passed. Logging tests cover JSON and text fields, secret redaction, ASCII and Unicode injection, bounded events, unsafe message/exception formatters, request IDs for built-in and injected process/thread executors, duplicate-error suppression, operation completion, concurrent configuration, saturated queues, failed destinations, and file rotation. GitHub Actions has not completed for the latest pushes; its Ubuntu/macOS/Windows matrix is still queued, so Linux and Windows validation remains outstanding.
