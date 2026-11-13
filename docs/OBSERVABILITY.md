# Logging and observability audit

## Application profile

BannedFuncDetector is a Python CLI and importable library. The main flow parses arguments, validates the local radare2 toolchain, creates application wiring, analyzes one binary or scans a directory, writes JSON/text/HTML analysis reports, and returns a result to the CLI or library caller. Directory scans may use `ProcessPoolExecutor`; individual binary analysis may query the local r2ai/Ollama HTTP services. The project has no database, authenticated web API, durable queue, scheduled jobs, or always-on service lifecycle, so database, request-authentication, and service-health metrics do not apply.

## Current design

- Components use the standard-library `logging` API and module-named loggers.
- CLI setup is in `bannedfuncdetector.cli_bootstrap.configure_logging`; text is the default and JSON can be selected with `BFD_LOG_FORMAT=json`. `BFD_LOG_LEVEL` selects a standard Python level, and invalid names fall back to `INFO`.
- The default destination is stderr. Existing host handlers are retained; `configure_logging` adds request-context and sanitizing filters to them without replacing their destination or formatter. The application does not configure local log files, rotation, remote collectors, or a vendor SDK; deployments can collect stderr using their process supervisor.
- JSON records include UTC `timestamp`, `level`, `service`, `component`, and `message`. Analysis completion adds `operation`, `event_name`, `duration_ms`, and `outcome`. Exception records include a sanitized `stack_trace`.
- A generated `request_id` scopes each CLI run and each public library call; it is explicitly included in directory worker payloads and restored after nested calls. It is not a W3C trace ID. The project does not make distributed calls between independently deployed services, so distributed spans and metrics are not configured.
- Credential-like fields, URL userinfo/path/query, and Unicode control/line separators are redacted or escaped. Message/exception formatting failures fall back to safe placeholders rather than escaping into application code. Requirement-check failures record command result metadata rather than subprocess output.

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
| Structure and consistency | 1 | 8 | JSON UTC schema and allowlisted event fields; most legacy message data remains in `message`. |
| Context and correlation | 0 | 9 | CLI and library IDs cross worker payloads; custom executors must supply their own transport. |
| Security and privacy | 2 | 9 | Credential/cookie/URL pattern redaction and Unicode line-separator escaping apply to configured handlers; arbitrary sensitive values remain undetectable. |
| Performance and resilience | 4 | 9 | Bounded worker queue and draining shutdown; saturation drops records safely and parent output is synchronous. |
| Configuration and portability | 2 | 8 | Environment-configurable level/format applies to workers and parent; stderr remains the only built-in destination. |
| Error handling | 4 | 9 | Duplicate directory errors are suppressed; handled directory exceptions retain type and stack trace, while legacy paths still vary. |
| Testing and verification | 3 | 9 | 100% line coverage plus real process and sink-failure tests; cross-platform CI results remain unverified. |

The current **provisional score is 8.6/10**, the arithmetic mean of the ten current dimension ratings. It is not the final score.

## Remaining work

This is an interim implementation, not a 10/10 claim. Remaining work includes reviewing all legacy log events and exception paths, validating custom executor behavior, evaluating destination/retention needs for actual deployments, and confirming CI on each supported OS. Regex redaction remains heuristic; the bounded queue intentionally drops records under pressure to keep analysis non-blocking.

## Verification evidence

The source tree has a 100% line-coverage gate in `pyproject.toml`. At revision `f949196`, the full suite passed with 100% line coverage; Ruff, mypy, Bandit, and package build passed. Logging tests cover JSON fields, secret redaction, ASCII and Unicode injection, unsafe message/exception formatters, request IDs, duplicate-error suppression, operation completion, concurrent configuration, real process log forwarding, saturated queues, and failed stream destinations. GitHub Actions has not completed for the latest pushes; its 3.13–3.15 Ubuntu/macOS/Windows matrix is still queued, so cross-platform validation remains outstanding.
