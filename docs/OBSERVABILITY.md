# Logging and observability audit

## Application profile

BannedFuncDetector is a Python CLI and importable library. The main flow parses arguments, validates the local radare2 toolchain, creates application wiring, analyzes one binary or scans a directory, writes JSON/text/HTML analysis reports, and returns a result to the CLI or library caller. Directory scans may use `ProcessPoolExecutor`; individual binary analysis may query the local r2ai/Ollama HTTP services. The project has no database, authenticated web API, durable queue, scheduled jobs, or always-on service lifecycle, so database, request-authentication, and service-health metrics do not apply.

## Current design

- Components use the standard-library `logging` API and module-named loggers.
- CLI setup is in `bannedfuncdetector.cli_bootstrap.configure_logging`; text is the default and JSON can be selected with `BFD_LOG_FORMAT=json`. `BFD_LOG_LEVEL` selects a standard Python level, and invalid names fall back to `INFO`.
- Logs go to stderr. The application does not configure local log files, rotation, remote collectors, or a vendor SDK; deployments can collect stderr using their process supervisor.
- JSON records include UTC `timestamp`, `level`, `service`, `component`, and `message`. Analysis completion adds `operation`, `event_name`, `duration_ms`, and `outcome`. Exception records include a sanitized `stack_trace`.
- A generated `request_id` scopes each CLI run and each public library call; it is explicitly included in directory worker payloads and restored after nested calls. It is not a W3C trace ID. The project does not make distributed calls between independently deployed services, so distributed spans and metrics are not configured.
- Credential-like fields, URL userinfo/path/query, and control characters are redacted/escaped by the configured formatter. Requirement-check failures record command result metadata rather than subprocess output.

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
| Architecture and decoupling | 5 | 8 | Standard `logging`, CLI bootstrap, and parent queue listener; no pluggable backend protocol. |
| Functional coverage | 6 | 8 | Binary/directory outcomes include duration; some lower-level events still lack operation fields. |
| Event quality | 3 | 7 | Exceptions and outcomes carry useful context; many legacy f-string events remain. |
| Structure and consistency | 1 | 8 | JSON UTC schema and allowlisted event fields; most legacy message data remains in `message`. |
| Context and correlation | 0 | 9 | CLI and library IDs cross worker payloads; custom executors must supply their own transport. |
| Security and privacy | 2 | 7 | Credential/cookie pattern redaction and control escaping; regex cannot identify arbitrary sensitive values. |
| Performance and resilience | 4 | 8 | Bounded worker queue and draining shutdown; saturation drops logs and parent output is synchronous. |
| Configuration and portability | 2 | 7 | Environment-configurable level/format and stderr output; no file rotation or destination selection. |
| Error handling | 4 | 8 | CLI suppresses duplicate ERROR records already emitted by binary flow; other modules still vary in exception details. |
| Testing and verification | 3 | 10 | 100% line coverage plus real process log propagation tests; cross-platform CI results remain external evidence. |

The current **provisional score is 8.0/10**, the arithmetic mean of the ten current dimension ratings. It is not the final score.

## Remaining work

This is an interim implementation, not a 10/10 claim. Remaining work includes reviewing all legacy log events and exception paths, validating custom executor behavior and preconfigured host handlers, evaluating destination/retention needs for actual deployments, and confirming CI on each supported OS. Regex redaction remains heuristic; the bounded queue may drop records under pressure.

## Verification evidence

The source tree has a 100% line-coverage gate in `pyproject.toml`. At revision `3bd14b3`, the full suite passed with 1,257 tests and 100% line coverage; Ruff, mypy, Bandit, and package build passed. Logging tests cover JSON fields, redaction, control-character escaping, exception stack traces, request IDs, duplicate-error suppression, operation completion, and real process log forwarding. Re-run all checks after subsequent changes and inspect remote CI results before making a final score claim.
