# Logging and observability audit

## Application profile

BannedFuncDetector is a Python CLI and importable library. The main flow parses arguments, validates the local radare2 toolchain, creates application wiring, analyzes one binary or scans a directory, writes JSON/text/HTML analysis reports, and returns a result to the CLI or library caller. Directory scans may use `ProcessPoolExecutor`; individual binary analysis may query the local r2ai/Ollama HTTP services. The project has no database, authenticated web API, durable queue, scheduled jobs, or always-on service lifecycle, so database, request-authentication, and service-health metrics do not apply.

## Current design

- Components use the standard-library `logging` API and module-named loggers.
- CLI setup is in `bannedfuncdetector.cli_bootstrap.configure_logging`; text is the default and JSON can be selected with `BFD_LOG_FORMAT=json`. `BFD_LOG_LEVEL` selects a standard Python level, and invalid names fall back to `INFO`.
- Logs go to stderr. The application does not configure local log files, rotation, remote collectors, or a vendor SDK; deployments can collect stderr using their process supervisor.
- JSON records include UTC `timestamp`, `level`, `service`, `component`, and `message`. Analysis completion adds `operation`, `event_name`, `duration_ms`, and `outcome`. Exception records include a sanitized `stack_trace`.
- A generated `request_id` scopes a CLI run and is explicitly included in directory worker payloads. It is not a W3C trace ID. The project does not make distributed calls between independently deployed services, so distributed spans and metrics are not configured.
- Credential-like fields and control characters are redacted/escaped by the configured formatter. Requirement-check failures record command result metadata rather than subprocess output.

## Event levels

- `DEBUG`: details needed for local diagnosis, including optional backend and file-detection fallbacks.
- `INFO`: requirement checks, analysis completion, and other meaningful transitions.
- `WARNING`: recoverable limitations, unavailable optional tools, and operational notices.
- `ERROR`: failed operations and captured exceptions.
- `CRITICAL`: reserved for process-continuity failures; no current flow has a justified use for it.
- Python logging has no built-in `TRACE` level; the project does not add a custom level.

## Security and limits

Redaction is defense in depth and uses patterns, not a complete data-loss-prevention engine. New log calls must avoid credentials, cookies, binary contents, full HTTP bodies, and confidential data at their source. Do not log arbitrary request/response bodies or subprocess output. Control characters are escaped to reduce log forging. JSON encoding keeps event values on one physical line.

The default stream handler is synchronous. It is suitable for this local CLI and does not add a service dependency, but there is no queue-based backpressure, sampling, rate limiting, or cross-process aggregation. Workers inherit stderr and may write concurrently. Deployments that need durable, centralized, or high-volume collection should provide a process-level logging collector and validate worker output under their operating system.

## Baseline score

The pre-change baseline was **3.0/10**, assessed from source before structured formatting, redaction, correlation, and operation-level duration events were added.

| Dimension | Baseline | Evidence at baseline |
|---|---:|---|
| Architecture and decoupling | 5 | Standard `logging`, but only `cli_bootstrap.py` configured the root logger. |
| Functional coverage | 6 | Logs existed across analysis, configuration, adapters, and reporting; operation outcomes were not consistently measurable. |
| Event quality | 3 | Many f-string messages and plain-text errors; useful context varied by module. |
| Structure and consistency | 1 | No normalized JSON event schema. |
| Context and correlation | 0 | No operation or worker correlation ID. |
| Security and privacy | 2 | No common formatter-level secret or control-character handling; dependency diagnostics included raw stdout/stderr. |
| Performance and resilience | 4 | Standard handlers were thread-safe, but output was synchronous and had no explicit volume controls. |
| Configuration and portability | 2 | CLI verbosity selected a level; format and level were not environment-configurable. |
| Error handling | 4 | Errors were often text-only, with inconsistent exception context and duplicate logging across layers. |
| Testing and verification | 3 | Existing tests checked verbosity, not the structured, privacy, and correlation contracts. |

## Remaining work

This is an interim implementation, not a 10/10 claim. The remaining review should measure duplicate errors across application and CLI boundaries; add coverage for context isolation under parallel execution and formatter behavior with preconfigured host handlers; inspect every logged exception and external integration for unnecessary data; and decide whether process-level collection is sufficient for supported deployment modes. The current regex redaction and synchronous multi-process stderr behavior are known limits.

## Verification evidence

The source tree has a 100% line-coverage gate in `pyproject.toml`. Logging tests cover JSON fields, redaction, control-character escaping, exception stack traces, request IDs, and operation completion. Full suite results should be recorded from the current revision before making any final score claim.
