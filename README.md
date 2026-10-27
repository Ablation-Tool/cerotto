# CEROTTO

**CEROTTO helps investigators trace what an AI agent did on a computer.**

It connects agent activity—such as conversations, tool calls, and process IDs—with host evidence such as audit events and filesystem timelines. A C11/POSIX core collects and correlates the evidence; an optional LLM explains a bounded timeline with mandatory event-ID citations.

Deterministic tools remain separate from the analytical layer. The model has no host credentials, shell, or tool-execution path, and its output is never executed. Citations constrain unsupported event references, but do not guarantee correct interpretation. Reports are investigative assistance, not forensic findings or proof of causation.

## Status

Version 0.2.0 implements:

- Transactional agent-event JSONL ingestion.
- Linux audit-log ingestion with process/parent-PID, file, and network attribution.
- Sleuth Kit allocated and deleted-file collection with preserved provenance.
- SQLite conversation, host, process, and time-window correlation.
- Metadata-only OpenAI-compatible analysis with response-schema and citation validation.
- A versioned schema with v1-to-v2 migration, integration tests, and sanitizer-capable builds.

CEROTTO does **not** configure auditd, provide live containment, or give the model host access. VM snapshots, AFF/EWF acquisition, carving, Chkrootkit, Volatility, natural-language queries, fleet-wide analysis, and incident similarity graphs remain future work.

## Build and test

Requirements: a C11 compiler, Make, Python 3, POSIX, `fls`, and `curl`. The real-image tests also use `mke2fs` and `debugfs`. SQLite and cJSON are pinned in `vendor/`; no C development packages are needed.

```sh
make
make check
make sanitize
make check BUILD_DIR=build/sanitize
```

The executable is `build/cerotto` (or `build/sanitize/cerotto`). Tests exercise the actual CLI with generated evidence and a local mock LLM; they do not contact an external provider. GitHub Actions runs both normal and AddressSanitizer/UndefinedBehaviorSanitizer suites.

## Agent event input

`ingest` accepts one JSON object per line. Required fields are `id`, `observed_at`, `host_id`, `source_tool`, and `event_type`. Optional fields are `conversation_id`, `prompt_id`, `tool_call_id`, `process_id`, `parent_process_id`, `path`, `deleted`, and `details` (an object). Timestamps must be UTC with at most six fractional-second digits.

```json
{"id":"evt-001","observed_at":"2026-10-27T12:00:00Z","host_id":"agent-vm-1","source_tool":"agent_gateway","event_type":"tool_call","conversation_id":"conv-7","prompt_id":"prompt-9","tool_call_id":"call-3","process_id":420,"parent_process_id":100,"path":"/tmp/job.sh"}
```

## Audit-log attribution

`ingest-audit` parses captured Linux audit logs and correlates records sharing an audit event ID, including interleaved records. It supports:

- `SYSCALL` + `EXECVE` for execve/execveat process events and arguments.
- `SYSCALL` + `PATH` for supported open/create/unlink file activity.
- `SYSCALL` + `SOCKADDR` for supported connect events.
- Quoted and audit hex-encoded strings, `node=` host selection, and microsecond-normalized timestamps.

Failed operations are recorded as attempts rather than successful actions. Audit events do not receive conversation or tool-call IDs unless a future trusted mapping supplies them; CEROTTO correlates them by host, process, and time instead. Coverage currently targets common x86-64, x86, and AArch64 syscall numbers, not every Linux ABI or audit record type.

An administrator must choose and configure audit rules appropriate for the host. For example, a controlled investigation might use rules such as:

```text
-a always,exit -F arch=b64 -S execve -S execveat -k cerotto_exec
-a always,exit -F arch=b64 -S connect -k cerotto_network
-w /path/to/sensitive-data -p rwa -k cerotto_sensitive
-w /opt/agent/tmp -p wa -k cerotto_files
```

These are examples, not automatically installed policy. Broad process, file, and network auditing can create substantial log volume and overhead. Test rules in a disposable environment, protect audit logs, and preserve their original timestamps and host identity.

## Workflow

```sh
CEROTTO=build/cerotto

$CEROTTO init --db case.db
$CEROTTO ingest --db case.db --case incident-7 --input agent-events.jsonl
$CEROTTO ingest-audit --db case.db --case incident-7 \
  --input audit.log --host agent-vm-1

mkdir -p collected/incident-7
$CEROTTO collect-tsk --db case.db --case incident-7 \
  --image agent-disk.img --output collected/incident-7 --host agent-vm-1

$CEROTTO timeline --db case.db --case incident-7 --conversation conv-7 \
  --from 2026-10-27T11:59:00Z --to 2026-10-27T12:05:00Z
```

Both ingestion paths record input hashes, source metadata, acquisition time, and completed/failed status. Records are inserted transactionally; malformed input or duplicate stable event IDs roll back the import.

`collect-tsk` requires a regular image file and an existing output directory. It never mounts the image. Separate allocated and deleted-file `fls` passes are preserved in `fls.body`, together with both exact commands, image/raw-output hashes, tool version, acquisition time, and event provenance. Existing evidence is not overwritten.

Timeline queries include events directly linked to the conversation plus events from hosts associated with that conversation. Time ranges are half-open (`from` inclusive, `to` exclusive). `--host` narrows correlated host activity. Details are omitted unless `--include-details` is supplied. Parent PIDs expose process ancestry, but timeline timing alone still does not prove causation.

## LLM analysis

Configure an OpenAI-compatible endpoint:

```sh
export CEROTTO_BASE_URL=https://provider.example/v1
export CEROTTO_MODEL=model-name
export CEROTTO_API_KEY=key-if-required

$CEROTTO analyze --db case.db --case incident-7 --conversation conv-7
```

The client appends `/chat/completions` to the base URL. Deterministic SQL—not the model—selects the evidence. Analysis is limited to 500 events and excludes free-form event details. Paths and identifiers remain untrusted and may contain hostile text.

Responses must follow the requested JSON schema and cite only supplied event IDs; invented citations are rejected. Requests have connection and total timeouts, responses are size-limited, and API keys are passed to `curl` through standard input rather than process arguments. Temporary request payloads are owner-only and removed after use.

Use a local mock endpoint for development rather than sending sensitive evidence to an external provider. Review material claims against the underlying evidence, and apply your organization's confidentiality and data-governance requirements before using an external model.

## Trust and handling

Run collectors with the least privilege available in an isolated analysis environment. Preserve original evidence separately, work from verified copies, use synchronized UTC clocks, and do not ingest untrusted collector output into a privileged shell. The database and generated reports can contain sensitive investigation metadata and should be protected accordingly.

Vendored dependency versions, source URLs, hashes, and licenses are documented in `vendor/README.md`.
