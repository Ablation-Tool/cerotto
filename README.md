# CEROTTO

By strictly separating LLM-assisted analysis from deterministic evidence collection and execution, CEROTTO avoids granting the model direct host access. 

This reduces the risk of model-initiated destructive actions and constrains unsupported conclusions through evidence-linked citations, though human verification remains necessary.



CEROTTO is a C11/POSIX evidence pipeline for investigating security incidents involving LLM agents. It correlates structured agent events with preserved host forensic evidence, then lets an LLM explain a bounded timeline with mandatory event-ID citations.

Deterministic tools collect and correlate evidence separately from the analytical layer. The model receives a bounded, metadata-only timeline and has no host credentials, shell, or tool-execution path; its output is never executed. Mandatory citations constrain unsupported event references, but they do not guarantee correct interpretation. Model output is investigative assistance, not a forensic finding, and material claims still require verification.

## Status

Version 0.1.0 implements JSONL ingestion, Sleuth Kit `fls` collection, SQLite correlation, and OpenAI-compatible analysis. It does **not** yet implement live host monitoring, VM snapshots, AFF/EWF acquisition, carving, Chkrootkit, Volatility, or autonomous tool calling. A filesystem timestamp alone does not prove which process caused an event.

## Build

Requirements: a C11 compiler, Make, POSIX, `fls`, and `curl`. SQLite and cJSON are pinned in `vendor/`; no development packages or root installation are needed.

```sh
make
make sanitize
```

The executable is `build/cerotto` (or `build/sanitize/cerotto`).

## Event input

`ingest` accepts one JSON object per line. Required fields are `id`, `observed_at`, `host_id`, `source_tool`, and `event_type`. Optional fields are `conversation_id`, `prompt_id`, `tool_call_id`, `process_id`, `path`, `deleted`, and `details` (an object). Timestamps must be UTC with at most six fractional-second digits. Records are inserted transactionally.

```json
{"id":"evt-001","observed_at":"2026-10-27T12:00:00Z","host_id":"agent-vm-1","source_tool":"agent_gateway","event_type":"tool_call","conversation_id":"conv-7","prompt_id":"prompt-9","tool_call_id":"call-3","process_id":420,"path":"/tmp/job.sh"}
```

## Workflow

```sh
CEROTTO=build/cerotto

$CEROTTO init --db case.db
$CEROTTO ingest --db case.db --case incident-7 --input agent-events.jsonl

mkdir -p collected/incident-7
$CEROTTO collect-tsk --db case.db --case incident-7 \
  --image agent-disk.img --output collected/incident-7 --host agent-vm-1

$CEROTTO timeline --db case.db --case incident-7 --conversation conv-7 \
  --from 2026-10-27T11:59:00Z --to 2026-10-27T12:05:00Z
```

`collect-tsk` requires a regular image file and an existing output directory. It never mounts the image. It runs separate allocated and deleted-file `fls` passes, preserves their combined body records in `fls.body`, and records both exact commands, the image hash, raw-output hash, tool version, acquisition time, and event provenance. Deleted paths are normalized without TSK's ` (deleted)` suffix. Each output directory represents one collection; existing evidence is not overwritten.

Timeline queries include events directly linked to the conversation plus events from hosts associated with that conversation. Time ranges are half-open (`from` inclusive, `to` exclusive). `--host` narrows correlated host activity. Details are omitted unless `--include-details` is supplied.

## LLM analysis

Configure an OpenAI-compatible endpoint:

```sh
export CEROTTO_BASE_URL=https://provider.example/v1
export CEROTTO_MODEL=model-name
export CEROTTO_API_KEY=key-if-required

$CEROTTO analyze --db case.db --case incident-7 --conversation conv-7
```

The client appends `/chat/completions` to the base URL. Analysis is limited to 500 events and excludes free-form event details. Paths and identifiers remain untrusted evidence and may contain hostile text. The response must follow the requested JSON schema and cite only supplied event IDs; invented citations are rejected. Requests have connection and total timeouts, responses are size-limited, and API keys are passed to `curl` through standard input rather than process arguments. Temporary request payloads are created with owner-only permissions and removed after use.

Use a local mock endpoint for development rather than sending sensitive evidence to an external provider. Treat reports as investigative assistance and verify every material statement against the underlying evidence.

## Trust and handling

Run collectors with the least privilege available in an isolated analysis environment. Preserve original evidence separately, work from verified copies, use synchronized UTC clocks, and do not ingest untrusted collector output into a privileged shell. The database and generated reports can contain sensitive investigation metadata and should be protected accordingly.

Vendored dependency versions, source URLs, hashes, and licenses are documented in `vendor/README.md`.
