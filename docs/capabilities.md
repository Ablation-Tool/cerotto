# Capability Reference

CEROTTO connects agent activity, host telemetry, and disk evidence for authorized incident investigations. This reference describes tested behavior and operational boundaries. Numbered implementation links remain in the [README capability tables](../README.md#capabilities).

Tests use generated evidence and a local mock LLM unless a section explicitly names an external tool. CEROTTO does not establish intent or causation from timing alone.

## Agent & Host Evidence Collection

### Agent Event Ingestion

Imports conversations, prompts, tool calls, processes, file events, and network events from validated JSONL records. These records connect user requests and agent actions to the host activity that CEROTTO correlates later.

Validation and transactional ingestion reject malformed or duplicate records instead of committing a partial batch. Implementation: [`src/event.c`](../src/event.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Linux Audit Attribution

Correlates interleaved Linux audit records into process execution, file activity, and network connections. PID and PPID relationships attribute events to processes and parents even when records from multiple tasks arrive together.

Attribution depends on audit collection being configured before the incident. Missing telemetry limits reconstruction. Implementation: [`src/audit.c`](../src/audit.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Raw Disk Timelines

Uses The Sleuth Kit to collect allocated and deleted filesystem records for timeline analysis. Collection reads the image without mounting it or modifying the source evidence.

Preserve the original evidence separately and work from verified copies. Implementation: [`src/collector_tsk.c`](../src/collector_tsk.c) and [`src/collect.c`](../src/collect.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Verified EWF Collection

Requires `ewfverify` to succeed before CEROTTO processes an Expert Witness Format image. It preserves `ewfinfo`, hashes EWF segments, and uses The Sleuth Kit for E01 processing.

A failed verification stops the workflow before Sleuth Kit processing. EWF and real-image tools are optional prerequisites for this capability. Implementation: [`src/ewf.c`](../src/ewf.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Controlled File Carving

Runs Foremost or Scalpel against an authorized image, preserves tool logs, and catalogs recovered files with hashes and acquisition provenance.

CEROTTO rejects symlinks and non-regular output, limits recovery size, and treats recovered content as untrusted. Implementation: [`src/carve.c`](../src/carve.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

## Correlation & Artifact Handling

### Versioned Evidence Store

Stores cases, source records, and normalized events in SQLite. Schema migrations define the database format, and transactional writes protect ingestion from partial updates.

The store rejects unsupported newer schemas rather than interpreting them incorrectly. Case databases remain sensitive investigation material. Implementation: [`src/db.c`](../src/db.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Deterministic Timelines

Correlates conversation-linked events with same-host activity during a selected UTC time range. The range is half-open, which gives repeatable boundary behavior when timelines are regenerated.

Correlation supports investigation but does not prove that one event caused another. Implementation: [`src/timeline.c`](../src/timeline.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py) and [`tests/test_investigation.py`](../tests/test_investigation.py).

### Case Manifests

Exports evidence paths, hashes, sizes, commands, tool versions, acquisition times, and collection status. A manifest records how evidence entered the case and which operations produced preserved artifacts.

Manifest metadata supports repeatable review. It is not independent proof that the original evidence is authentic. Implementation: [`src/manifest.c`](../src/manifest.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Evidence Verification

Recomputes source and preserved-output hashes and compares them with manifest records. Missing or modified artifacts are reported so reviewers can stop and reassess the evidence chain.

Verification detects change relative to the recorded hash. It does not establish who created an artifact or whether its contents are safe. Implementation: [`src/manifest.c`](../src/manifest.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Hash-Verified Artifact Inspection

Revalidates a recovered file's hash before bounded hex or base64 inspection. The hash check connects the inspected bytes to the cataloged artifact.

Inspection never executes recovered content. Byte limits and format controls reduce exposure to hostile or oversized output. Implementation: [`src/artifact.c`](../src/artifact.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

## Analysis & Reporting

### Bounded LLM Analysis

Sends at most 500 metadata-only events to an OpenAI-compatible endpoint. Request timeouts and response limits constrain optional analysis work.

This capability is opt-in. It does not give the model a shell, host credentials, forensic tools, database writes, or an execution path. Use a local mock endpoint for development. Implementation: [`src/analyze.c`](../src/analyze.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py) and [`tests/test_llm_transport.py`](../tests/test_llm_transport.py).

### Citation Validation

Requires structured observations and hypotheses from the model. It rejects invented event references and mismatched evidence counts before those claims can enter a report.

Validation checks reference structure, not whether a conclusion is correct. Human review remains necessary. Implementation: [`src/analyze.c`](../src/analyze.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py) and [`tests/test_investigation.py`](../tests/test_investigation.py).

### Portable Investigation Reports

Produces JSON or escaped Markdown reports that separate observations, hypotheses, limitations, and human review. This structure helps readers distinguish evidence from interpretation.

Reports can include sensitive investigation data and must be protected accordingly. Implementation: [`src/report.c`](../src/report.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Human Review Attestations

Records reviewer identity and decision with a report. The attestation makes human approval visible during later review.

An attestation is a recorded statement, not a cryptographic signature or proof of reviewer identity. Implementation: [`src/report.c`](../src/report.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

## Security & Evidence Integrity

### No Model-to-Host Execution

The LLM receives no shell, host credentials, forensic tools, database writes, or execution path. Analysis code prepares bounded input and handles model output as untrusted data.

This boundary prevents model text from directly becoming a host action. It does not replace human review of reports. Implementation: [`src/analyze.c`](../src/analyze.c). Tests: [`tests/test_llm_transport.py`](../tests/test_llm_transport.py).

### No-Shell Subprocesses

Executes forensic tools with fixed argument arrays rather than shell command strings. CEROTTO bounds captured output and checks exit status before continuing.

These controls reduce command-injection risk and prevent failed tools from being treated as successful. Implementation: [`src/process.c`](../src/process.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Evidence Hashing

Computes SHA-256 for source images, preserved output, EWF segments, and recovered artifacts. Manifest and verification workflows use these hashes to detect missing or changed bytes.

A matching hash supports integrity comparison. It does not establish provenance or safety by itself. Implementation: [`src/util.c`](../src/util.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Transactional Ingestion

Rolls back malformed or duplicate event batches instead of committing partial evidence sets. Database transactions keep related source and event records consistent.

A rejected batch requires correction or review before ingestion can continue. Implementation: [`src/event.c`](../src/event.c), [`src/audit.c`](../src/audit.c), and [`src/carve.c`](../src/carve.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Hostile-Artifact Boundaries

Rejects symlinks and non-regular output, caps recovered bytes, and keeps recovered content out of automatic LLM requests. Artifact inspection also requires a fresh hash check.

Treat all recovered files as untrusted even after these checks. Implementation: [`src/carve.c`](../src/carve.c) and [`src/artifact.c`](../src/artifact.c). Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py).

### Regression & Sanitizer CI

Runs normal and AddressSanitizer/UndefinedBehaviorSanitizer builds with generated evidence, subprocess pairs, and a local mock LLM. Tests cover ingestion, rollback, evidence integrity, transport failures, and report boundaries.

Real EWF tests skip when EWF tools are unavailable. CI and local test results must be reported separately from untested external-tool behavior. Tests: [`tests/test_cerotto.py`](../tests/test_cerotto.py). Workflow: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
