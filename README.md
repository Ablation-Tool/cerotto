
CEROTTO investigates attacks involving autonomous AI agents and sandbox escapes.

It connects user requests, agent tool calls, operating-system activity, and disk evidence. Incident responders can reconstruct what happened and verify each conclusion against the underlying records.

CEROTTO helps incident responders, security engineers, and forensic analysts answer one question: **What did the agent do on the computer?**

---

## Capabilities

<details>
<summary><strong>Agent & Host Evidence Collection</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Agent Event Ingestion**](src/event.c) | [1](src/event.c) | Imports conversations, prompts, tool calls, processes, file events, and network events from validated JSONL records. |
| [**Linux Audit Attribution**](src/audit.c) | [1](src/audit.c) | Correlates interleaved audit records into process execution, file activity, and network connections with PID/PPID attribution. |
| [**Raw Disk Timelines**](src/collector_tsk.c) | [1](src/collector_tsk.c) | Collects allocated and deleted filesystem records without mounting or modifying the image. |
| [**Verified EWF Collection**](src/ewf.c) | [1](src/ewf.c) | Requires successful `ewfverify`, preserves `ewfinfo`, hashes EWF segments, and processes E01 evidence through The Sleuth Kit. |
| [**Controlled File Carving**](src/carve.c) | [1](src/carve.c) | Runs Foremost or Scalpel, preserves logs, and catalogs recovered files with hashes and acquisition provenance. |

</details>

<details>
<summary><strong>Correlation & Artifact Handling</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Versioned Evidence Store**](src/db.c) | [1](src/db.c) | Stores cases, sources, and normalized events in SQLite with schema migrations and transactional writes. |
| [**Deterministic Timelines**](src/timeline.c) | [1](src/timeline.c) | Correlates conversation-linked and same-host activity by UTC time range, host, process, and parent process. |
| [**Case Manifests**](src/manifest.c) | [1](src/manifest.c) | Exports evidence paths, hashes, sizes, commands, tool versions, acquisition times, and collection status. |
| [**Evidence Verification**](src/manifest.c) | [1](src/manifest.c) | Recomputes source and preserved-output hashes and reports missing or modified artifacts. |
| [**Hash-Verified Artifact Inspection**](src/artifact.c) | [1](src/artifact.c) | Revalidates carved files before bounded hex or base64 JSON inspection. Recovered content is never executed. |

</details>

<details>
<summary><strong>Analysis & Reporting</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Bounded LLM Analysis**](src/analyze.c) | [1](src/analyze.c) | Sends at most 500 metadata-only events to an OpenAI-compatible endpoint with timeouts and response limits. |
| [**Citation Validation**](src/analyze.c) | [1](src/analyze.c) | Requires structured observations and hypotheses. Rejects invented event references and mismatched evidence counts. |
| [**Portable Investigation Reports**](src/report.c) | [1](src/report.c) | Produces JSON or escaped Markdown reports that separate observations, hypotheses, limitations, and human review. |
| [**Human Review Attestations**](src/report.c) | [1](src/report.c) | Records reviewer identity and decision. An attestation is not a cryptographic signature. |

</details>

<details>
<summary><strong>Security & Evidence Integrity</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**No Model-to-Host Execution**](src/analyze.c) | [1](src/analyze.c) | Gives the LLM no shell, host credentials, forensic tools, database writes, or execution path. |
| [**No-Shell Subprocesses**](src/process.c) | [1](src/process.c) | Executes forensic tools with fixed argument arrays, bounded output, and checked exit status. |
| [**Evidence Hashing**](src/util.c) | [1](src/util.c) | Computes SHA-256 for source images, preserved output, EWF segments, and recovered artifacts. |
| [**Transactional Ingestion**](src/event.c) | [1](src/event.c) [2](src/audit.c) [3](src/carve.c) | Rolls back malformed or duplicate records instead of accepting partial evidence sets. |
| [**Hostile-Artifact Boundaries**](src/carve.c) | [1](src/carve.c) [2](src/artifact.c) | Rejects symlinks and non-regular output, caps recovery size, and keeps recovered bytes out of LLM requests. |
| [**Regression & Sanitizer CI**](tests/test_cerotto.py) | [1](tests/test_cerotto.py) [2](.github/workflows/ci.yml) | Tests real evidence workflows, failure paths, and normal/ASan/UBSan builds on every push and pull request. |

</details>

---

## Setup & About

<details>
<summary><strong>AI Agent Install</strong></summary>

```text
Build CEROTTO from https://github.com/Ablation-Tool/cerotto for me.

Check for a C11 compiler, Make, Python 3, a POSIX environment, Sleuth Kit, and
curl. Report missing prerequisites and ask before installing system packages.
Clone the repository if it is not already present, then build and test from
that checkout with:

  make
  make check

Report the checkout path, compiler version, test result, and the path to
`build/cerotto`. Keep EWF and real-image tooling optional until I request a
workflow that needs it.

Do not use sudo, access disks or evidence files, run collection or carving
commands, create case databases, configure an LLM endpoint, or request API
credentials during setup. Evidence work requires a separate authorized request
with explicit input and output paths.
```

</details>

<details>
<summary><strong>Manual Install</strong></summary>

**Requirements:** C11 compiler · Make · Python 3 · POSIX · Sleuth Kit · `curl`

EWF collection also requires `ewfinfo` and `ewfverify`. Real-image tests use `mke2fs`, `debugfs`, and `ewfacquire`. SQLite and cJSON are pinned in `vendor/`; no C development packages are required.

```bash
make
make check
make sanitize
make check BUILD_DIR=build/sanitize
```

The executable is `build/cerotto`.

</details>

<details>
<summary><strong>Investigate a case</strong></summary>

```bash
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

CEROTTO links conversation-associated events with activity on the relevant host during the selected half-open time window.

</details>

<details>
<summary><strong>Carve and inspect recovered files</strong></summary>

```bash
build/cerotto carve --db case.db --case incident-7 \
  --image evidence.img --output recovered --host agent-vm-1 --carver foremost

build/cerotto artifact show --db case.db --case incident-7 \
  --source-id ARTIFACT_ID --format hex --max-bytes 8192
```

CEROTTO hashes each recovered file before inspection. It rejects missing or modified artifacts and never sends recovered bytes to the LLM automatically.

</details>

<details>
<summary><strong>Verify evidence and export a report</strong></summary>

```bash
build/cerotto manifest --db case.db --case incident-7 --output manifest.json
build/cerotto verify --db case.db --case incident-7

build/cerotto report --db case.db --case incident-7 --conversation conv-7 \
  --format markdown --output report.md --reviewer "Incident Reviewer" \
  --review-status reviewed
```

`verify --base DIR` resolves recorded relative paths against a different case directory. Reports also support `--format json`.

</details>

<details>
<summary><strong>Optional LLM analysis</strong></summary>

```bash
export CEROTTO_BASE_URL=https://provider.example/v1
export CEROTTO_MODEL=model-name
export CEROTTO_API_KEY=key-if-required

build/cerotto analyze --db case.db --case incident-7 --conversation conv-7
```

CEROTTO appends `/chat/completions` to the base URL. Deterministic SQL selects the evidence before the request. Use a local mock endpoint during development instead of transmitting sensitive evidence.

</details>

<details>
<summary><strong>Limits and safe use</strong></summary>

- CEROTTO investigates after an incident. It does not block prompt injection or stop an attack in progress.
- Audit collection must be configured before an incident for complete process telemetry.
- Timing alone does not prove causation or intent. An outbound connection does not prove exfiltration.
- Paths and identifiers remain untrusted evidence. LLM observations and hypotheses require human verification.
- CEROTTO does not currently provide live containment, natural-language queries, fleet-wide analysis, incident-similarity graphs, Chkrootkit, or Volatility integration.

Use CEROTTO only for authorized investigations. Preserve original evidence separately, analyze verified copies, and protect case databases and reports as sensitive material.

</details>

<details>
<summary><strong>Development and verification</strong></summary>

Code changes require a FORGE review, a passing test suite, and resolution of every HIGH or CRITICAL finding before publication.

```bash
make check
make sanitize
make check BUILD_DIR=build/sanitize
```

Tests use generated evidence and a local mock LLM. They do not contact external providers or publish investigation data.

</details>

<details>
<summary><strong>Responsible use and contact</strong></summary>

CEROTTO is built for authorized security research and incident response. Use it only on systems and evidence you own or have explicit permission to investigate.

Report bugs through [GitHub Issues](https://github.com/Ablation-Tool/cerotto/issues).

</details>
