
CEROTTO investigates attacks involving autonomous AI agents and sandbox escapes.

It connects user requests, agent tool calls, operating-system activity, and disk evidence. Incident responders can reconstruct what happened and verify each conclusion against the underlying records.

CEROTTO helps incident responders, security engineers, and forensic analysts answer one question: **What did the agent do on the computer?**

---

## Capabilities

<details>
<summary><strong>Agent & Host Evidence Collection</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Agent Event Ingestion**](docs/capabilities.md#agent-event-ingestion) | [1](src/event.c) | Imports conversations, prompts, tool calls, processes, file events, and network events from validated JSONL records. |
| [**Linux Audit Attribution**](docs/capabilities.md#linux-audit-attribution) | [1](src/audit.c) | Correlates interleaved audit records into process execution, file activity, and network connections with PID/PPID attribution. |
| [**Raw Disk Timelines**](docs/capabilities.md#raw-disk-timelines) | [1](src/collector_tsk.c) | Collects allocated and deleted filesystem records without mounting or modifying the image. |
| [**Verified EWF Collection**](docs/capabilities.md#verified-ewf-collection) | [1](src/ewf.c) | Requires successful `ewfverify`, preserves `ewfinfo`, hashes EWF segments, and processes E01 evidence through The Sleuth Kit. |
| [**Controlled File Carving**](docs/capabilities.md#controlled-file-carving) | [1](src/carve.c) | Runs Foremost or Scalpel, preserves logs, and catalogs recovered files with hashes and acquisition provenance. |

</details>

<details>
<summary><strong>Correlation & Artifact Handling</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Versioned Evidence Store**](docs/capabilities.md#versioned-evidence-store) | [1](src/db.c) | Stores cases, sources, and normalized events in SQLite with schema migrations and transactional writes. |
| [**Deterministic Timelines**](docs/capabilities.md#deterministic-timelines) | [1](src/timeline.c) | Correlates conversation-linked and same-host activity by UTC time range, host, process, and parent process. |
| [**Case Manifests**](docs/capabilities.md#case-manifests) | [1](src/manifest.c) | Exports evidence paths, hashes, sizes, commands, tool versions, acquisition times, and collection status. |
| [**Evidence Verification**](docs/capabilities.md#evidence-verification) | [1](src/manifest.c) | Recomputes source and preserved-output hashes and reports missing or modified artifacts. |
| [**Hash-Verified Artifact Inspection**](docs/capabilities.md#hash-verified-artifact-inspection) | [1](src/artifact.c) | Revalidates carved files before bounded hex or base64 JSON inspection. Recovered content is never executed. |

</details>

<details>
<summary><strong>Analysis & Reporting</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Bounded LLM Analysis**](docs/capabilities.md#bounded-llm-analysis) | [1](src/analyze.c) | Sends at most 500 metadata-only events to an OpenAI-compatible endpoint with timeouts and response limits. |
| [**Citation Validation**](docs/capabilities.md#citation-validation) | [1](src/analyze.c) | Requires structured observations and hypotheses. Rejects invented event references and mismatched evidence counts. |
| [**Portable Investigation Reports**](docs/capabilities.md#portable-investigation-reports) | [1](src/report.c) | Produces JSON or escaped Markdown reports that separate observations, hypotheses, limitations, and human review. |
| [**Human Review Attestations**](docs/capabilities.md#human-review-attestations) | [1](src/report.c) | Records reviewer identity and decision. An attestation is not a cryptographic signature. |

</details>

<details>
<summary><strong>Security & Evidence Integrity</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**No Model-to-Host Execution**](docs/capabilities.md#no-model-to-host-execution) | [1](src/analyze.c) | Gives the LLM no shell, host credentials, forensic tools, database writes, or execution path. |
| [**No-Shell Subprocesses**](docs/capabilities.md#no-shell-subprocesses) | [1](src/process.c) | Executes forensic tools with fixed argument arrays, bounded output, and checked exit status. |
| [**Evidence Hashing**](docs/capabilities.md#evidence-hashing) | [1](src/util.c) | Computes SHA-256 for source images, preserved output, EWF segments, and recovered artifacts. |
| [**Transactional Ingestion**](docs/capabilities.md#transactional-ingestion) | [1](src/event.c)&nbsp;[2](src/audit.c)&nbsp;[3](src/carve.c) | Rolls back malformed or duplicate records instead of accepting partial evidence sets. |
| [**Hostile-Artifact Boundaries**](docs/capabilities.md#hostile-artifact-boundaries) | [1](src/carve.c)&nbsp;[2](src/artifact.c) | Rejects symlinks and non-regular output, caps recovery size, and keeps recovered bytes out of LLM requests. |
| [**Regression & Sanitizer CI**](docs/capabilities.md#regression--sanitizer-ci) | [1](tests/test_cerotto.py)&nbsp;[2](.github/workflows/ci.yml) | Tests real evidence workflows, failure paths, and normal/ASan/UBSan builds on every push and pull request. |

</details>

<details>
<summary><strong>Encrypted Vault & Forensic Tripwire</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Native GEMSEAL Containers**](docs/vault.md#native-container-operations) | [1](src/gemseal.c)&nbsp;[2](src/crypto.c) | Implements GEMSEAL version 1 with streaming authenticated encryption, strict validation, and atomic no-overwrite publication. |
| [**Native Vault Sensor**](docs/vault.md#monitor-a-vault) | [1](src/vault_sensor.c)&nbsp;[2](src/vault.c) | Persists recursive Linux inotify access and health events directly into Cerotto cases with watcher, host, boot, vault, and sequence context. |
| [**Plaintext Release Broker**](docs/vault.md#release-plaintext) | [1](src/vault_release.c) | Records approval, denial, expiration, content hashes, residual plaintext, and cleanup. Refuses to delete modified releases. |
| [**Correlation & Evidence-First Response**](docs/vault.md#timeline-and-correlation) | [1](src/vault_correlate.c)&nbsp;[2](src/vault_response.c) | Correlates only independent process, agent, and network evidence. Exports evidence before approved suspend/resume actions. |
| [**Vault Case Workbench**](docs/vault.md) | [1](cerotto_gem/vault.py)&nbsp;[2](tests/test_vault.py) | Displays native vault contacts, modifications, release outcomes, health alerts, and response events in CEROTTO GEM. |

See [the vault operator and forensic guide](docs/vault.md) for workflow, interoperability, diagnostics, experimental status, and monitoring limits.

</details>

<details>
<summary><strong>Ablation + GEM Defense Research</strong></summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Accessible Volume Measurement**](docs/capabilities.md#accessible-volume-measurement) | [1](investigation/forecast.py) | Computes strict threshold sweeps, entropy, maximum probability, and top-token mass from validated full distributions. |
| [**Native Accessible Volume**](docs/capabilities.md#native-accessible-volume) | [1](src/forecast.c)&nbsp;[2](src/util.c) | Computes and hashes the same threshold sweep directly in C from a bounded probability array. |
| [**Native Guarded Evidence Actions**](docs/capabilities.md#native-guarded-evidence-actions) | [1](src/guard.c)&nbsp;[2](tests/test_native_guard.py) | Validates forecast-bound structured proposals and executes only bounded timeline, event, manifest, and verification actions. |
| [**Guard Proposal Provenance**](docs/capabilities.md#guard-proposal-provenance) | [1](src/guard.c)&nbsp;[2](src/manifest.c) | Registers each raw proposal and probability array as a hashed evidence source linked to its guard events. |
| [**Native GEM Workbench**](docs/capabilities.md#native-gem-workbench) | [1](cerotto_gem/gui.py)&nbsp;[2](cerotto_gem/chart.py)&nbsp;[3](tests/test_gem_workbench.py) | Provides a native GTK Lab, defense details, Cairo forecast charts, guard controls, reporting, and an optional VTE agent terminal. |
| [**Guarded GEM Execution**](docs/capabilities.md#guarded-gem-execution) | [1](investigation/guard.py)&nbsp;[2](integration/ablation_gem_defense.py) | Binds forecasts to the current GEM revision and proposal. Denies stale, malformed, and unsupported actions before broker execution. |
| [**Guard Evidence Chains**](docs/capabilities.md#guard-evidence-chains) | [1](investigation/guard.py)&nbsp;[2](tests/test_defense.py) | Links model forecasts, action proposals, policy decisions, and execution receipts through shared conversation, prompt, and action identifiers. |
| [**GEM History Export**](docs/capabilities.md#gem-history-export) | [1](investigation/gem_events.py)&nbsp;[2](integration/ablation_gem_defense.py) | Converts bounded GEM event ranges into Cerotto JSONL for ingestion and timeline correlation. |

</details>

<details>
<summary><strong>Guard an Ablation + GEM action</strong></summary>

This experimental integration uses the pinned DistilGPT2 ONNX model from the accessible-volume papers. It requires NumPy, ONNX Runtime, Tokenizers, an initialized GEM session, and a structured agent proposal such as:

```json
{"command":"begin_selected_work","expected_id":"artifact:ARTIFACT_ID","expected_revision":3}
```

The expected ID and revision must match current GEM state. Run the forecast, guard, execution, and Cerotto ingestion path:

```bash
python3 integration/ablation_gem_defense.py run \
  --gem-lab /path/to/ablation/gem-lab \
  --session /path/to/gem-session \
  --proposal proposal.json \
  --model-dir /path/to/distilgpt2-onnx \
  --artifacts forecast-artifacts \
  --output guard-events.jsonl \
  --host agent-vm-1 --conversation conv-7 \
  --db case.db --case incident-7
```

Export the resulting GEM history into the same case:

```bash
python3 integration/ablation_gem_defense.py export-gem \
  --session /path/to/gem-session \
  --output gem-events.jsonl \
  --host agent-vm-1 --conversation conv-7 \
  --db case.db --case incident-7
```

The run command exits 0 after successful execution, 3 after a policy denial, and 1 after an error. The export command prints the next source line for incremental collection.

The guard protects only structured `GemCommandBroker` calls. It does not contain an embedded agent terminal, arbitrary shell commands, or network activity. The proposal is supplied by an external agent or analyst; this harness does not autonomously generate proposals. Accessible volume is recorded as observational telemetry and does not currently influence authorization.

Forecast NPZ files contain context JSON, input IDs, and raw probabilities. Protect them as sensitive evidence. Their paths and hashes are recorded in forecast events, but `cerotto verify` does not currently verify these external artifacts.

</details>

<details>
<summary><strong>Native guarded evidence actions</strong></summary>

`cerotto guard` implements the proposal-validation-execution-receipt pattern directly in C. It supports `query_timeline`, `get_event`, `get_manifest`, and `verify_case`. It does not provide shell, arbitrary SQL, artifact execution, or host mutation actions.

A proposal has this shape:

```json
{
  "schema_version": 1,
  "action_id": "action-1",
  "host_id": "agent-vm-1",
  "conversation_id": "conv-7",
  "expected_event_count": 5,
  "action": "query_timeline",
  "arguments": {"limit": 200},
  "forecast": {
    "model": "model-identifier",
    "context_sha256": "SHA256_OF_CANONICAL_CONTEXT",
    "probabilities": [0.5, 0.5]
  }
}
```

The context digest is SHA-256 of the exact compact UTF-8 context, with object fields in this order and no trailing newline:

```json
{"case_id":"incident-7","conversation_id":"conv-7","expected_event_count":5,"action":"query_timeline","arguments":{"limit":200}}
```

The expected event count is the number of events in the case before the guard runs. An allowed action appends four guard events. A policy denial appends three and does not execute the proposal. A duplicate action ID rolls back the attempted chain.

Run a prepared proposal:

```bash
build/cerotto guard --db case.db --case incident-7 \
  --input proposal.json --output guard-result.json
```

The command exits 0 after successful execution, 3 after a policy denial, and 1 after an error. The raw proposal is registered as a hashed `guard_proposal` source and is covered by case manifest verification while it remains at its recorded path.

The native guard computes accessible volume from the supplied full distribution. It does not run model inference, authenticate the distribution producer, or treat the measurement as a safety verdict.

</details>

<details>
<summary><strong>Open CEROTTO GEM</strong></summary>

CEROTTO GEM is a native GTK3 workbench for an existing case. It provides a filterable Lab, defense-event details, a Vault event timeline, an accessible-volume chart, native guard controls, verification, JSON report export, and an optional VTE agent terminal.

The GUI requires Python GI, GTK3, and Cairo. The agent terminal also requires VTE 2.91. The launcher checks the system distribution packages automatically.

```bash
python3 -m cerotto_gem \
  --db case.db --case incident-7 --conversation conv-7
```

The equivalent launcher is `integration/cerotto-gem`. Add an interactive agent and workspace explicitly:

```bash
python3 -m cerotto_gem \
  --db case.db --case incident-7 --conversation conv-7 \
  --agent-command kimi --workspace /path/to/agent-workspace
```

The terminal receives `CEROTTO_DB`, `CEROTTO_CASE`, `CEROTTO_CONVERSATION`, and `CEROTTO_BINARY`. It retains the agent's own permissions and is not a guarded execution boundary.

Run the real GUI lifecycle check in isolated X11:

```bash
integration/nested_x11.sh python3 -m cerotto_gem \
  --db case.db --case incident-7 --conversation conv-7 \
  --self-test --screenshot /tmp/cerotto-gem.png
```

The self-test selects a forecast, verifies its chart, optionally checks agent startup and shutdown, captures the window, and exits. GUI dependencies are optional for the C core and required only for desktop use.

</details>

---

## Setup & About

<details>
<summary><strong>Install</strong></summary>

**Requirements:** C11 compiler · Make · Python 3 · POSIX · Sleuth Kit · `curl`

EWF collection also requires `ewfinfo` and `ewfverify`. Real-image tests use `mke2fs`, `debugfs`, and `ewfacquire`. SQLite and cJSON are pinned in `vendor/`; no C development packages are required.

CEROTTO GEM additionally requires Python GI, GTK3, and Cairo. VTE 2.91 is required only for the optional agent terminal. Native GUI tests require Xephyr and `xwininfo`; they use a private display and do not open test windows on the live desktop.

The native vault and GEMSEAL implementation uses Linux inotify. Its cryptography is built into the C core and requires no additional crypto package.

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

- The native guard covers four Cerotto evidence actions. The optional GEM guard covers structured broker calls. Neither provides whole-agent, terminal, process, or network containment.
- Audit collection must be configured before an incident for complete process telemetry.
- Timing alone does not prove causation or intent. An outbound connection does not prove exfiltration.
- Paths and identifiers remain untrusted evidence. LLM observations and hypotheses require human verification.
- Accessible volume is not a maliciousness score. No trained attack predictor or measured detection advantage is claimed.
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

The [LLM-Driven Digital Forensics: Blue versus Red playbook](docs/references/LLM_Driven_Digital_Forensics_BvR_Playbook.pdf) provides the adversarial evaluation doctrine for future exercises: independent refereeing, sealed ground truth, red/blue separation, safety gates, and coverage metrics. Its twelve play cards are evaluation guidance, not a claim that Cerotto currently implements or passes every scenario.

</details>

<details>
<summary><strong>Responsible use and contact</strong></summary>

CEROTTO is built for authorized security research and incident response. Use it only on systems and evidence you own or have explicit permission to investigate.

Report bugs through [GitHub Issues](https://github.com/Ablation-Tool/cerotto/issues).

</details>
