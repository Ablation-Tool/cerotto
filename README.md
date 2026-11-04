# CEROTTO

CEROTTO investigates attacks involving autonomous AI agents and sandbox escapes. It connects user requests, agent tool calls, model forecasts, operating-system activity, encrypted-vault events, and disk evidence. Incident responders can reconstruct what happened and verify each conclusion against retained records.

CEROTTO is a C11 forensic engine with a native GTK workbench, deterministic guarded actions, accessible-volume measurement, and a native encrypted-vault tripwire. It does not include an LLM, credentials, or a separate sidecar service.

**Current version:** 0.6.0

**Primary question:** **What did the agent do on the computer?**

## Architecture

```text
AI agent and host telemetry
          |
          v
C11 evidence ingestion and SQLite case store
          |
          +--> Timelines, manifests, reports, and verification
          |
          +--> Deterministic guard and evidence actions
          |
          +--> Accessible-volume forecasts and guarded GEM execution
          |
          +--> Encrypted vault, inotify sensor, release broker, and response
          |
          v
CEROTTO GEM native GTK workbench
```

The native C core owns evidence writes. The GUI opens the database read-only and uses the C binary for guard actions, verification, and report generation. The optional Ablation + GEM bridge uses its own session and command broker. No GEMSEAL Python package is required at runtime.

## Capabilities

### Forensic collection and evidence handling

| Capability | Implementation | Description |
|:---|:---|:---|
| Agent event ingestion | `src/event.c` | Imports conversations, prompts, tool calls, processes, file events, and network events from validated JSONL records. |
| Linux audit attribution | `src/audit.c` | Correlates interleaved audit records into execution, file, and network events with PID, PPID, UID, executable, and syscall context where available. |
| Raw disk timelines | `src/collector_tsk.c` | Collects allocated and deleted filesystem records without mounting or modifying the image. |
| Verified EWF collection | `src/ewf.c` | Requires successful `ewfverify`, preserves `ewfinfo`, hashes EWF segments, and processes E01 evidence through The Sleuth Kit. |
| Controlled carving | `src/carve.c` | Runs Foremost or Scalpel with bounded output, preserved logs, and acquisition provenance. |
| Versioned evidence store | `src/db.c` | Uses SQLite migrations, transactional writes, cases, sources, and normalized events. |
| Deterministic timelines | `src/timeline.c` | Correlates conversation-linked and same-host activity by time, host, process, and parent process. |
| Evidence verification | `src/manifest.c` | Recomputes source and preserved-output hashes and reports missing or modified artifacts. |
| Artifact inspection | `src/artifact.c` | Revalidates carved files before bounded hex or base64 JSON inspection. Recovered content is never executed. |

### CEROTTO GEM native workbench

CEROTTO GEM is a native GTK3 application, not a browser interface.

- Filterable Lab grouped by guard action.
- Full defense-event details, host, type, status, and timestamps.
- Dedicated Vault timeline with contacts, modifications, releases, health alerts, and response events.
- Native Cairo accessible-volume charts.
- Run Guard, Verify Case, Refresh, and Export Report controls.
- Optional embedded VTE terminal for the user's real AI CLI.
- Read-only SQLite case model with bounded native commands.
- Isolated X11 self-tests, screenshots, and agent-process cleanup.

Launch an existing case:

```bash
python3 -m cerotto_gem \
  --db case.db --case incident-7 --conversation conv-7
```

The equivalent launcher is `integration/cerotto-gem`.

Embed the user's actual interactive agent explicitly:

```bash
python3 -m cerotto_gem \
  --db case.db --case incident-7 --conversation conv-7 \
  --agent-command kimi --workspace /path/to/agent-workspace
```

The terminal receives `CEROTTO_DB`, `CEROTTO_CASE`, `CEROTTO_CONVERSATION`, and `CEROTTO_BINARY`. It retains the agent's permissions and is explicitly unguarded. No model or credentials are installed or substituted.

### Encrypted vault and forensic tripwire

| Component | Implementation | Purpose |
|:---|:---|:---|
| GEMSEAL version 1 | `src/gemseal.c`, `src/crypto.c` | Native authenticated encryption with strict format validation and atomic no-overwrite publication. |
| Vault sensor | `src/vault_sensor.c` | Recursive Linux inotify access and health events written directly into Cerotto cases. |
| Evidence model | `src/vault.c` | Native source details, watcher sessions, sequence numbers, host/boot/vault IDs, and separate timestamps. |
| Plaintext release broker | `src/vault_release.c` | Approval, denial, expiration, content hashes, residual plaintext, and cleanup. |
| Correlation | `src/vault_correlate.c` | Conservative process, agent, and network correlation with confidence labels and benign alternatives. |
| Evidence-first response | `src/vault_response.c` | Exports evidence before approved suspend and resume actions. |
| Vault case view | `cerotto_gem/vault_view.py` | Native Vault tab in CEROTTO GEM. |

GEMSEAL is experimental and has not received an independent cryptographic review. For production confidentiality, use an audited format such as `age`. The sensor can monitor other encrypted formats, but the release broker currently decrypts only GEMSEAL version 1.

### Deterministic guard and accessible volume

The native `guard` command implements proposal, validation, execution, and receipt in C. Supported actions are:

- `query_timeline`
- `get_event`
- `get_manifest`
- `verify_case`

The guard checks the proposal schema, duplicate fields, arguments, expected case event count, forecast context hash, normalized distribution, existing output, and duplicate action IDs. Denied actions do not execute. Failed executions cannot produce success receipts. Raw proposals are registered as hashed `guard_proposal` sources.

Accessible volume is implemented in Python and C:

- Strict threshold counts and normalized values.
- Entropy, maximum probability, and top-ten probability mass.
- Vocabulary size and packed probability hashes.
- Real DistilGPT2 ONNX measurement through the Ablation + GEM bridge.
- Native measurement of the paper's full 50,257-token distribution and its published digest.

Accessible volume describes the shape of a particular next-token forecast. It is not a maliciousness score, an authorization rule, or a trained attack predictor.

### Ablation + GEM integration

`integration/ablation_gem_defense.py` provides:

- Real DistilGPT2 ONNX forward passes with pinned model, tokenizer, and configuration hashes.
- Raw NPZ probability preservation.
- Forecast binding to the exact GEM target, selected event, revision, and structured proposal.
- Guarded `GemCommandBroker` execution with denial before stale or unsupported actions.
- Four-record evidence chains: `model_forecast`, `action_proposal`, `policy_decision`, and `execution_receipt`.
- GEM history export and Cerotto timeline correlation.

The bridge protects structured broker calls only. It does not contain unrestricted embedded terminals, shell commands, or network activity. External agent proposals are supplied as JSON; the harness does not autonomously generate them.

### Bounded AI investigation

The Python `investigation` package provides a bounded ReAct investigator. The model can request only:

- `query_timeline`
- `get_event`
- `get_manifest`
- `verify_case`
- `done`

It cannot execute shell commands, issue arbitrary SQL, leave the selected case scope, or invent event citations. Observations and hypotheses require valid event IDs and human review. The C analysis path also supports metadata-only bounded LLM analysis with citation validation.

### Security diagnostics

`cerotto crack` demonstrates weak manually derived keys:

```bash
build/cerotto crack wordlist --input container.gemseal \
  --wordlist words.txt --mode sha256

build/cerotto crack pin --input container.gemseal --digits 4

build/cerotto crack raw-prefix --input container.gemseal --variable-bytes 1
```

Supported candidate transforms are SHA-256, zero-padding, and exact raw 32-byte keys. Reports include tested and skipped candidates, elapsed time, candidates per second, and first-record authentication. `--output` additionally verifies the complete container after recovery. These are bounded tests of weak manually derived keys, not a generic ChaCha20 attack.

## Quick start

### Build and verify

Requirements:

- C11 compiler, Make, Python 3, POSIX, Sleuth Kit, and `curl`.
- EWF collection additionally uses `ewfinfo` and `ewfverify`.
- Real-image tests use `mke2fs`, `debugfs`, and `ewfacquire`.
- CEROTTO GEM requires Python GI, GTK3, and Cairo. VTE 2.91 is optional for the agent terminal.
- GUI tests require Xephyr and `xwininfo`.
- The native vault uses Linux inotify. Its cryptography is built into the C core and requires no additional crypto package.

SQLite and cJSON are pinned in `vendor/`.

```bash
make
make check
make sanitize
make check BUILD_DIR=build/sanitize
```

The executable is `build/cerotto`.

### Investigate a case

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

Carve and inspect recovered files:

```bash
$CEROTTO carve --db case.db --case incident-7 \
  --image evidence.img --output recovered --host agent-vm-1 --carver foremost

$CEROTTO artifact show --db case.db --case incident-7 \
  --source-id ARTIFACT_ID --format hex --max-bytes 8192
```

Verify and export a report:

```bash
$CEROTTO manifest --db case.db --case incident-7 --output manifest.json
$CEROTTO verify --db case.db --case incident-7

$CEROTTO report --db case.db --case incident-7 --conversation conv-7 \
  --format markdown --output report.md --reviewer "Incident Reviewer" \
  --review-status reviewed
```

### Create and monitor a vault

Create the external key and release directories first. Keep the key and database outside the vault.

```bash
mkdir -p /safe/private /safe/release
chmod 700 /safe/release

build/cerotto init --db case.db
build/cerotto vault init --db case.db --case incident-7 \
  --vault /safe/vault --key /safe/private/vault.key --host agent-vm-1

build/cerotto vault watch --db case.db --case incident-7 \
  --vault /safe/vault --host agent-vm-1
```

Initialization refuses existing paths and creates an encrypted canary. The sensor records access and health events directly into the case. Start it before starting the agent.

### Release and clean up plaintext

A denial records the request without decrypting:

```bash
build/cerotto vault release --db case.db --case incident-7 \
  --key /safe/private/vault.key --input /safe/vault/project_notes.gemseal \
  --output /safe/release/denied.bin --release-root /safe/release \
  --requester analyst --reason "unapproved test" --identity agent-test \
  --host agent-vm-1
```

An approved release requires `--approve` and a future expiration:

```bash
build/cerotto vault release --db case.db --case incident-7 \
  --key /safe/private/vault.key --input /safe/vault/project_notes.gemseal \
  --output /safe/release/approved.bin --release-root /safe/release \
  --requester analyst --reason "approved forensic review" --identity agent-test \
  --host agent-vm-1 --expires YYYY-MM-DDTHH:MM:SSZ --approve
```

Clean up after the approved task:

```bash
build/cerotto vault cleanup --db case.db --case incident-7 \
  --release-id RELEASE_ID --approve --host agent-vm-1
```

Cleanup verifies the content hash before deletion. Modified content is retained and recorded. Expiration does not automatically delete plaintext.

### Timeline, correlation, response, and export

```bash
build/cerotto vault timeline --db case.db --case incident-7 \
  --output vault-timeline.json

build/cerotto vault correlate --db case.db --case incident-7 \
  --event-id VAULT_EVENT_ID --output correlation.json

build/cerotto vault respond --db case.db --case incident-7 \
  --event-id VAULT_EVENT_ID --pid AGENT_PID \
  --output response-evidence --approve --host agent-vm-1

build/cerotto vault resume --db case.db --case incident-7 \
  --event-id VAULT_EVENT_ID --pid AGENT_PID --approve --host agent-vm-1

build/cerotto vault export --db case.db --case incident-7 \
  --output vault-export --retention-days 30
```

Agent attribution requires independent process and tool-call evidence. Network proximity is not proof of exfiltration. Response affects only the supplied process and does not isolate networking.

### Native guard proposal

A native proposal has this shape:

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

The context digest is SHA-256 of the exact compact UTF-8 context with fields in this order and no trailing newline:

```json
{"case_id":"incident-7","conversation_id":"conv-7","expected_event_count":5,"action":"query_timeline","arguments":{"limit":200}}
```

The expected event count is the number of events currently in the case. An allowed action appends four guard events. A denial appends three and does not execute. Duplicate action IDs roll back the attempted chain.

```bash
build/cerotto guard --db case.db --case incident-7 \
  --input proposal.json --output guard-result.json
```

### Optional LLM analysis

```bash
export CEROTTO_BASE_URL=https://provider.example/v1
export CEROTTO_MODEL=model-name
export CEROTTO_API_KEY=key-if-required

build/cerotto analyze --db case.db --case incident-7 --conversation conv-7
```

CEROTTO appends `/chat/completions` to the base URL. Deterministic SQL selects the evidence. Use a local mock endpoint during development instead of transmitting sensitive evidence.

## Repository layout

```text
src/                    C11 forensic core, guard, crypto, vault, and correlation
cerotto_gem/            Native GTK workbench and Vault view
investigation/          Bounded Python investigation and forecast support
integration/            Ablation + GEM bridge and GUI launchers
tests/                  Forensic, guard, vault, interoperability, and GTK tests
docs/                   Capability reference, vault guide, and BvR playbook
vendor/                 Pinned SQLite and cJSON
```

## Documentation

- [Capability reference](docs/capabilities.md)
- [Encrypted vault and forensic tripwire guide](docs/vault.md)
- [Bounded investigation engine](investigation/README.md)
- [LLM-Driven Digital Forensics: Blue versus Red playbook](docs/references/LLM_Driven_Digital_Forensics_BvR_Playbook.pdf)

The playbook provides adversarial evaluation doctrine: independent refereeing, sealed ground truth, red/blue separation, safety gates, and coverage metrics. Its twelve play cards are evaluation guidance, not a claim that Cerotto currently implements or passes every scenario.

## Verification status

- 65 normal tests passed.
- 65 ASan/UBSan tests passed.
- One existing EWF test was skipped in each suite because EWF tools are unavailable.
- Deterministic GEMSEAL vector and both reference compatibility directions passed.
- Real DistilGPT2 and GEM execution paths were exercised.
- Real inotify access, watcher health, release, cleanup, modified-release retention, correlation, response, and reproducible exports were exercised.
- Real GTK rendering, Vault view, screenshots, and VTE cleanup were exercised in isolated X11.
- FORGE reviews passed with no HIGH or CRITICAL findings.

Run the complete verification matrix:

```bash
make clean && make && make check
make sanitize
make check BUILD_DIR=build/sanitize
```

## Limits and safe use

- The native guard covers four Cerotto evidence actions. The optional GEM guard covers structured broker calls. Neither provides whole-agent, terminal, process, or network containment.
- Inotify does not block access, identify processes, prove intent, or cover every VM, network-filesystem, alternate-mount, or directory-enumeration path.
- Queue-overflow and clock-change tests use diagnostic injection. No real kernel overflow or clock adjustment was forced.
- Plaintext remains sensitive after approval. Expiration does not automatically delete it.
- SIGKILL and power loss can leave temporary files. Permissions and atomic publication depend on filesystem behavior.
- Same-user agents, root compromise, key theft, plaintext exposure, and agent-writable evidence stores weaken the security boundary. Protected or remote evidence replication is required for stronger custody.
- Accessible volume is not a maliciousness score. No trained attack predictor or measured detection advantage is claimed.
- Cerotto does not currently provide live network containment, fleet-wide learning, incident-similarity graphs, Chkrootkit, Volatility integration, or age-container release.
- Paths and identifiers remain untrusted evidence. LLM observations and hypotheses require human verification.

Use CEROTTO only for authorized investigations. Preserve original evidence separately, analyze verified copies, and protect case databases, keys, releases, and reports as sensitive material.

## Responsible use and contact

CEROTTO is built for authorized security research and incident response. Use it only on systems and evidence you own or have explicit permission to investigate.

Report bugs through [GitHub Issues](https://github.com/Ablation-Tool/cerotto/issues).
