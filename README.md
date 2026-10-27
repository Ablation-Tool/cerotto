<p align="center">
  <img src="assets/branding/cerotto-wordmark.svg" width="640" alt="CEROTTO">
</p>

<p align="center">
  <a href="https://github.com/Ablation-Tool/cerotto/actions/workflows/ci.yml"><img src="https://github.com/Ablation-Tool/cerotto/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/version-0.2.0-grey" alt="Version 0.2.0">
  <img src="https://img.shields.io/badge/language-C11-grey" alt="C11">
  <img src="https://img.shields.io/badge/platform-Linux-grey" alt="Linux">
</p>

**CEROTTO helps investigators trace what an AI agent did on a computer.**

It connects prompts and tool calls to processes, files, network activity, and disk evidence—then produces a reviewable timeline and an optional evidence-cited analysis.


---


CEROTTO is a Digital Forensics and Incident Response tool, built for a modern problem: investigating AI agents.


Traditional DFIR tools answer: "A hacker or malware got onto this server—what files did they touch and what commands did they run?"


CEROTTO answers: "An autonomous AI agent was given access to a computer—what did the user ask it, what tools did the agent decide to call, and what actually happened on the operating system as a result?"

---

## Who is it for?

CEROTTO is for **incident responders, security engineers, and forensic analysts** who run or investigate AI agents that can access files, execute tools, or make network connections.

Use it when you need to answer questions such as:

- What happened on the host after this suspicious conversation?
- Which process ran after this tool call, and what was its parent process?
- Did the agent access a sensitive file, create or delete a script, or open a network connection?
- What does the available evidence actually establish—and what remains uncertain?

## What problem does it solve?

Agent investigations produce scattered evidence:

| Evidence you have | What it tells you |
|---|---|
| Prompt and tool-call logs | What the agent was asked to do and which tools it invoked |
| Linux audit logs | Which processes ran and which file/network operations occurred |
| Disk images | Which files existed, changed, or were deleted |

Manually connecting these records is slow and error-prone. **CEROTTO puts them into one case and one ordered timeline.** An optional LLM can summarize that timeline with citations to the exact events it used.

CEROTTO helps investigate causation; it does not claim that timing alone proves it.

## What does CEROTTO do?

| Input | CEROTTO processing | Output |
|---|---|---|
| Agent-event JSONL | Validates records and preserves source hashes | One SQLite evidence case |
| Captured Linux audit logs | Correlates audit records into process, file, and network events | Ordered, filtered JSON timelines |
| Raw disk images | Runs Sleuth Kit allocated/deleted-file passes and preserves provenance | Evidence manifests and hashes |
| Bounded timeline metadata | Sends only the selected metadata to an optional LLM | Observations, hypotheses, limitations, and event citations |

### The safety model

Deterministic code collects evidence and runs the queries. **The LLM has no shell, host credentials, forensic-tool access, or execution path.** Its output is never executed.

Citations prevent invented event references. They do not guarantee that an interpretation is correct, so a human still reviews the evidence.

## A typical investigation

```bash
make

CEROTTO=build/cerotto

# Create a case and import agent and host telemetry.
$CEROTTO init --db case.db
$CEROTTO ingest --db case.db --case incident-7 --input agent-events.jsonl
$CEROTTO ingest-audit --db case.db --case incident-7 \
  --input audit.log --host agent-vm-1

# Add filesystem evidence from a raw disk image.
mkdir -p collected/incident-7
$CEROTTO collect-tsk --db case.db --case incident-7 \
  --image agent-disk.img --output collected/incident-7 --host agent-vm-1

# Review what happened around the conversation.
$CEROTTO timeline --db case.db --case incident-7 --conversation conv-7 \
  --from 2026-10-27T11:59:00Z --to 2026-10-27T12:05:00Z
```

The result links conversation-associated events with activity on the relevant host during the selected half-open time window.

---

## Capabilities

<details>
<summary><strong>Collection & Attribution</strong></summary>

| Capability | What it does |
|---|---|
| **Agent events** | Transactional JSONL ingestion with conversation, prompt, tool-call, process, parent-process, path, and timestamp fields. |
| **Process attribution** | Combines `SYSCALL` and `EXECVE` audit records into process events with PID, PPID, executable, arguments, and result. |
| **File and network events** | Correlates supported `PATH` and `SOCKADDR` records for open/create/unlink and connect operations. |
| **Audit decoding** | Handles interleaved records, quoted/hex strings, `node=` host identity, and normalized fractional timestamps. |
| **Filesystem timelines** | Runs separate allocated and deleted-file `fls` passes without mounting or modifying the image. |
| **Provenance** | Preserves source/output hashes, exact commands, tool versions, acquisition times, and import status. |

Failed audit operations are recorded as attempts, not successful actions. Malformed input or duplicate stable event IDs roll back an import.

</details>

<details>
<summary><strong>Analysis & Review</strong></summary>

| Capability | What it does |
|---|---|
| **Deterministic timelines** | SQL selects conversation-linked and same-host events by host and time range—not the LLM. |
| **Process ancestry** | Includes PID and parent PID in timeline output. |
| **Bounded LLM analysis** | Sends at most 500 events and excludes free-form event details. |
| **Citation validation** | Rejects invented event IDs and malformed response structures. |
| **Transport safeguards** | Uses timeouts, response limits, owner-only temporary payloads, and no API key in process arguments. |

Paths and identifiers remain untrusted evidence and may contain hostile text. Review material claims against the original records and apply your organization's confidentiality requirements before using an external model.

</details>

<details>
<summary><strong>What CEROTTO does not do</strong></summary>

- It does not prevent prompt injection or replace agent sandboxing and access controls.
- It does not configure auditd or provide live containment.
- It does not give the LLM direct host access or execute model suggestions.
- It does not prove that a prompt caused a host event merely because one preceded the other.
- It does not currently provide natural-language queries, fleet-wide analysis, incident-similarity graphs, AFF/EWF acquisition, carving, Chkrootkit, or Volatility integration.

</details>

---

## Setup & Reference

<details>
<summary><strong>Install and verify</strong></summary>

Requirements: a C11 compiler, Make, Python 3, POSIX, `fls`, and `curl`. Real-image tests also use `mke2fs` and `debugfs`. SQLite and cJSON are pinned in `vendor/`; no C development packages are required.

```bash
make
make check
make sanitize
make check BUILD_DIR=build/sanitize
```

The executable is `build/cerotto`. Tests use generated evidence and a local mock LLM; no external provider is contacted. GitHub Actions runs normal and AddressSanitizer/UndefinedBehaviorSanitizer suites.

</details>

<details>
<summary><strong>Agent JSONL format</strong></summary>

Required fields: `id`, `observed_at`, `host_id`, `source_tool`, and `event_type`.

Optional fields: `conversation_id`, `prompt_id`, `tool_call_id`, `process_id`, `parent_process_id`, `path`, `deleted`, and `details` (an object). Timestamps must be UTC with at most six fractional-second digits.

```json
{"id":"evt-001","observed_at":"2026-10-27T12:00:00Z","host_id":"agent-vm-1","source_tool":"agent_gateway","event_type":"tool_call","conversation_id":"conv-7","prompt_id":"prompt-9","tool_call_id":"call-3","process_id":420,"parent_process_id":100,"path":"/tmp/job.sh"}
```

</details>

<details>
<summary><strong>Audit configuration</strong></summary>

CEROTTO ingests captured logs; an administrator chooses the audit policy. Coverage targets common x86-64, x86, and AArch64 execve/execveat, open/create/unlink, and connect syscall numbers—not every Linux ABI or record type.

Example rules for a controlled investigation:

```text
-a always,exit -F arch=b64 -S execve -S execveat -k cerotto_exec
-a always,exit -F arch=b64 -S connect -k cerotto_network
-w /path/to/sensitive-data -p rwa -k cerotto_sensitive
-w /opt/agent/tmp -p wa -k cerotto_files
```

These examples are not installed automatically. Broad auditing can create substantial overhead and log volume. Test rules in a disposable environment and protect the resulting logs.

</details>

<details>
<summary><strong>Optional LLM analysis</strong></summary>

```bash
export CEROTTO_BASE_URL=https://provider.example/v1
export CEROTTO_MODEL=model-name
export CEROTTO_API_KEY=key-if-required

build/cerotto analyze --db case.db --case incident-7 --conversation conv-7
```

CEROTTO appends `/chat/completions` to the base URL. Use a local mock endpoint during development rather than transmitting sensitive evidence.

</details>

<details>
<summary><strong>Responsible use and evidence handling</strong></summary>

Use CEROTTO only for authorized investigations. Preserve original evidence separately, analyze verified copies, use synchronized UTC clocks, and run collectors with the least privilege available in an isolated environment.

Databases, timelines, and reports can contain sensitive investigation metadata. Protect them accordingly. Vendored dependency versions, source URLs, hashes, and licenses are documented in `vendor/README.md`.

</details>
