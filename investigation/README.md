# CEROTTO investigation engine

This package provides bounded, iterative investigation over CEROTTO evidence cases. The model proposes actions. CEROTTO validates them, collects the evidence, and checks every citation before accepting a report.

The implementation is self-contained. It does not require Ablation or another repository.

## How it works

```text
Model proposes one JSON action
        ↓
CEROTTO validates the action and scope
        ↓
The C CLI returns bounded evidence
        ↓
The model reviews the evidence and chooses the next action
        ↓
CEROTTO validates the final report and every event citation
```

The engine accepts completion only through `done`. It rejects unknown event citations, out-of-scope hosts, unsupported actions, trailing prose, and repeated action loops. Every observation and hypothesis needs at least one event citation. Completion requires evidence.

## Run an investigation

Build CEROTTO and expose the package:

```sh
make
export PYTHONPATH="$PWD"
```

Use an Anthropic API key or an available `claude` CLI:

```sh
export CEROTTO_MODEL=model-name
export CEROTTO_API_KEY=key-if-required

python3 -m investigation.cli investigate \
  --db case.db --case incident-7 --conversation conv-7
```

The CLI exits with status 0 for a completed investigation, 2 for an unfinished loop, and 1 for an error.

## Available actions

- `query_timeline`: Query the fixed case and conversation with optional host, UTC range, and event limit.
- `get_event`: Retrieve an event already returned by the timeline.
- `get_manifest`: Retrieve source provenance for the case.
- `verify_case`: Recheck source and preserved-output hashes.
- `done`: Return a summary, observations, hypotheses, and limitations with event citations.

## Current limits

- Tests use scripted responses and a fake `claude` executable. They do not test a production model provider.
- Recovered artifact content, prior-case retrieval, and autonomous host actions are not exposed.
- The model cannot run shell commands, issue arbitrary SQL, or leave the selected case and conversation scope.
- Result size, event count, transcript size, and model steps are bounded.
- Citations prove that referenced events exist. They do not prove the model's interpretation.

## Verify

```sh
python3 -m unittest discover -v -s tests -p 'test_*.py'
```
