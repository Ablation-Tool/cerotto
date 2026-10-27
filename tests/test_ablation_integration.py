#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from integration.ablation_cerotto.adapter import CerottoAdapter
from integration.ablation_cerotto.engine import InvestigationEngine, InvestigationError
from test_cerotto import agent_events, audit_lines

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CEROTTO_BIN", ROOT / "build" / "cerotto")).resolve()
ABLATION_REPO = os.environ.get("ABLATION_REPO", "/home/cowboy/_projects/ablation-standard")


def completion():
    return {
        "action": "done",
        "arguments": {
            "summary": "The evidence supports a tool call and subsequent host activity, not data exfiltration.",
            "observations": [{"description": "The agent gateway recorded a shell tool call.", "event_ids": ["evt-tool"]}],
            "hypotheses": [{"description": "Later host events may be related and need review.", "confidence": "low", "event_ids": ["evt-tool"]}],
            "limitations": ["An outbound connection alone does not establish transmitted content."],
        },
    }


class ScriptedTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, system, prompt, task, max_tokens):
        self.calls.append({"system": system, "prompt": prompt, "task": task, "max_tokens": max_tokens})
        if isinstance(self.responses[0], Exception):
            raise self.responses.pop(0)
        response = self.responses.pop(0)
        return SimpleNamespace(text=response if isinstance(response, str) else json.dumps(response))


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cerotto-ablation-test-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.db = self.root / "case.db"
        self.assertTrue(BINARY.is_file())
        self.cli("init", "--db", self.db)
        events = self.root / "events.jsonl"
        events.write_text("".join(json.dumps(event) + "\n" for event in agent_events()))
        self.cli("ingest", "--db", self.db, "--case", "incident-7", "--input", events)
        audit = self.root / "audit.log"
        audit.write_text("\n".join(audit_lines()) + "\n")
        self.cli("ingest-audit", "--db", self.db, "--case", "incident-7", "--input", audit, "--host", "agent-vm-1")

    def cli(self, *args, expected=0, env=None, timeout=30):
        environment = os.environ.copy()
        if env:
            environment.update(env)
        result = subprocess.run([str(BINARY), *map(str, args)], capture_output=True, text=True,
                                env=environment, timeout=timeout, cwd=self.root)
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def adapter(self):
        return CerottoAdapter(str(BINARY), str(self.db), "incident-7", "conv-7")

    def test_iterative_investigation_requests_evidence(self):
        transport = ScriptedTransport([
            {"action": "query_timeline", "arguments": {"limit": 50}},
            {"action": "get_event", "arguments": {"event_id": "evt-tool"}},
            {"action": "get_manifest", "arguments": {}},
            {"action": "verify_case", "arguments": {}},
            completion(),
        ])
        result = InvestigationEngine(self.adapter(), transport).run()
        self.assertTrue(result.finished, result.report)
        self.assertEqual(result.report["analysis"]["observations"][0]["event_ids"], ["evt-tool"])
        self.assertEqual([call["action"] for call in result.report["tool_calls"]],
                         ["query_timeline", "get_event", "get_manifest", "verify_case"])
        self.assertNotIn("evt-tool", transport.calls[0]["prompt"])
        self.assertIn("evt-tool", transport.calls[1]["prompt"])
        self.assertNotIn("CANARY_SECRET_DO_NOT_SEND", json.dumps(transport.calls))

    def test_scope_defaults_and_completion_requires_evidence(self):
        adapter = CerottoAdapter(
            str(BINARY), str(self.db), "incident-7", "conv-7",
            scope_host="agent-vm-1", scope_from="2026-10-27T11:59:00Z",
            scope_to="2026-10-27T12:05:00Z", default_limit=1,
        )
        timeline = adapter.query_timeline()
        self.assertEqual(len(timeline["events"]), 1)
        self.assertEqual(timeline["host_id"], "agent-vm-1")
        self.assertEqual(timeline["events"][0]["observed_at"], "2026-10-27T11:59:00.000000Z")
        with self.assertRaisesRegex(InvestigationError, "before query_timeline returns evidence"):
            InvestigationEngine(self.adapter(), ScriptedTransport([completion()])).run()

    def test_unknown_citation_and_out_of_scope_host_are_rejected(self):
        bad_completion = completion()
        bad_completion["arguments"]["observations"][0]["event_ids"] = ["invented-event"]
        with self.assertRaisesRegex(InvestigationError, "unknown event citations"):
            InvestigationEngine(self.adapter(), ScriptedTransport([
                {"action": "query_timeline", "arguments": {}}, bad_completion,
            ])).run()
        with self.assertRaisesRegex(InvestigationError, "outside the conversation evidence scope"):
            InvestigationEngine(self.adapter(), ScriptedTransport([
                {"action": "query_timeline", "arguments": {"host": "unrelated-host"}},
            ])).run()

    def test_repeated_action_is_unfinished(self):
        action = {"action": "query_timeline", "arguments": {}}
        result = InvestigationEngine(self.adapter(), ScriptedTransport([action, action])).run()
        self.assertFalse(result.finished)
        self.assertEqual(result.report["reason"], "repeated_action")
        self.assertEqual(len(result.report["tool_calls"]), 1)

    def test_malformed_action_unknown_event_and_transport_error(self):
        with self.assertRaisesRegex(InvestigationError, "not one JSON object"):
            InvestigationEngine(self.adapter(), ScriptedTransport(["not-json"])).run()
        with self.assertRaisesRegex(InvestigationError, "current investigation scope"):
            InvestigationEngine(self.adapter(), ScriptedTransport([
                {"action": "get_event", "arguments": {"event_id": "evt-tool"}},
            ])).run()
        with self.assertRaisesRegex(InvestigationError, "provider unavailable"):
            InvestigationEngine(self.adapter(), ScriptedTransport([RuntimeError("provider unavailable")])).run()

    def test_json_with_trailing_prose_and_unknown_action_are_rejected(self):
        class RawTransport:
            def __init__(self, text):
                self.text = text
            def complete(self, *args, **kwargs):
                return SimpleNamespace(text=self.text)
        with self.assertRaisesRegex(InvestigationError, "trailing prose"):
            InvestigationEngine(self.adapter(), RawTransport('{"action":"get_manifest","arguments":{}} trailing')).run()
        with self.assertRaisesRegex(InvestigationError, "unsupported action"):
            InvestigationEngine(self.adapter(), RawTransport('{"action":"shell","arguments":{}}')).run()

    @unittest.skipUnless(Path(ABLATION_REPO, "ablation/analyzers/llm_analyst/transport.py").is_file(), "Ablation checkout unavailable")
    def test_real_ablation_transport_cli_end_to_end(self):
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        counter = self.root / "counter"
        prompt_log = self.root / "prompts.log"
        actions = [
            {"action": "query_timeline", "arguments": {}},
            completion(),
        ]
        script = self.root / "responses.json"
        script.write_text(json.dumps(actions))
        fake = fake_bin / "claude"
        fake.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FAKE_ROOT'])
counter = root / 'counter'
index = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(index + 1))
actions = json.loads((root / 'responses.json').read_text())
prompt = sys.stdin.read()
with (root / 'prompts.log').open('a') as log:
    log.write(prompt + '\\n')
action = actions[min(index, len(actions) - 1)]
print(json.dumps([{'type':'result','result':json.dumps(action)}]))
""")
        fake.chmod(0o755)
        env = os.environ.copy()
        env.update({
            "PATH": f"{fake_bin}:{env['PATH']}",
            "ABLATION_REPO": ABLATION_REPO,
            "FAKE_ROOT": str(self.root),
            "PYTHONPATH": str(ROOT),
        })
        env.pop("ANTHROPIC_API_KEY", None)
        env.pop("CEROTTO_API_KEY", None)
        result = subprocess.run(
            [sys.executable, "-m", "integration.ablation_cerotto.cli", "investigate",
             "--db", str(self.db), "--case", "incident-7", "--conversation", "conv-7"],
            capture_output=True, text=True, env=env, timeout=60, cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["finished"])
        self.assertEqual(report["analysis"]["observations"][0]["event_ids"], ["evt-tool"])
        self.assertNotIn("CANARY_SECRET_DO_NOT_SEND", prompt_log.read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
