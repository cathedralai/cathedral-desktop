"""Evidence status must match the outcome of the computer-use loop."""

import base64
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "cathedral_computer_use.py"
PNG = base64.b64encode(
    base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
).decode()


class FakeRoom:
    def __init__(self, sandbox_id):
        self.id = sandbox_id
        self.receipts = []

    def screenshot(self):
        self.receipts.append({"request_id": f"shot-{len(self.receipts)}", "argv": ["shot"], "rc": 0})
        return PNG


class AgentLoopStatusTests(unittest.TestCase):
    def setUp(self):
        fake_anthropic = types.ModuleType("anthropic")
        with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
            spec = importlib.util.spec_from_file_location("cathedral_computer_use_test", SCRIPT)
            self.agent = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.agent)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_loop(self, responses, max_turns=1):
        calls = iter(responses)
        client = types.SimpleNamespace(
            beta=types.SimpleNamespace(
                messages=types.SimpleNamespace(create=lambda **_kwargs: next(calls))
            )
        )
        args = [
            "cathedral_computer_use.py", "--sandbox", "test-room", "--task", "Look at the desktop",
            "--max-turns", str(max_turns), "--out", self.tmp.name,
        ]
        with patch.object(self.agent, "Room", FakeRoom), patch.object(
            self.agent.anthropic, "Anthropic", return_value=client, create=True
        ), patch.object(sys, "argv", args):
            try:
                code = self.agent.main()
            except Exception as exc:
                code = exc
        run_dir = next(Path(self.tmp.name).iterdir())
        return code, json.loads((run_dir / "receipts.json").read_text())

    def test_end_turn_is_complete(self):
        response = types.SimpleNamespace(stop_reason="end_turn", content=[])
        code, log = self.run_loop([response])
        self.assertEqual(code, 0)
        self.assertTrue(log["complete"])
        self.assertEqual(log["outcome"], "done (end_turn)")

    def test_max_tokens_is_incomplete(self):
        response = types.SimpleNamespace(stop_reason="max_tokens", content=[])
        code, log = self.run_loop([response])
        self.assertEqual(code, 1)
        self.assertFalse(log["complete"])
        self.assertEqual(log["outcome"], "incomplete (max_tokens)")

    def test_turn_limit_is_incomplete(self):
        action = types.SimpleNamespace(type="tool_use", id="call-1", name="wait", input={"duration": 0})
        response = types.SimpleNamespace(stop_reason="tool_use", content=[action])
        code, log = self.run_loop([response])
        self.assertEqual(code, 1)
        self.assertFalse(log["complete"])
        self.assertEqual(log["outcome"], "max turns reached")

    def test_api_error_keeps_log_incomplete(self):
        def fail(**_kwargs):
            raise RuntimeError("model unavailable")

        client = types.SimpleNamespace(beta=types.SimpleNamespace(messages=types.SimpleNamespace(create=fail)))
        args = ["cathedral_computer_use.py", "--sandbox", "test-room", "--task", "Look", "--out", self.tmp.name]
        with patch.object(self.agent, "Room", FakeRoom), patch.object(
            self.agent.anthropic, "Anthropic", return_value=client, create=True
        ), patch.object(sys, "argv", args):
            with self.assertRaisesRegex(RuntimeError, "model unavailable"):
                self.agent.main()
        run_dir = next(Path(self.tmp.name).iterdir())
        log = json.loads((run_dir / "receipts.json").read_text())
        self.assertFalse(log["complete"])
        self.assertIn("model unavailable", log["outcome"])

    def test_missing_api_key_keeps_log_incomplete(self):
        args = ["cathedral_computer_use.py", "--sandbox", "test-room", "--task", "Look", "--out", self.tmp.name]
        with patch.object(self.agent, "Room", FakeRoom), patch.object(
            self.agent.anthropic, "Anthropic", side_effect=RuntimeError("missing API key"), create=True
        ), patch.object(sys, "argv", args):
            with self.assertRaisesRegex(RuntimeError, "missing API key"):
                self.agent.main()
        run_dir = next(Path(self.tmp.name).iterdir())
        log = json.loads((run_dir / "receipts.json").read_text())
        self.assertFalse(log["complete"])
        self.assertIn("missing API key", log["outcome"])


class ExecRequestLogTests(unittest.TestCase):
    def setUp(self):
        fake_anthropic = types.ModuleType("anthropic")
        with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
            spec = importlib.util.spec_from_file_location("cathedral_computer_use_exec_test", SCRIPT)
            self.agent = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.agent)

    def test_success_requires_ctcli_request_id(self):
        room = self.agent.Room("test-room")
        response = types.SimpleNamespace(returncode=0, stdout="ok", stderr="")
        with patch.object(self.agent.subprocess, "run", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "without an exec request id"):
                room.exec(["true"])
        self.assertIsNone(room.receipts[0]["request_id"])

    def test_logs_request_id_without_calling_it_a_receipt(self):
        room = self.agent.Room("test-room")
        response = types.SimpleNamespace(returncode=0, stdout="ok", stderr="ctcli: exec request id: exec-123\n")
        with patch.object(self.agent.subprocess, "run", return_value=response):
            self.assertEqual(room.exec(["true"]), "ok")
        self.assertEqual(room.receipts[0]["request_id"], "exec-123")


if __name__ == "__main__":
    unittest.main()
