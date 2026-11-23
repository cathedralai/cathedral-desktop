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

    def xdo(self, *args):
        self.receipts.append({"request_id": f"action-{len(self.receipts)}", "argv": list(args), "rc": 0})
        return "X=5\nY=6\n" if args and args[0] == "getmouselocation" else ""

    def step(self, *args):
        self.receipts.append({"request_id": f"step-{len(self.receipts)}", "argv": list(args), "rc": 0,
                              "settle_ms": getattr(self, "settle_ms", None)})
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

    def run_loop(self, responses, max_turns=1, extra=()):
        calls = iter(responses)
        client = types.SimpleNamespace(
            beta=types.SimpleNamespace(
                messages=types.SimpleNamespace(create=lambda **_kwargs: next(calls))
            )
        )
        args = [
            "cathedral_computer_use.py", "--sandbox", "test-room", "--task", "Look at the desktop",
            "--max-turns", str(max_turns), "--out", self.tmp.name, *extra,
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

    def test_computer_toolset_action_batch_then_end_turn(self):
        click = types.SimpleNamespace(
            type="tool_use", id="call-1", name="left_click", toolset_name="computer",
            input={"coordinate": [12, 34]},
        )
        screenshot = types.SimpleNamespace(
            type="tool_use", id="call-2", name="screenshot", toolset_name="computer", input={},
        )
        action = types.SimpleNamespace(stop_reason="tool_use", content=[click, screenshot])
        done = types.SimpleNamespace(stop_reason="end_turn", content=[])
        code, log = self.run_loop([action, done], max_turns=2)
        self.assertEqual(code, 0)
        self.assertTrue(log["complete"])
        self.assertEqual([item["request_id"] for item in log["execs"]], ["shot-0", "action-1", "shot-2"])
        self.assertEqual(log["execs"][1]["argv"], ["mousemove", 12, 34, "click", 1])

    def tool(self, call_id, name, **inp):
        return types.SimpleNamespace(type="tool_use", id=call_id, name=name, toolset_name="computer", input=inp)

    def shots_written(self):
        run_dir = next(Path(self.tmp.name).iterdir())
        return sorted(f.name for f in run_dir.glob("step-*.png"))

    def test_a_click_is_two_execs_by_default(self):
        """Unchanged behaviour without the flag: the input, then a separate screenshot."""
        turn = types.SimpleNamespace(stop_reason="tool_use", content=[self.tool("c1", "left_click", coordinate=[12, 34])])
        done = types.SimpleNamespace(stop_reason="end_turn", content=[])
        code, log = self.run_loop([turn, done], max_turns=2)
        self.assertEqual(code, 0)
        self.assertEqual([e["request_id"] for e in log["execs"]], ["shot-0", "action-1", "shot-2"])
        self.assertEqual(self.shots_written(), ["step-000.png", "step-001.png"])

    def test_one_call_steps_fuses_the_click_and_its_screenshot(self):
        turn = types.SimpleNamespace(stop_reason="tool_use", content=[self.tool("c1", "left_click", coordinate=[12, 34])])
        done = types.SimpleNamespace(stop_reason="end_turn", content=[])
        code, log = self.run_loop([turn, done], max_turns=2, extra=("--one-call-steps", "--settle-ms", "120"))
        self.assertEqual(code, 0)
        self.assertEqual([e["request_id"] for e in log["execs"]], ["shot-0", "step-1"])
        self.assertEqual(log["execs"][1]["argv"], ["mousemove", 12, 34, "click", 1])
        self.assertEqual(log["execs"][1]["settle_ms"], 120)
        # The fused screenshot is kept on disk like any other: the first look plus the step.
        self.assertEqual(self.shots_written(), ["step-000.png", "step-001.png"])

    def test_one_call_steps_fuses_only_the_last_input_of_a_turn(self):
        turn = types.SimpleNamespace(stop_reason="tool_use", content=[
            self.tool("c1", "mouse_move", coordinate=[1, 2]), self.tool("c2", "type", text="hi")])
        done = types.SimpleNamespace(stop_reason="end_turn", content=[])
        code, log = self.run_loop([turn, done], max_turns=2, extra=("--one-call-steps",))
        self.assertEqual(code, 0)
        self.assertEqual([e["request_id"] for e in log["execs"]], ["shot-0", "action-1", "step-2"])
        self.assertEqual(log["execs"][2]["argv"], ["type", "--delay", 12, "--", "hi"])

    def test_one_call_steps_leaves_actions_that_are_not_one_plain_input(self):
        """cursor_position reads xdotool's output and wait is no input: both keep the separate screenshot."""
        for name, inp, ids in (("cursor_position", {}, ["shot-0", "action-1", "shot-2"]), ("wait", {"duration": 0}, ["shot-0", "shot-1"])):
            with self.subTest(name=name):
                self.tmp.cleanup(); self.tmp = tempfile.TemporaryDirectory()
                turn = types.SimpleNamespace(stop_reason="tool_use", content=[self.tool("c1", name, **inp)])
                done = types.SimpleNamespace(stop_reason="end_turn", content=[])
                code, log = self.run_loop([turn, done], max_turns=2, extra=("--one-call-steps",))
                self.assertEqual(code, 0)
                self.assertEqual([e["request_id"] for e in log["execs"]], ids)

    def test_one_call_steps_with_a_screenshot_last_changes_nothing(self):
        turn = types.SimpleNamespace(stop_reason="tool_use", content=[
            self.tool("c1", "left_click", coordinate=[12, 34]), self.tool("c2", "screenshot")])
        done = types.SimpleNamespace(stop_reason="end_turn", content=[])
        code, log = self.run_loop([turn, done], max_turns=2, extra=("--one-call-steps",))
        self.assertEqual(code, 0)
        self.assertEqual([e["request_id"] for e in log["execs"]], ["shot-0", "action-1", "shot-2"])

    def test_a_failed_fused_step_is_reported_and_no_screenshot_is_attached(self):
        class FailingStep(FakeRoom):
            def step(self, *args):
                self.receipts.append({"request_id": f"step-{len(self.receipts)}", "argv": list(args), "rc": 3})
                raise RuntimeError("exec rc=3: step: the input failed")
        seen = {}
        def create(**kwargs):
            seen.setdefault("calls", []).append(list(kwargs["messages"]))  # a copy: the loop keeps appending
            return next(calls)
        turn = types.SimpleNamespace(stop_reason="tool_use", content=[self.tool("c1", "left_click", coordinate=[1, 1])])
        done = types.SimpleNamespace(stop_reason="end_turn", content=[])
        calls = iter([turn, done])
        client = types.SimpleNamespace(beta=types.SimpleNamespace(messages=types.SimpleNamespace(create=create)))
        args = ["cathedral_computer_use.py", "--sandbox", "r", "--task", "t", "--max-turns", "2", "--out", self.tmp.name, "--one-call-steps"]
        with patch.object(self.agent, "Room", FailingStep), patch.object(
            self.agent.anthropic, "Anthropic", return_value=client, create=True
        ), patch.object(sys, "argv", args):
            self.agent.main()
        result = seen["calls"][1][-1]["content"][0]
        self.assertTrue(result["is_error"])
        self.assertEqual([c["type"] for c in result["content"]], ["text"])  # the error, and no image
        self.assertEqual(self.shots_written(), ["step-000.png"])

    def test_settle_ms_out_of_range_is_refused(self):
        with self.assertRaises(SystemExit):
            self.run_loop([], extra=("--one-call-steps", "--settle-ms", "20000"))

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
