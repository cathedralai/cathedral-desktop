#!/usr/bin/env python3
"""Drive a Cathedral sealed desktop with Claude's computer toolset.

Every input action is one `ctcli sandbox exec` of xdotool and every screenshot is one exec of
`shot --b64`, so Cathedral signs a receipt for each step. Nothing from the room reaches the
model except the screenshots.

Usage:
  cathedral_computer_use.py --sandbox ID --task "Open a terminal and run uname -a" [--max-turns 40]
                            [--launch "browser https://cathedral.computer"] [--out runs]
Env:
  ANTHROPIC_API_KEY  Claude API key read by the Anthropic Python SDK
  CTCLI_CONFIG       optional ctcli login file for the room
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

import anthropic

MODEL = "claude-opus-5-5"
SYSTEM = (
    "You are operating a Linux desktop (openbox, 1280x800) inside a Cathedral sealed sandbox. "
    "Right-click the desktop background for a menu with a terminal. A browser may already be open. "
    "Work step by step. After each action take a screenshot and check the result before the next action. "
    "Use keyboard shortcuts when menus are awkward. When the task is done or impossible, say so and stop."
)
BUTTONS = {"left_click": 1, "middle_click": 2, "right_click": 3, "double_click": 1, "triple_click": 1}
REPEATS = {"double_click": 2, "triple_click": 3}
SCROLL_BUTTONS = {"up": 4, "down": 5, "left": 6, "right": 7}


class Room:
    """A sealed sandbox reached only through ctcli."""

    def __init__(self, sandbox_id: str):
        self.id = sandbox_id
        self.receipts: list[dict] = []

    def exec(self, argv: list, timeout: int = 40) -> str:
        cmd = ["ctcli", "sandbox", "exec", self.id, "--timeout", str(timeout), "--"] + [str(a) for a in argv]
        p = subprocess.run(cmd, capture_output=True, text=True)
        m = re.search(r"exec request id: (\S+)", p.stderr)
        self.receipts.append({"request_id": m.group(1) if m else None, "argv": [str(a) for a in argv], "rc": p.returncode})
        if p.returncode != 0:
            raise RuntimeError(f"exec rc={p.returncode}: {p.stderr.strip()[-300:]}")
        return p.stdout

    def xdo(self, *args) -> str:
        return self.exec(["env", "DISPLAY=:1", "xdotool", *args])

    def screenshot(self) -> str:
        """Base64 PNG of the whole display, in one receipted exec."""
        return self.exec(["shot", "--b64"]).strip()


def with_mods(mods: str | None, args: list) -> list:
    return ["keydown", mods, *args, "keyup", mods] if mods else args


def do_action(room: Room, name: str, inp: dict) -> str:
    """Run one toolset member. Returns 'image' when the caller must attach a screenshot, else text."""
    coord = inp.get("coordinate")
    if name == "screenshot":
        return "image"
    if name == "cursor_position":
        out = room.xdo("getmouselocation", "--shell")
        d = dict(line.split("=", 1) for line in out.split() if "=" in line)
        return f"X={d.get('X')}, Y={d.get('Y')}"
    if name in BUTTONS:
        args = ["mousemove", coord[0], coord[1]] if coord else []
        rep = REPEATS.get(name, 1)
        args += ["click"] + (["--repeat", rep, "--delay", 80] if rep > 1 else []) + [BUTTONS[name]]
        room.xdo(*with_mods(inp.get("text"), args))
        return "OK"
    if name == "left_click_drag":
        s, e = inp["start_coordinate"], inp["coordinate"]
        room.xdo(*with_mods(inp.get("text"), ["mousemove", s[0], s[1], "mousedown", 1, "mousemove", "--sync", e[0], e[1], "mouseup", 1]))
        return "OK"
    if name == "mouse_move":
        room.xdo("mousemove", coord[0], coord[1])
        return "OK"
    if name == "left_mouse_down":
        room.xdo("mousedown", 1)
        return "OK"
    if name == "left_mouse_up":
        room.xdo("mouseup", 1)
        return "OK"
    if name == "scroll":
        n = int(inp.get("scroll_amount", 3))
        args = (["mousemove", coord[0], coord[1]] if coord else []) + ["click", "--repeat", n, "--delay", 40, SCROLL_BUTTONS[inp["scroll_direction"]]]
        room.xdo(*with_mods(inp.get("text"), args))
        return "OK"
    if name == "type":
        room.xdo("type", "--delay", 12, "--", inp["text"])
        return "OK"
    if name == "key":
        room.xdo("key", "--repeat", int(inp.get("repeat", 1)), "--delay", 60, "--", inp["text"])
        return "OK"
    if name == "hold_key":
        d = min(float(inp["duration"]), 30)
        k = shlex.quote(inp["text"])
        room.exec(["bash", "-c", f"export DISPLAY=:1; xdotool keydown -- {k}; sleep {d}; xdotool keyup -- {k}"], timeout=int(d) + 10)
        return "OK"
    if name == "wait":
        time.sleep(min(float(inp.get("duration", 1)), 60))
        return "OK"
    raise ValueError(f"unsupported computer action: {name}")


def image_block(b64: str) -> dict:
    return {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": b64}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sandbox", required=True, help="sealed sandbox id with the desktop running")
    ap.add_argument("--task", required=True)
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--launch", action="append", default=[], help="command to start on the desktop first, e.g. 'browser https://example.com'")
    ap.add_argument("--out", default="runs", help="directory for screenshots and the receipt log")
    ap.add_argument("--model", default=MODEL)
    args = ap.parse_args()

    room = Room(args.sandbox)
    run_dir = Path(args.out) / dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir.mkdir(parents=True, exist_ok=True)
    shots = 0

    def snap() -> str:
        nonlocal shots
        b64 = room.screenshot()
        (run_dir / f"step-{shots:03d}.png").write_bytes(base64.b64decode(b64))
        shots += 1
        return b64

    outcome = "max turns reached"
    succeeded = False

    def write_log(complete: bool = False) -> None:
        # Written after every receipted action and once more at the end, so a run
        # that fails (model API error, screenshot failure, Ctrl-C) keeps its audit trail.
        (run_dir / "receipts.json").write_text(json.dumps(
            {"sandbox": room.id, "task": args.task, "outcome": outcome, "complete": complete,
             "execs": room.receipts}, indent=2))

    try:
        client = anthropic.Anthropic()
        for launch in args.launch:
            room.exec(["bash", "-c", f"export DISPLAY=:1; setsid {launch} >/dev/null 2>&1 < /dev/null &"])
            time.sleep(3)

        tools = [{"type": "computer_toolset_20260801", "configs": {"zoom": {"enabled": False}}}]
        messages = [{"role": "user", "content": [{"type": "text", "text": args.task}, image_block(snap())]}]
        for turn in range(1, args.max_turns + 1):
            resp = client.beta.messages.create(
                model=args.model,
                max_tokens=4096,
                system=SYSTEM,
                tools=tools,
                messages=messages,
                betas=["server-side-fallback-2026-07-01"],
                extra_body={"fallbacks": "default"},
            )
            messages.append({"role": "assistant", "content": resp.content})
            for b in resp.content:
                if b.type == "text" and b.text.strip():
                    print(f"[turn {turn}] claude: {b.text.strip()}")
            if resp.stop_reason == "refusal":
                outcome = f"refusal: {getattr(resp, 'stop_details', None)}"
                break
            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            if resp.stop_reason != "tool_use" or not tool_uses:
                succeeded = resp.stop_reason == "end_turn" and not tool_uses
                outcome = f"done ({resp.stop_reason})" if succeeded else f"incomplete ({resp.stop_reason})"
                break
            results, failed = [], False
            for tu in tool_uses:
                base = {"type": "tool_result", "tool_use_id": tu.id, "toolset_name": "computer"}
                if failed:
                    results.append({**base, "is_error": True, "content": "Not executed: an earlier computer action in this turn failed."})
                    continue
                inp = dict(tu.input or {})
                try:
                    prior_receipts = len(room.receipts)
                    r = do_action(room, tu.name, inp)
                    content = [image_block(snap())] if r == "image" else [{"type": "text", "text": r}]
                    results.append({**base, "content": content})
                    new_receipts = room.receipts[prior_receipts:]
                    receipt_ids = [entry["request_id"] for entry in new_receipts]
                    print(f"[turn {turn}] {tu.name} {json.dumps(inp)}  receipts {receipt_ids}")
                    write_log()
                except Exception as e:  # report to the model, stop the batch
                    failed = True
                    results.append({**base, "is_error": True, "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"[:500]}]})
                    print(f"[turn {turn}] {tu.name} failed: {e}", file=sys.stderr)
            if tool_uses[-1].name != "screenshot" and not failed:
                results[-1]["content"] = list(results[-1]["content"]) + [image_block(snap())]
            messages.append({"role": "user", "content": results})

    except BaseException as exc:
        outcome = f"error: {type(exc).__name__}: {exc}"[:300]
        raise
    finally:
        write_log(complete=succeeded)
    print(f"{outcome}; {len(room.receipts)} receipted execs, {shots} screenshots in {run_dir}")
    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
