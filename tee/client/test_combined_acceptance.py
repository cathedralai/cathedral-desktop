"""Runner acceptance/cleanup regressions; no SNP hardware or production launch."""
import asyncio
import contextlib
import io
import json
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

import combined_check as runner


class AcceptanceTests(unittest.TestCase):
    def run_count(self, count, extra_hosts=0):
        def box(name, opts, verify, binary, tampered, launch=None, box_host=None, index=0):
            return {"box": name, "tampered": tampered, "ms": {"boot": 1} if launch else {},
                    "ok": True, "detail": "measurement refused" if tampered else ""}
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'job'
            binary.write_bytes(b'fixture')
            output = Path(tmp) / 'result.json'
            args = ['--boxes', str(count), '--launch', 'unused', '--tampered-launch', 'unused',
                    '--measurement', 'ab' * 48, '--binary', str(binary), '--json-out', str(output)]
            for _ in range(extra_hosts):
                args += ['--box', 'unused']
            with patch.object(runner, 'check_box', side_effect=box), contextlib.redirect_stdout(io.StringIO()):
                rc = runner.main(args)
            return rc, json.loads(output.read_text())

    def test_one_boot_cannot_claim_ten_box_acceptance(self):
        rc, result = self.run_count(1)
        self.assertEqual(rc, 2)
        self.assertFalse(result['complete'])

    def test_nine_boots_plus_existing_host_are_incomplete(self):
        rc, result = self.run_count(9, extra_hosts=1)
        self.assertEqual(rc, 2)
        self.assertFalse(result['complete'])

    def test_ten_boots_and_measurement_refusal_complete(self):
        rc, result = self.run_count(10)
        self.assertEqual(rc, 0)
        self.assertTrue(result['complete'])

    def test_cleanup_after_shell_leader_exits(self):
        launched = runner.Launched('sleep 60 & echo CHILD:$!; exit 0')
        child = None
        try:
            line = launched.wait_for('CHILD:', time.monotonic() + 3)
            child = int(line.split(':')[1])
            self.assertEqual(launched.proc.wait(timeout=3), 0)
            launched.halt()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                status = Path(f'/proc/{child}/stat')
                if not status.exists() or status.read_text().split(') ', 1)[1].startswith('Z'):
                    break
                time.sleep(0.01)
            else:
                self.fail('background child survived halt after its leader exited')
            launched.halt()  # Idempotent: do not signal a later reused process group.
        finally:
            # Clean up even when running this regression against the old implementation.
            try:
                runner.os.killpg(launched.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            launched.proc.wait()
            launched.proc.stdout.close()


class DeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_connected_peer_never_sends_attest_times_out_and_closes(self):
        closed = asyncio.Event()

        async def peer(reader, writer):
            try:
                await reader.read()  # HELLO arrives, but we deliberately never answer.
            finally:
                writer.close()
                closed.set()

        server = await asyncio.start_server(peer, '127.0.0.1', 0)
        try:
            started = time.monotonic()
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(runner._attest_only('127.0.0.1', server.sockets[0].getsockname()[1],
                                                         timeout=0.05), 1)
            self.assertLess(time.monotonic() - started, 0.5)
            await asyncio.wait_for(closed.wait(), 1)
        finally:
            server.close()
            await server.wait_closed()

    async def test_connect_wait_is_inside_deadline(self):
        cancelled = asyncio.Event()

        async def stalled(*args):
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        started = time.monotonic()
        with patch.object(runner.asyncio, 'open_connection', side_effect=stalled):
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(runner._attest_only('unused', 1, timeout=0.05), 1)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(cancelled.is_set())

    async def test_valid_attest_exchange_still_returns_key_and_binding(self):
        from sealed_stream import read_frame, write_frame
        import base64

        async def peer(reader, writer):
            try:
                await read_frame(reader)
                write_frame(writer, json.dumps({'report': 'present', 'static': base64.urlsafe_b64encode(bytes(32)).decode().rstrip('='),
                                                'binding': 'binding'}).encode())
                await writer.drain()
            finally:
                writer.close()

        server = await asyncio.start_server(peer, '127.0.0.1', 0)
        try:
            result = await runner._attest_only('127.0.0.1', server.sockets[0].getsockname()[1])
            self.assertEqual(result, (bytes(32), 'binding'))
        finally:
            server.close()
            await server.wait_closed()


class SignalCleanupTests(unittest.TestCase):
    def test_sigterm_and_sighup_halt_the_launched_box(self):
        import subprocess
        import sys
        here = Path(__file__).resolve().parent
        # The launch and the pid line sit inside the try, as the launch does in combined_check.main.
        # They used to sit before it: a signal that landed between the print and the try raised
        # SystemExit with no finally around it, the box lived on, and this test failed about once
        # in 40 runs ("box survived signal 15") with nothing wrong in the code under test.
        script = (
            "import time, combined_check as r\n"
            "r._exit_on_signals()\n"
            "b = None\n"
            "try:\n"
            "    b = r.Launched('exec sleep 300')\n"
            "    print(b.proc.pid, flush=True)\n"
            "    time.sleep(60)\n"
            "finally:\n"
            "    if b is not None:\n"
            "        b.halt()\n"
        )
        for signum in (signal.SIGTERM, signal.SIGHUP):
            proc = subprocess.Popen([sys.executable, "-c", script], cwd=here, stdout=subprocess.PIPE, text=True)
            child = int(proc.stdout.readline())
            try:
                proc.send_signal(signum)
                proc.wait(timeout=10)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    stat = Path(f"/proc/{child}/stat")
                    if not stat.exists() or stat.read_text().split(") ", 1)[1].startswith("Z"):
                        break
                    time.sleep(0.02)
                else:
                    self.fail(f"box survived signal {signum}")
            finally:
                try:
                    runner.os.killpg(child, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.stdout.close()


if __name__ == '__main__':
    unittest.main()
