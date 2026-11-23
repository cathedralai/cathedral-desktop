"""Isolated startup tests: temporary files, owned processes and loopback servers only."""
import contextlib
import http.server
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
loader = importlib.machinery.SourceFileLoader("desktop_supervise", str(HERE / "desktop-supervise"))
spec = importlib.util.spec_from_loader(loader.name, loader)
supervisor = importlib.util.module_from_spec(spec)
loader.exec_module(supervisor)


@contextlib.contextmanager
def server(handler):
    with socketserver.TCPServer(("127.0.0.1", 0), handler) as instance:
        thread = threading.Thread(target=instance.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield instance.server_address[1]
        finally:
            instance.shutdown()
            thread.join(timeout=2)


class Web(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"desktop page")

    def log_message(self, *_args):
        pass


class Rfb(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"RFB 003.")
        self.request.sendall(b"008\n")


class WrongService(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"not vnc")


class StartupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)
        self.state = self.work / "state"
        self.processes = []
        self.old_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}

    def tearDown(self):
        for sig, handler in self.old_handlers.items():
            signal.signal(sig, handler)
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        self.temp.cleanup()

    def child(self, script="import time; time.sleep(60)"):
        process = subprocess.Popen([sys.executable, "-c", script], start_new_session=True)
        self.processes.append(process)
        return process

    def link(self):
        url = "https://example.trycloudflare.com/#p=test-only"
        (self.work / "desktop.json").write_text(json.dumps({"url": url}))
        (self.work / "desktop-url.txt").write_text(url + "\n")

    def run_supervisor(self, pids, **kwargs):
        # Real signal/reap behavior with a shorter grace period for disposable children.
        shutdown = supervisor.shutdown
        with patch.object(supervisor, "shutdown", side_effect=lambda ps: shutdown(ps, grace=0.05)):
            return supervisor.supervise(pids, self.work, self.state, True,
                                        interval=0.005, startup_timeout=0.03, **kwargs)

    def test_readiness_requires_http_and_real_rfb_banner(self):
        with server(Web) as web, server(Rfb) as vnc:
            self.assertTrue(supervisor.local_ready(web, vnc))
        with server(Web) as web, server(WrongService) as vnc:
            self.assertFalse(supervisor.local_ready(web, vnc))

    def test_non_200_web_page_is_not_ready(self):
        class Missing(Web):
            def do_GET(self):
                self.send_error(404)
        with server(Missing) as web, server(Rfb) as vnc:
            self.assertFalse(supervisor.local_ready(web, vnc))

    def test_live_process_without_services_times_out_and_cleans_link(self):
        process = self.child()
        self.link()
        self.assertEqual(self.run_supervisor([process.pid], ready=lambda: False), 1)
        self.assertEqual(self.state.read_text(), "failed\n")
        self.assertFalse((self.work / "desktop.json").exists())
        self.assertFalse((self.work / "desktop-url.txt").exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(process.pid, 0)

    def test_missing_tunnel_url_cannot_report_ready(self):
        process = self.child()
        self.assertEqual(self.run_supervisor([process.pid], ready=lambda: True), 1)
        self.assertEqual(self.state.read_text(), "failed\n")

    def test_mismatched_link_files_cannot_report_ready(self):
        process = self.child()
        self.link()
        (self.work / "desktop-url.txt").write_text("stale")
        self.assertEqual(self.run_supervisor([process.pid], ready=lambda: True), 1)

    def test_exited_child_is_not_live_even_when_a_zombie(self):
        process = self.child("pass")
        deadline = time.monotonic() + 5
        while Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z":
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.005)
        self.assertFalse(supervisor.alive(process.pid))

    def test_shutdown_also_stops_a_child_before_setsid(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.processes.append(process)
        supervisor.shutdown([process.pid], grace=0.05)
        with self.assertRaises(ProcessLookupError):
            os.kill(process.pid, 0)

    def test_child_exit_after_ready_fails_and_stops_siblings(self):
        first, sibling = self.child(), self.child()
        self.link()
        seen = []
        real_sleep = time.sleep
        def sleep(_seconds):
            seen.append(self.state.read_text())
            if first.poll() is None:
                os.kill(first.pid, signal.SIGKILL)
                first.wait(timeout=2)
            else:
                real_sleep(_seconds)
        with patch.object(supervisor.time, "sleep", side_effect=sleep):
            # Stub only the grace sleep, retaining real termination/reaping.
            self.assertEqual(self.run_supervisor([first.pid, sibling.pid], ready=lambda: True), 1)
        self.assertIn("ready\n", seen)
        self.assertEqual(self.state.read_text(), "failed\n")
        with self.assertRaises(ProcessLookupError):
            os.kill(sibling.pid, 0)

    def test_stop_clears_readiness_and_link(self):
        process = self.child()
        self.link()
        def stopped():
            raise supervisor.Stopped()
        self.assertEqual(self.run_supervisor([process.pid], ready=stopped), 0)
        self.assertEqual(self.state.read_text(), "stopped\n")
        self.assertFalse((self.work / "desktop.json").exists())

    def test_shell_launch_preserves_child_ownership_through_exec(self):
        source = (HERE / "desktop-up").read_text()
        launch = source[source.index("CHILDREN=()"):source.index("foreground_cleanup()")]
        # Execute only the actual launch helper, never the host-mutating desktop script.
        script = launch + '''\nlaunch sleep 60
exec "$1" -c 'import os,signal,sys; p=int(sys.argv[1]); assert os.getpgid(p)==p; assert os.waitpid(p,os.WNOHANG)==(0,0); os.killpg(p,signal.SIGTERM); os.waitpid(p,0)' "${CHILDREN[0]}"
'''
        subprocess.run(["bash", "-c", script, "test", sys.executable], check=True, timeout=5)

    def test_sigterm_after_ready_stops_children_and_removes_link(self):
        self.link()
        harness = '''
import os, runpy, signal, subprocess, sys
from pathlib import Path
m=runpy.run_path(sys.argv[1])
p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'], start_new_session=True)
work=Path(sys.argv[2])
(work/'pid').write_text(str(p.pid))
signal.signal(signal.SIGTERM,m['stop'])
sys.exit(m['supervise']([p.pid],work,work/'state',True,ready=lambda:True,interval=0.01))
'''
        process = subprocess.Popen([sys.executable, "-c", harness,
                                    str(HERE / "desktop-supervise"), str(self.work)])
        self.processes.append(process)
        deadline = time.monotonic() + 5
        while not self.state.exists() or self.state.read_text() != "ready\n":
            self.assertIsNone(process.poll())
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        process.terminate()
        self.assertEqual(process.wait(timeout=5), 0)
        self.assertEqual(self.state.read_text(), "stopped\n")
        self.assertFalse((self.work / "desktop.json").exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(int((self.work / "pid").read_text()), 0)


if __name__ == "__main__":
    unittest.main()
