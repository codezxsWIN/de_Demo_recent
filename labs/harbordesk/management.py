"""Bounded network-management weaknesses: fictional data and in-memory state only."""

from __future__ import annotations

import threading

from labs.harbordesk.app import LAB_ID, Handler, LabServer

HOST = "127.0.0.1"
PORT = 8791
COMPARISON_PORT = 8792
SERVICE_ID = "harbordesk-management-v1"


class ManagementServer(LabServer):
    def __init__(self, address: tuple[str, int], handler: type[Handler]) -> None:
        self.policy_lock = threading.RLock()
        self.paused = False
        super().__init__(address, handler)


class ManagementHandler(Handler):
    server: ManagementServer
    comparison = False

    def authorized(self) -> bool:
        if self.comparison and self.headers.get_all("X-Lab-Access") != ["training-admin"]:
            self.reply(403, {"error": "Fixture administrator authorization required", "fixture": True})
            return False
        return True

    def do_GET(self) -> None:
        if not self.allowed():
            return
        path = self.path.partition("?")[0]
        if path == "/__lab__/health":
            self.reply(
                200,
                {
                    "lab_id": LAB_ID,
                    "service_id": SERVICE_ID,
                    "fixtures_only": True,
                    "binding": HOST,
                    "comparison": self.comparison,
                },
            )
            return
        if not self.authorized():
            return
        if path == "/":
            self.reply(
                200,
                '<!doctype html><html lang="en"><meta charset="utf-8">'
                "<title>HarborDesk training management</title>"
                "<h1>Local network management lab</h1>"
                "<p>Fictional backup and in-memory queue only. Never publish this service.</p>"
                '<p><a href="/backup">Read fictional backup</a> | '
                '<a href="/config">Read configuration</a> | '
                '<a href="/dispatch">Check dispatch response</a></p>'
                '<form method="post" action="/config">'
                '<button name="paused" value="true">Pause fictional queue</button> '
                '<button name="paused" value="false">Resume fictional queue</button></form>'
                "<p>Pause changes the dispatch response from 200 to 503. "
                "Resume restores it. No host service or real operation is controlled.</p></html>",
                "text/html",
            )
        elif path == "/backup":
            self.reply(200, {"backup": self.server.workspace.export(), "fixture": True})
        elif path == "/config":
            with self.server.policy_lock:
                self.reply(200, {"paused": self.server.paused, "fixture": True})
        elif path == "/dispatch":
            with self.server.policy_lock:
                self.reply(
                    503 if self.server.paused else 200,
                    {
                        "dispatch": "paused" if self.server.paused else "ready",
                        "scope": "fictional in-memory queue; no real operations",
                        "fixture": True,
                    },
                )
        else:
            self.reply(404, {"error": "Unknown training management route", "fixture": True})

    def do_POST(self) -> None:
        if not self.allowed():
            return
        origin = self.headers.get("Origin")
        if origin and origin != f"http://{HOST}:{self.server.server_address[1]}":
            self.reply(403, {"error": "Cross-origin management writes refused", "fixture": True})
            return
        if not self.authorized():
            return
        if self.path.partition("?")[0] != "/config":
            self.reply(404, {"error": "Unknown training management route", "fixture": True})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 512 or self.headers.get("Transfer-Encoding"):
                raise ValueError("Expected a bounded form body")
            form = self.rfile.read(length).decode("ascii")
            if form not in ("paused=true", "paused=false"):
                raise ValueError("Only paused=true or paused=false is permitted")
        except (ValueError, UnicodeError) as error:
            self.reply(400, {"error": str(error), "fixture": True})
            return
        # INTENTIONAL missing authorization on the vulnerable service, never host control.
        with self.server.policy_lock:
            self.server.paused = form == "paused=true"
            self.reply(200, {"paused": self.server.paused, "fixture": True})


class ProtectedManagementHandler(ManagementHandler):
    comparison = True


class ManagementLab:
    """Own the fixed loopback listeners; never execute commands or contact other hosts."""

    def __init__(self) -> None:
        self._servers: list[ManagementServer] = []
        self._workers: list[tuple[ManagementServer, threading.Thread]] = []

    def __enter__(self) -> ManagementLab:
        try:
            for port, handler in (
                (PORT, ManagementHandler),
                (COMPARISON_PORT, ProtectedManagementHandler),
            ):
                self._servers.append(ManagementServer((HOST, port), handler))
            for server in self._servers:
                worker = threading.Thread(
                    target=server.serve_forever,
                    kwargs={"poll_interval": 0.05},
                    daemon=True,
                )
                worker.start()
                self._workers.append((server, worker))
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        for server, worker in self._workers:
            server.shutdown()
            worker.join()
        self._workers.clear()
        for server in self._servers:
            server.server_close()
        self._servers.clear()

    def __exit__(self, *_args: object) -> None:
        self.close()
