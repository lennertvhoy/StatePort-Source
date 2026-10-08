"""Two-instance HTTP fixture backed by a retained shared volume."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import json
import os


DATA = Path("/data/value.txt")
SERVICE_ID = os.environ.get("SERVICE_ID", "unknown")


class Handler(BaseHTTPRequestHandler):
    def _reply(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            DATA.parent.mkdir(parents=True, exist_ok=True)
            DATA.touch(exist_ok=True)
            self._reply(200, {"ok": True, "service": SERVICE_ID})
            return
        if parsed.path == "/value":
            self._reply(200, {"service": SERVICE_ID, "value": DATA.read_text() if DATA.exists() else ""})
            return
        if parsed.path == "/set":
            value = parse_qs(parsed.query).get("value", [""])[0][:128]
            DATA.write_text(value, encoding="utf-8")
            self._reply(200, {"stored": value})
            return
        self._reply(404, {"ok": False})

    def log_message(self, format: str, *args: object) -> None:
        print(f"{SERVICE_ID}: {format % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
