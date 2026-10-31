"""Two-request, one-endpoint proxy between ZAP and the vulnerable target."""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

LIMIT = 2
ORIGIN = "http://vulnerable-store-origin:8000"
PATH = "/scenarios/xss/search"
_lock = threading.Lock()
_forwarded = 0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl


_opener = urllib.request.build_opener(_NoRedirect)


class Handler(BaseHTTPRequestHandler):
    server_version = "mars-zap-gate"

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        global _forwarded
        parsed = urlsplit(self.path)
        if parsed.path == "/__mars__/status" and not parsed.query:
            with _lock:
                count = _forwarded
            self._send(200, json.dumps({"forwarded": count, "limit": LIMIT}).encode(),
                       "application/json")
            return
        try:
            query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            self._send(400, b"invalid query", "text/plain")
            return
        if parsed.path != PATH or set(query) != {"q"} or len(query["q"]) != 1:
            self._send(404, b"outside registered endpoint", "text/plain")
            return
        with _lock:
            if _forwarded >= LIMIT:
                self._send(429, b"registered request limit reached", "text/plain")
                return
            _forwarded += 1
        target = ORIGIN + parsed.path + "?q=" + quote(query["q"][0], safe="")
        request = urllib.request.Request(target, method="GET")
        try:
            with _opener.open(request, timeout=5) as response:
                body = response.read(65_537)
                if len(body) > 65_536:
                    raise RuntimeError("upstream response exceeded bound")
                self._send(response.status, body, response.headers.get_content_type())
        except urllib.error.HTTPError as exc:
            body = exc.read(65_537)
            if len(body) > 65_536:
                body = b"upstream error exceeded bound"
            self._send(exc.code, body, "text/plain")
        except (OSError, RuntimeError):
            self._send(502, b"registered upstream unavailable", "text/plain")


def main() -> None:
    if os.environ.get("MARS_ZAP_GATE_MODE") != "xss-reflection-001":
        raise SystemExit("fixed gate mode required")
    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
