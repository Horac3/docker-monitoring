#!/usr/bin/env python3
"""
Dashboard server for Resource Monitor.
Serves the PWA and exposes /data/latest.json and /data/alerts.json.
"""
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

LOG_DIR  = Path(os.getenv("LOG_DIR", "/var/log/docker-monitor"))
PORT     = int(os.getenv("DASHBOARD_PORT", "8080"))
APP_DIR  = Path("/app")

MIME = {
    ".html": "text/html; charset=utf-8",
    ".json": "application/json",
    ".js":   "application/javascript",
    ".png":  "image/png",
    ".ico":  "image/x-icon",
    ".svg":  "image/svg+xml",
}

DATA_FILES = {
    "/data/latest.json": "latest.json",
    "/data/alerts.json": "alerts.json",
}

STATIC = {
    "/manifest.json":        "manifest.json",
    "/sw.js":                "sw.js",
    "/icons/icon-192.png":   "icons/icon-192.png",
    "/icons/icon-512.png":   "icons/icon-512.png",
    "/icons/screenshot.png": "icons/screenshot.png",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]

        # Live data endpoints
        if path in DATA_FILES:
            target = LOG_DIR / DATA_FILES[path]
            if target.exists():
                self._send(target.read_bytes(), "application/json", cache=False)
            else:
                self._send(
                    json.dumps({"error": "not yet available"}).encode(),
                    "application/json", status=404, cache=False
                )
            return

        # Dashboard root
        if path in ("/", "/index.html"):
            self._send_file(APP_DIR / "dashboard.html")
            return

        # Static PWA assets
        if path in STATIC:
            self._send_file(APP_DIR / STATIC[path])
            return

        self.send_response(404)
        self.end_headers()

    def _send_file(self, p: Path):
        if not p.exists():
            self.send_response(404); self.end_headers(); return
        mime = MIME.get(p.suffix, "application/octet-stream")
        self._send(p.read_bytes(), mime, cache=(p.name != "sw.js"))

    def _send(self, data: bytes, ct: str, status=200, cache=True):
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control",
                         "public, max-age=3600" if cache else "no-cache, no-store")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print(f"Dashboard running on http://0.0.0.0:{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()