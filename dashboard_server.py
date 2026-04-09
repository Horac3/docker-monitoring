#!/usr/bin/env python3
"""
Dashboard server for Docker Resource Monitor.
Serves the PWA (dashboard.html, manifest.json, sw.js, icons/) and
proxies /data/latest.json from the shared log volume.
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


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence access logs

    def do_GET(self):
        path = self.path.split("?")[0]  # strip query string

        # ── Live data endpoint ──────────────────────────────────────────
        if path == "/data/latest.json":
            target = LOG_DIR / "latest.json"
            if target.exists():
                self._send(target.read_bytes(), "application/json", cache=False)
            else:
                self._send(
                    json.dumps({"error": "snapshot not yet available"}).encode(),
                    "application/json", status=404, cache=False
                )
            return

        # ── Root → dashboard ────────────────────────────────────────────
        if path in ("/", "/index.html"):
            self._send_file(APP_DIR / "dashboard.html")
            return

        # ── PWA files ───────────────────────────────────────────────────
        static_map = {
            "/manifest.json":       APP_DIR / "manifest.json",
            "/sw.js":               APP_DIR / "sw.js",
            "/icons/icon-192.png":  APP_DIR / "icons" / "icon-192.png",
            "/icons/icon-512.png":  APP_DIR / "icons" / "icon-512.png",
            "/icons/screenshot.png":APP_DIR / "icons" / "screenshot.png",
        }
        if path in static_map:
            self._send_file(static_map[path])
            return

        self.send_response(404)
        self.end_headers()

    def _send_file(self, path: Path):
        if not path.exists():
            self.send_response(404)
            self.end_headers()
            return
        mime = MIME.get(path.suffix, "application/octet-stream")
        # sw.js must not be cached — browsers won't pick up updates otherwise
        cache = path.suffix != ".js" or path.name != "sw.js"
        self._send(path.read_bytes(), mime, cache=cache)

    def _send(self, data: bytes, content_type: str, status=200, cache=True):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        if not cache:
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        else:
            self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print(f"Dashboard running on http://0.0.0.0:{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
