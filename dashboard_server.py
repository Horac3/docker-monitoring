#!/usr/bin/env python3
"""
Minimal HTTP server for the Docker Monitor dashboard.
Serves dashboard.html and proxies /data/latest.json from the shared log volume.
"""
import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

LOG_DIR  = Path(os.getenv("LOG_DIR", "/var/log/docker-monitor"))
PORT     = int(os.getenv("DASHBOARD_PORT", "8080"))
APP_DIR  = Path("/app")


class DashboardHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence access logs; the monitor already logs to file

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._serve_file(APP_DIR / "dashboard.html", "text/html; charset=utf-8")
        elif self.path.startswith("/data/latest.json"):
            target = LOG_DIR / "latest.json"
            if target.exists():
                self._serve_file(target, "application/json")
            else:
                self._json_404()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_file(self, path: Path, content_type: str):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _json_404(self):
        body = json.dumps({"error": "snapshot not yet available"}).encode()
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"Dashboard running on http://0.0.0.0:{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), DashboardHandler).serve_forever()
