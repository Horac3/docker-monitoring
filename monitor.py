#!/usr/bin/env python3
"""
Docker Memory Monitor
Monitors all running containers and sends email alerts on memory spikes.
"""

import os
import time
import json
import smtplib
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict

import docker

# ── Config from environment ──────────────────────────────────────────────────
POLL_INTERVAL     = int(os.getenv("POLL_INTERVAL", "30"))         # seconds
ALERT_THRESHOLD   = float(os.getenv("ALERT_THRESHOLD", "80"))     # % of limit
SPIKE_DELTA       = float(os.getenv("SPIKE_DELTA", "20"))         # % jump = spike
COOLDOWN_SECONDS  = int(os.getenv("COOLDOWN_SECONDS", "300"))     # 5 min between alerts

SMTP_HOST         = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT         = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASS", "")
ALERT_TO          = os.getenv("ALERT_TO", "")                     # recipient email
ALERT_FROM        = os.getenv("ALERT_FROM", SMTP_USER)

LOG_LEVEL         = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE          = os.getenv("LOG_FILE", "/var/log/docker-monitor/monitor.log")

# ── Logging setup ────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE),
    ],
)
log = logging.getLogger("docker-monitor")

# ── State ────────────────────────────────────────────────────────────────────
last_alert_time: dict[str, float] = defaultdict(float)
prev_usage_pct:  dict[str, float] = {}


def bytes_to_mb(b: int) -> float:
    return round(b / (1024 ** 2), 2)


def get_memory_stats(container) -> dict | None:
    """Pull memory stats from Docker stats stream (one-shot)."""
    try:
        stats = container.stats(stream=False)
        mem  = stats.get("memory_stats", {})
        usage = mem.get("usage", 0)
        limit = mem.get("limit", 0)

        # Docker subtracts cache from usage on cgroups v2
        cache = mem.get("stats", {}).get("cache", 0)
        rss   = usage - cache if cache else usage

        pct = (usage / limit * 100) if limit else 0.0

        return {
            "container_id":   container.short_id,
            "container_name": container.name,
            "usage_mb":       bytes_to_mb(usage),
            "rss_mb":         bytes_to_mb(rss),
            "limit_mb":       bytes_to_mb(limit) if limit else None,
            "usage_pct":      round(pct, 2),
            "timestamp":      datetime.utcnow().isoformat() + "Z",
        }
    except Exception as exc:
        log.warning("Could not get stats for %s: %s", container.name, exc)
        return None


def send_email(subject: str, body_html: str) -> None:
    if not all([SMTP_USER, SMTP_PASS, ALERT_TO]):
        log.warning("Email not configured — skipping alert. Set SMTP_USER, SMTP_PASS, ALERT_TO.")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = ALERT_FROM
    msg["To"]      = ALERT_TO
    msg.attach(MIMEText(body_html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(ALERT_FROM, ALERT_TO, msg.as_string())
        log.info("Alert email sent → %s", ALERT_TO)
    except Exception as exc:
        log.error("Failed to send email: %s", exc)


def build_alert_email(reason: str, stat: dict, all_stats: list[dict]) -> str:
    rows = ""
    for s in sorted(all_stats, key=lambda x: x["usage_pct"], reverse=True):
        limit_str = f"{s['limit_mb']} MB" if s["limit_mb"] else "unlimited"
        bar_pct   = min(s["usage_pct"], 100)
        bar_color = "#e74c3c" if s["usage_pct"] >= ALERT_THRESHOLD else "#2ecc71"
        rows += f"""
        <tr>
          <td style="padding:8px;border-bottom:1px solid #2d2d2d;font-family:monospace">{s['container_name']}</td>
          <td style="padding:8px;border-bottom:1px solid #2d2d2d">{s['usage_mb']} MB</td>
          <td style="padding:8px;border-bottom:1px solid #2d2d2d">{limit_str}</td>
          <td style="padding:8px;border-bottom:1px solid #2d2d2d">
            <div style="background:#1a1a1a;border-radius:4px;overflow:hidden;width:120px;height:14px">
              <div style="background:{bar_color};width:{bar_pct}%;height:100%"></div>
            </div>
            {s['usage_pct']}%
          </td>
        </tr>"""

    return f"""
    <html><body style="background:#0d0d0d;color:#e0e0e0;font-family:sans-serif;padding:24px">
      <h2 style="color:#e74c3c;margin-bottom:4px">⚠️ Docker Memory Alert</h2>
      <p style="color:#888;margin-top:0">{stat['timestamp']}</p>
      <p><strong style="color:#fff">Container:</strong>
         <code style="background:#1e1e1e;padding:2px 6px;border-radius:3px">{stat['container_name']}</code></p>
      <p><strong style="color:#fff">Reason:</strong> {reason}</p>
      <p><strong style="color:#fff">Current usage:</strong> {stat['usage_mb']} MB
         {"/ " + str(stat['limit_mb']) + " MB" if stat['limit_mb'] else "(no limit)"} —
         <strong style="color:#e74c3c">{stat['usage_pct']}%</strong></p>
      <hr style="border-color:#2d2d2d;margin:20px 0">
      <h3 style="color:#ccc">All Running Containers</h3>
      <table style="width:100%;border-collapse:collapse;background:#111">
        <thead>
          <tr style="background:#1e1e1e;color:#aaa;text-align:left">
            <th style="padding:8px">Container</th>
            <th style="padding:8px">Used</th>
            <th style="padding:8px">Limit</th>
            <th style="padding:8px">Usage %</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
      <p style="color:#555;font-size:12px;margin-top:24px">
        Docker Memory Monitor · Poll interval: {POLL_INTERVAL}s ·
        Alert threshold: {ALERT_THRESHOLD}% · Spike delta: {SPIKE_DELTA}%
      </p>
    </body></html>"""


def check_and_alert(stat: dict, all_stats: list[dict]) -> None:
    name = stat["container_name"]
    pct  = stat["usage_pct"]
    now  = time.time()

    reasons = []

    if pct >= ALERT_THRESHOLD:
        reasons.append(f"memory usage {pct}% exceeds threshold {ALERT_THRESHOLD}%")

    prev = prev_usage_pct.get(name)
    if prev is not None and (pct - prev) >= SPIKE_DELTA:
        reasons.append(f"spike detected: {prev}% → {pct}% (+{round(pct - prev, 1)}%)")

    prev_usage_pct[name] = pct

    if not reasons:
        return

    reason_str = " & ".join(reasons)

    if now - last_alert_time[name] < COOLDOWN_SECONDS:
        log.debug("Alert suppressed (cooldown) for %s: %s", name, reason_str)
        return

    last_alert_time[name] = now
    log.warning("ALERT %s — %s", name, reason_str)

    subject = f"🚨 Docker Memory Alert: {name} ({pct}%)"
    html    = build_alert_email(reason_str, stat, all_stats)
    send_email(subject, html)


def poll_once(client: docker.DockerClient) -> list[dict]:
    containers = client.containers.list()
    stats_list = []

    for c in containers:
        s = get_memory_stats(c)
        if s:
            stats_list.append(s)
            log.info(
                "%-30s  %7.1f MB  %5.1f%%",
                s["container_name"], s["usage_mb"], s["usage_pct"]
            )

    for s in stats_list:
        check_and_alert(s, stats_list)

    # Write a snapshot JSON for optional dashboard use
    snapshot_path = "/var/log/docker-monitor/latest.json"
    try:
        with open(snapshot_path, "w") as f:
            json.dump({"polled_at": datetime.utcnow().isoformat() + "Z", "containers": stats_list}, f, indent=2)
    except Exception:
        pass

    return stats_list


def main() -> None:
    log.info("Docker Memory Monitor starting up")
    log.info("Poll interval: %ss | Threshold: %s%% | Spike delta: %s%%",
             POLL_INTERVAL, ALERT_THRESHOLD, SPIKE_DELTA)

    try:
        client = docker.from_env()
        log.info("Connected to Docker daemon")
    except Exception as exc:
        log.critical("Cannot connect to Docker: %s", exc)
        raise SystemExit(1)

    while True:
        try:
            poll_once(client)
        except Exception as exc:
            log.error("Poll error: %s", exc)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
