#!/usr/bin/env python3
"""
Resource Monitor
Monitors Docker containers, host system stats, and arbitrary
external services (HTTP, TCP, process, ping).
Sends email alerts and writes a snapshot + alert log to disk.
"""

import os
import time
import json
import socket
import smtplib
import logging
import subprocess
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from pathlib import Path

import docker
import psutil
import requests
import yaml

# ── Config ────────────────────────────────────────────────────────────────────
POLL_INTERVAL    = int(os.getenv("POLL_INTERVAL",    "30"))
ALERT_THRESHOLD  = float(os.getenv("ALERT_THRESHOLD","80"))
SPIKE_DELTA      = float(os.getenv("SPIKE_DELTA",    "20"))
COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "300"))

SMTP_HOST        = os.getenv("SMTP_HOST",  "smtp.gmail.com")
SMTP_PORT        = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER        = os.getenv("SMTP_USER",  "")
SMTP_PASS        = os.getenv("SMTP_PASS",  "")
ALERT_TO         = os.getenv("ALERT_TO",   "")
ALERT_FROM       = os.getenv("ALERT_FROM", "") or SMTP_USER

LOG_LEVEL        = os.getenv("LOG_LEVEL",  "INFO").upper()
LOG_FILE         = os.getenv("LOG_FILE",   "/var/log/docker-monitor/monitor.log")
SNAPSHOT_PATH    = Path("/var/log/docker-monitor/latest.json")
ALERT_LOG_PATH   = Path("/var/log/docker-monitor/alerts.json")
SERVICES_FILE    = Path(os.getenv("SERVICES_FILE", "/etc/monitor/services.yml"))

# ── Logging ───────────────────────────────────────────────────────────────────
SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE),
    ],
)
log = logging.getLogger("monitor")

# ── State ─────────────────────────────────────────────────────────────────────
last_alert_time:  dict[str, float] = defaultdict(float)
prev_usage_pct:   dict[str, float] = {}
svc_fail_counts:  dict[str, int]   = defaultdict(int)
svc_last_alert:   dict[str, float] = defaultdict(float)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

def b2mb(b: int) -> float:
    return round(b / 1024 ** 2, 2)

def b2gb(b: int) -> float:
    return round(b / 1024 ** 3, 2)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EMAIL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _smtp_send(subject: str, html: str) -> tuple[bool, str]:
    """
    Low-level send. Returns (success, error_message).
    Does NOT check SMTP_USER/PASS — caller must validate.
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = ALERT_FROM
    msg["To"]      = ALERT_TO
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as srv:
            srv.ehlo()
            srv.starttls()
            srv.ehlo()
            srv.login(SMTP_USER, SMTP_PASS)
            srv.sendmail(ALERT_FROM, [ALERT_TO], msg.as_string())
        return True, ""
    except smtplib.SMTPAuthenticationError as e:
        return False, f"SMTP auth failed — check SMTP_USER/SMTP_PASS: {e}"
    except smtplib.SMTPRecipientsRefused as e:
        return False, f"Recipient refused — check ALERT_TO: {e}"
    except smtplib.SMTPConnectError as e:
        return False, f"Cannot connect to {SMTP_HOST}:{SMTP_PORT}: {e}"
    except TimeoutError:
        return False, f"SMTP connection timed out ({SMTP_HOST}:{SMTP_PORT})"
    except Exception as e:
        return False, str(e)


def send_email(subject: str, html: str, alert_key: str = "") -> bool:
    """Send email and append result to the alert log. Returns True on success."""
    if not all([SMTP_USER, SMTP_PASS, ALERT_TO]):
        log.warning(
            "Email skipped — SMTP not fully configured. "
            "Set SMTP_USER, SMTP_PASS and ALERT_TO in your .env"
        )
        _append_alert_log(subject, "misconfigured", "SMTP_USER/SMTP_PASS/ALERT_TO not set", alert_key)
        return False

    ok, err = _smtp_send(subject, html)
    if ok:
        log.info("Email sent → %s  subject: %s", ALERT_TO, subject)
        _append_alert_log(subject, "sent", "", alert_key)
    else:
        log.error("Email FAILED: %s", err)
        _append_alert_log(subject, "failed", err, alert_key)
    return ok


def test_email() -> None:
    """Send a startup test email so you know delivery works immediately."""
    if not all([SMTP_USER, SMTP_PASS, ALERT_TO]):
        log.warning("Startup email test skipped — SMTP not configured.")
        return
    log.info("Sending startup test email to %s …", ALERT_TO)
    html = f"""
    <html><body style="background:#0d0d0d;color:#e0e0e0;font-family:sans-serif;padding:24px">
      <h2 style="color:#22d3a5">Resource Monitor — startup test</h2>
      <p>This email confirms that alert delivery is working correctly.</p>
      <p style="color:#888;font-size:12px">Started at {utcnow()}<br>
      Polling every {POLL_INTERVAL}s · Memory threshold {ALERT_THRESHOLD}%</p>
    </body></html>"""
    ok, err = _smtp_send("Resource Monitor started — email delivery test", html)
    if ok:
        log.info("Startup test email delivered successfully.")
    else:
        log.error("Startup test email FAILED: %s  — alerts will not reach you until this is fixed.", err)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ALERT LOG  (persisted to disk so the dashboard shows real history)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MAX_ALERT_ENTRIES = 200

def _load_alert_log() -> list:
    try:
        return json.loads(ALERT_LOG_PATH.read_text())
    except Exception:
        return []

def _append_alert_log(subject: str, status: str, error: str, key: str) -> None:
    entries = _load_alert_log()
    entries.insert(0, {
        "time":    utcnow(),
        "subject": subject,
        "status":  status,   # sent | failed | suppressed | misconfigured
        "error":   error,
        "key":     key,
    })
    # Keep only the latest N entries
    entries = entries[:MAX_ALERT_ENTRIES]
    try:
        ALERT_LOG_PATH.write_text(json.dumps(entries, indent=2))
    except Exception as exc:
        log.error("Failed to write alert log: %s", exc)


def suppress_log(subject: str, key: str, cooldown_left: float) -> None:
    _append_alert_log(subject, "suppressed", f"cooldown {int(cooldown_left)}s remaining", key)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HOST STATS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_host_stats() -> dict:
    try:
        cpu_pct  = psutil.cpu_percent(interval=1)
        cpu_freq = psutil.cpu_freq()
        vm       = psutil.virtual_memory()
        swap     = psutil.swap_memory()
        disk     = psutil.disk_usage("/")
        disk_io  = psutil.disk_io_counters()
        net      = psutil.net_io_counters()
        load1, load5, load15 = psutil.getloadavg()

        return {
            "timestamp": utcnow(),
            "cpu": {
                "usage_pct":  round(cpu_pct, 1),
                "core_count": psutil.cpu_count(logical=True),
                "freq_mhz":   round(cpu_freq.current) if cpu_freq else None,
                "load_1m":    round(load1, 2),
                "load_5m":    round(load5, 2),
                "load_15m":   round(load15, 2),
            },
            "memory": {
                "total_mb":     b2mb(vm.total),
                "used_mb":      b2mb(vm.used),
                "available_mb": b2mb(vm.available),
                "usage_pct":    round(vm.percent, 1),
                "cached_mb":    b2mb(getattr(vm, "cached", 0)),
                "buffers_mb":   b2mb(getattr(vm, "buffers", 0)),
                "swap_total_mb": b2mb(swap.total),
                "swap_used_mb":  b2mb(swap.used),
                "swap_pct":      round(swap.percent, 1),
            },
            "disk": {
                "total_gb":  b2gb(disk.total),
                "used_gb":   b2gb(disk.used),
                "free_gb":   b2gb(disk.free),
                "usage_pct": round(disk.percent, 1),
                "read_mb":   b2mb(disk_io.read_bytes)  if disk_io else None,
                "write_mb":  b2mb(disk_io.write_bytes) if disk_io else None,
            },
            "network": {
                "bytes_sent_mb": b2mb(net.bytes_sent),
                "bytes_recv_mb": b2mb(net.bytes_recv),
                "packets_sent":  net.packets_sent,
                "packets_recv":  net.packets_recv,
                "err_in":        net.errin,
                "err_out":       net.errout,
            },
        }
    except Exception as exc:
        log.warning("Host stats error: %s", exc)
        return {}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONTAINER STATS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_container_stats(container) -> dict | None:
    try:
        stats = container.stats(stream=False)
        mem   = stats.get("memory_stats", {})
        usage = mem.get("usage", 0)
        limit = mem.get("limit", 0)
        cache = mem.get("stats", {}).get("cache", 0)
        rss   = usage - cache if cache else usage
        pct   = (usage / limit * 100) if limit else 0.0

        cpu_pct = 0.0
        try:
            cd = stats["cpu_stats"]
            pd = stats["precpu_stats"]
            cpu_delta    = cd["cpu_usage"]["total_usage"] - pd["cpu_usage"]["total_usage"]
            sys_delta    = cd["system_cpu_usage"] - pd["system_cpu_usage"]
            n_cpu        = cd.get("online_cpus") or len(cd["cpu_usage"].get("percpu_usage", [1]))
            if sys_delta > 0:
                cpu_pct = round((cpu_delta / sys_delta) * n_cpu * 100, 2)
        except (KeyError, ZeroDivisionError):
            pass

        net_stats  = stats.get("networks", {})
        net_rx = sum(v.get("rx_bytes", 0) for v in net_stats.values())
        net_tx = sum(v.get("tx_bytes", 0) for v in net_stats.values())

        blk = stats.get("blkio_stats", {}).get("io_service_bytes_recursive") or []
        blk_r = sum(x["value"] for x in blk if x.get("op") == "Read")
        blk_w = sum(x["value"] for x in blk if x.get("op") == "Write")

        return {
            "container_id":   container.short_id,
            "container_name": container.name,
            "usage_mb":       b2mb(usage),
            "rss_mb":         b2mb(rss),
            "limit_mb":       b2mb(limit) if limit else None,
            "usage_pct":      round(pct, 2),
            "cpu_pct":        cpu_pct,
            "net_rx_mb":      b2mb(net_rx),
            "net_tx_mb":      b2mb(net_tx),
            "blk_read_mb":    b2mb(blk_r),
            "blk_write_mb":   b2mb(blk_w),
            "timestamp":      utcnow(),
        }
    except Exception as exc:
        log.warning("Container stats error for %s: %s", container.name, exc)
        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SERVICE CHECKS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def load_services() -> list[dict]:
    if not SERVICES_FILE.exists():
        return []
    try:
        data = yaml.safe_load(SERVICES_FILE.read_text()) or {}
        svcs = data.get("services", [])
        return [s for s in svcs if s.get("enabled", True)]
    except Exception as exc:
        log.warning("Could not load %s: %s", SERVICES_FILE, exc)
        return []


def check_http(svc: dict) -> dict:
    url     = svc["url"]
    timeout = svc.get("timeout_ms", 5000) / 1000
    expect  = svc.get("expected_status", 200)
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "ResourceMonitor/1.0"})
        ok  = resp.status_code == expect
        return {
            "status":       "up" if ok else "degraded",
            "http_code":    resp.status_code,
            "response_ms":  round(resp.elapsed.total_seconds() * 1000),
            "error":        "" if ok else f"expected {expect}, got {resp.status_code}",
        }
    except requests.exceptions.SSLError as e:
        return {"status": "down", "http_code": None, "response_ms": None, "error": f"SSL error: {e}"}
    except requests.exceptions.ConnectionError as e:
        return {"status": "down", "http_code": None, "response_ms": None, "error": f"Connection refused: {e}"}
    except requests.exceptions.Timeout:
        return {"status": "down", "http_code": None, "response_ms": None, "error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"status": "down", "http_code": None, "response_ms": None, "error": str(e)}


def check_tcp(svc: dict) -> dict:
    host    = svc.get("host", "localhost")
    port    = int(svc["port"])
    timeout = svc.get("timeout_ms", 3000) / 1000
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return {"status": "up", "response_ms": round((time.monotonic()-t0)*1000), "error": ""}
    except (socket.timeout, TimeoutError):
        return {"status": "down", "response_ms": None, "error": f"TCP connect timed out ({host}:{port})"}
    except ConnectionRefusedError:
        return {"status": "down", "response_ms": None, "error": f"Connection refused ({host}:{port})"}
    except Exception as e:
        return {"status": "down", "response_ms": None, "error": str(e)}


def check_process(svc: dict) -> dict:
    name = svc.get("process_name", "")
    found = any(
        name.lower() in (p.name() or "").lower()
        for p in psutil.process_iter(["name"])
    )
    return {
        "status": "up" if found else "down",
        "error":  "" if found else f"No process matching '{name}' found",
    }


def check_ping(svc: dict) -> dict:
    host = svc.get("host", "8.8.8.8")
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True, timeout=5
        )
        ok = result.returncode == 0
        return {"status": "up" if ok else "down", "error": "" if ok else f"ping failed for {host}"}
    except Exception as e:
        return {"status": "down", "error": str(e)}


def run_service_checks(services: list[dict]) -> list[dict]:
    results = []
    for svc in services:
        name     = svc.get("name", "unknown")
        svc_type = svc.get("type", "http").lower()
        t0       = time.monotonic()

        if svc_type == "http":
            result = check_http(svc)
        elif svc_type in ("tcp", "port"):
            result = check_tcp(svc)
        elif svc_type == "process":
            result = check_process(svc)
        elif svc_type == "ping":
            result = check_ping(svc)
        else:
            result = {"status": "unknown", "error": f"unsupported type: {svc_type}"}

        entry = {
            "name":        name,
            "type":        svc_type,
            "status":      result.get("status", "unknown"),
            "response_ms": result.get("response_ms"),
            "http_code":   result.get("http_code"),
            "error":       result.get("error", ""),
            "tags":        svc.get("tags", []),
            "timestamp":   utcnow(),
        }
        results.append(entry)

        icon = "✓" if entry["status"] == "up" else "✗"
        log.info("SVC  %-30s  %-8s  %s%s",
                 name, entry["status"].upper(),
                 icon,
                 f"  {entry['response_ms']}ms" if entry["response_ms"] else "")
    return results


def alert_services(results: list[dict], svc_configs: list[dict]) -> None:
    """Fire email alerts for services that have failed enough consecutive times."""
    config_map = {s.get("name"): s for s in svc_configs}
    now = time.time()

    for r in results:
        name   = r["name"]
        cfg    = config_map.get(name, {})
        thresh = cfg.get("alert_after", 1)
        cool   = cfg.get("cooldown", COOLDOWN_SECONDS)

        if r["status"] == "up":
            if svc_fail_counts[name] > 0:
                log.info("SVC RECOVERED: %s", name)
                # Send recovery email
                subject = f"✓ RECOVERED: {name} is back up"
                html = _svc_email_html(name, r, recovered=True)
                send_email(subject, html, alert_key=f"svc:{name}")
            svc_fail_counts[name] = 0
            continue

        svc_fail_counts[name] += 1
        fails = svc_fail_counts[name]

        if fails < thresh:
            log.debug("SVC %s: %d/%d consecutive failures (not alerting yet)", name, fails, thresh)
            continue

        cooldown_left = svc_last_alert[name] + cool - now
        if cooldown_left > 0:
            log.debug("SVC alert suppressed for %s (cooldown %.0fs)", name, cooldown_left)
            suppress_log(f"Service down: {name}", f"svc:{name}", cooldown_left)
            continue

        svc_last_alert[name] = now
        log.warning("SVC ALERT: %s — %s", name, r["error"])
        subject = f"✗ SERVICE DOWN: {name} ({r['status'].upper()})"
        html    = _svc_email_html(name, r)
        send_email(subject, html, alert_key=f"svc:{name}")


def _svc_email_html(name: str, r: dict, recovered: bool = False) -> str:
    color   = "#22d3a5" if recovered else "#f87171"
    heading = "Service Recovered" if recovered else "Service Down"
    status  = r["status"].upper()
    detail  = ""
    if r.get("http_code"):
        detail += f"<p><strong>HTTP status:</strong> {r['http_code']}</p>"
    if r.get("response_ms"):
        detail += f"<p><strong>Response time:</strong> {r['response_ms']}ms</p>"
    if r.get("error"):
        detail += f"<p><strong>Error:</strong> <code>{r['error']}</code></p>"
    return f"""
    <html><body style="background:#0d0d0d;color:#e0e0e0;font-family:sans-serif;padding:24px">
      <h2 style="color:{color}">⚠ {heading}: {name}</h2>
      <p style="color:#888">{r['timestamp']}</p>
      <p><strong>Service:</strong> <code>{name}</code></p>
      <p><strong>Type:</strong> {r['type']}</p>
      <p><strong>Status:</strong> <span style="color:{color}">{status}</span></p>
      {detail}
      <p style="color:#555;font-size:12px;margin-top:24px">Resource Monitor · Poll: {POLL_INTERVAL}s</p>
    </body></html>"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONTAINER ALERTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_container_alert(stat: dict, all_stats: list[dict]) -> None:
    name = stat["container_name"]
    pct  = stat["usage_pct"]
    now  = time.time()
    reasons = []

    if pct >= ALERT_THRESHOLD:
        reasons.append(f"memory {pct}% ≥ threshold {ALERT_THRESHOLD}%")

    prev = prev_usage_pct.get(name)
    if prev is not None and (pct - prev) >= SPIKE_DELTA:
        reasons.append(f"spike {prev}% → {pct}% (+{round(pct-prev,1)}%)")

    prev_usage_pct[name] = pct
    if not reasons:
        return

    key = f"container:{name}"
    cooldown_left = last_alert_time[key] + COOLDOWN_SECONDS - now
    if cooldown_left > 0:
        log.debug("Container alert suppressed for %s (cooldown %.0fs)", name, cooldown_left)
        suppress_log(f"Container alert: {name} ({pct}%)", key, cooldown_left)
        return

    last_alert_time[key] = now
    reason_str = " & ".join(reasons)
    log.warning("CONTAINER ALERT %s — %s", name, reason_str)

    subject = f"🚨 Container Memory Alert: {name} ({pct}%)"
    html    = _container_alert_html(reason_str, stat, all_stats)
    send_email(subject, html, alert_key=key)


def _container_alert_html(reason: str, stat: dict, all_stats: list[dict]) -> str:
    rows = ""
    for s in sorted(all_stats, key=lambda x: x["usage_pct"], reverse=True):
        limit_str = f"{s['limit_mb']} MB" if s["limit_mb"] else "unlimited"
        bar_pct   = min(s["usage_pct"], 100)
        color     = "#f87171" if s["usage_pct"] >= ALERT_THRESHOLD else "#22d3a5"
        rows += f"""<tr>
          <td style="padding:8px;border-bottom:1px solid #2d2d2d;font-family:monospace">{s['container_name']}</td>
          <td style="padding:8px;border-bottom:1px solid #2d2d2d">{s['usage_mb']} MB</td>
          <td style="padding:8px;border-bottom:1px solid #2d2d2d">{limit_str}</td>
          <td style="padding:8px;border-bottom:1px solid #2d2d2d">
            <div style="background:#1a1a1a;border-radius:4px;overflow:hidden;width:120px;height:12px">
              <div style="background:{color};width:{bar_pct}%;height:100%"></div>
            </div> {s['usage_pct']}%
          </td>
        </tr>"""
    return f"""
    <html><body style="background:#0d0d0d;color:#e0e0e0;font-family:sans-serif;padding:24px">
      <h2 style="color:#f87171">🚨 Container Memory Alert</h2>
      <p style="color:#888">{stat['timestamp']}</p>
      <p><strong>Container:</strong> <code>{stat['container_name']}</code></p>
      <p><strong>Reason:</strong> {reason}</p>
      <p><strong>Usage:</strong> {stat['usage_mb']} MB
        {"/ "+str(stat['limit_mb'])+" MB" if stat['limit_mb'] else "(no limit)"} —
        <strong style="color:#f87171">{stat['usage_pct']}%</strong></p>
      <hr style="border-color:#2d2d2d;margin:20px 0">
      <h3>All Containers</h3>
      <table style="width:100%;border-collapse:collapse;background:#111">
        <thead><tr style="background:#1e1e1e;color:#aaa;text-align:left">
          <th style="padding:8px">Container</th><th style="padding:8px">Used</th>
          <th style="padding:8px">Limit</th><th style="padding:8px">%</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p style="color:#555;font-size:12px;margin-top:24px">
        Resource Monitor · Poll: {POLL_INTERVAL}s · Threshold: {ALERT_THRESHOLD}%
      </p>
    </body></html>"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HOST ALERTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HOST_CHECKS = [
    ("host:cpu",  lambda h: h["cpu"]["usage_pct"],      90,  "Host CPU above 90%"),
    ("host:mem",  lambda h: h["memory"]["usage_pct"],   90,  "Host RAM above 90%"),
    ("host:disk", lambda h: h["disk"]["usage_pct"],     85,  "Host disk above 85%"),
    ("host:swap", lambda h: h["memory"]["swap_pct"],    60,  "Host swap above 60%"),
]

def check_host_alerts(host: dict) -> None:
    if not host or not host.get("cpu"):
        return
    now = time.time()
    for key, getter, threshold, label in HOST_CHECKS:
        try:
            val = getter(host)
        except Exception:
            continue
        if val < threshold:
            continue
        cooldown_left = last_alert_time[key] + COOLDOWN_SECONDS - now
        if cooldown_left > 0:
            suppress_log(f"{label} ({val}%)", key, cooldown_left)
            continue
        last_alert_time[key] = now
        log.warning("HOST ALERT: %s = %.1f%%", label, val)
        subject = f"🖥 Host Alert: {label} ({val}%)"
        html = f"""
        <html><body style="background:#0d0d0d;color:#e0e0e0;font-family:sans-serif;padding:24px">
          <h2 style="color:#f59e0b">🖥 Host System Alert</h2>
          <p style="color:#888">{utcnow()}</p>
          <p><strong>Issue:</strong> {label}</p>
          <p><strong>Current value:</strong> <span style="color:#f87171">{val}%</span></p>
          <p style="color:#555;font-size:12px;margin-top:24px">Resource Monitor · Poll: {POLL_INTERVAL}s</p>
        </body></html>"""
        send_email(subject, html, alert_key=key)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POLL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def poll_once(client: docker.DockerClient) -> None:
    # 1. Container stats
    containers  = client.containers.list()
    ct_stats    = []
    for c in containers:
        s = get_container_stats(c)
        if s:
            ct_stats.append(s)
            log.info("CT   %-28s  mem:%6.1fMB (%5.1f%%)  cpu:%5.1f%%",
                     s["container_name"], s["usage_mb"], s["usage_pct"], s["cpu_pct"])
    for s in ct_stats:
        check_container_alert(s, ct_stats)

    # 2. Host stats
    host = get_host_stats()
    if host:
        log.info("HOST cpu:%.1f%%  mem:%.1f%%  disk:%.1f%%  swap:%.1f%%",
                 host["cpu"]["usage_pct"], host["memory"]["usage_pct"],
                 host["disk"]["usage_pct"], host["memory"]["swap_pct"])
        check_host_alerts(host)

    # 3. Service checks (reload config each poll — no restart needed)
    svc_configs = load_services()
    svc_results = run_service_checks(svc_configs) if svc_configs else []
    if svc_configs:
        alert_services(svc_results, svc_configs)

    # 4. Write snapshot
    snapshot = {
        "polled_at":  utcnow(),
        "containers": ct_stats,
        "host":       host,
        "services":   svc_results,
    }
    try:
        SNAPSHOT_PATH.write_text(json.dumps(snapshot, indent=2))
    except Exception as exc:
        log.error("Snapshot write failed: %s", exc)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main() -> None:
    log.info("Resource Monitor starting")
    log.info("Poll: %ss | Mem threshold: %s%% | Spike delta: %s%%",
             POLL_INTERVAL, ALERT_THRESHOLD, SPIKE_DELTA)
    log.info("SMTP: %s:%s | From: %s | To: %s",
             SMTP_HOST, SMTP_PORT, SMTP_USER or "(not set)", ALERT_TO or "(not set)")

    # Send a test email immediately so you know delivery works
    test_email()

    try:
        client = docker.from_env()
        log.info("Connected to Docker daemon")
    except Exception as exc:
        log.critical("Cannot connect to Docker daemon: %s", exc)
        raise SystemExit(1)

    while True:
        try:
            poll_once(client)
        except Exception as exc:
            log.error("Poll error: %s", exc)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()