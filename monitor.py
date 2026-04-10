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

# ── Email rate limits ─────────────────────────────────────────────────────────
# Gmail free accounts: 500/day. Workspace: 2000/day.
# We default to 480 to stay safely under the 500 limit.
# Set EMAIL_DAILY_LIMIT=1900 if you're on Workspace.
EMAIL_DAILY_LIMIT  = int(os.getenv("EMAIL_DAILY_LIMIT",  "480"))
EMAIL_HOURLY_LIMIT = int(os.getenv("EMAIL_HOURLY_LIMIT", "40"))
# Warn when this fraction of the daily quota is used (default 80%)
EMAIL_QUOTA_WARN   = float(os.getenv("EMAIL_QUOTA_WARN", "0.80"))

LOG_LEVEL        = os.getenv("LOG_LEVEL",  "INFO").upper()
LOG_FILE         = os.getenv("LOG_FILE",   "/var/log/docker-monitor/monitor.log")
SNAPSHOT_PATH    = Path("/var/log/docker-monitor/latest.json")
ALERT_LOG_PATH   = Path("/var/log/docker-monitor/alerts.json")
EMAIL_QUOTA_PATH = Path("/var/log/docker-monitor/email_quota.json")
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
# EMAIL QUOTA  (persisted to disk — survives container restarts)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Structure of email_quota.json:
# {
#   "day":          "2025-04-10",   # UTC date — resets when date changes
#   "day_count":    12,             # emails sent today
#   "hour":         "2025-04-10T14", # UTC year-month-day-hour
#   "hour_count":   3,              # emails sent this hour
#   "quota_warned": false           # true once the 80% warning email fires
# }

def _load_quota() -> dict:
    try:
        return json.loads(EMAIL_QUOTA_PATH.read_text())
    except Exception:
        return {"day": "", "day_count": 0, "hour": "", "hour_count": 0, "quota_warned": False}


def _save_quota(q: dict) -> None:
    try:
        EMAIL_QUOTA_PATH.write_text(json.dumps(q, indent=2))
    except Exception as exc:
        log.error("Failed to save email quota: %s", exc)


def _quota_key_day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _quota_key_hour() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")


def _check_quota() -> tuple[bool, str]:
    """
    Returns (allowed, reason).
    allowed=True  → quota has room, proceed.
    allowed=False → quota exceeded, reason explains which limit was hit.
    Also resets stale windows and fires a warning email at EMAIL_QUOTA_WARN%.
    """
    q = _load_quota()
    now_day  = _quota_key_day()
    now_hour = _quota_key_hour()

    # Reset daily window when the UTC date rolls over
    if q["day"] != now_day:
        q["day"]          = now_day
        q["day_count"]    = 0
        q["quota_warned"] = False

    # Reset hourly window when the hour rolls over
    if q["hour"] != now_hour:
        q["hour"]       = now_hour
        q["hour_count"] = 0

    # Check limits BEFORE incrementing
    if q["day_count"] >= EMAIL_DAILY_LIMIT:
        resets_in = _seconds_until_midnight()
        reason = (
            f"Daily email limit reached ({q['day_count']}/{EMAIL_DAILY_LIMIT}). "
            f"Quota resets in {resets_in // 3600}h {(resets_in % 3600) // 60}m."
        )
        log.warning("EMAIL QUOTA: %s", reason)
        _save_quota(q)
        return False, reason

    if q["hour_count"] >= EMAIL_HOURLY_LIMIT:
        reason = (
            f"Hourly email limit reached ({q['hour_count']}/{EMAIL_HOURLY_LIMIT}). "
            f"Resets at the top of the next hour."
        )
        log.warning("EMAIL QUOTA: %s", reason)
        _save_quota(q)
        return False, reason

    # Increment counters
    q["day_count"]  += 1
    q["hour_count"] += 1
    _save_quota(q)

    # Fire a warning email when we cross EMAIL_QUOTA_WARN of the daily limit
    # (but only once per day — quota_warned flag prevents repeats)
    warn_threshold = int(EMAIL_DAILY_LIMIT * EMAIL_QUOTA_WARN)
    if not q["quota_warned"] and q["day_count"] >= warn_threshold:
        _send_quota_warning(q["day_count"], EMAIL_DAILY_LIMIT)
        q["quota_warned"] = True
        _save_quota(q)

    return True, ""


def _seconds_until_midnight() -> int:
    """Seconds until next UTC midnight."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int((tomorrow - now).total_seconds())


def _send_quota_warning(used: int, limit: int) -> None:
    """Send a one-time warning when approaching the daily quota."""
    pct = round(used / limit * 100)
    resets_in = _seconds_until_midnight()
    html = f"""
    <html><body style="background:#0d0d0d;color:#e0e0e0;font-family:sans-serif;padding:24px">
      <h2 style="color:#f59e0b">⚠ Email Quota Warning</h2>
      <p style="color:#888">{utcnow()}</p>
      <p>Resource Monitor has used <strong style="color:#f59e0b">{used} of {limit}</strong>
         emails today ({pct}% of daily quota).</p>
      <p>Further alerts will be suppressed once the limit is reached.<br>
         Quota resets in <strong>{resets_in // 3600}h {(resets_in % 3600) // 60}m</strong> (UTC midnight).</p>
      <p style="margin-top:16px">To adjust limits, set in your <code>.env</code>:<br>
         <code>EMAIL_DAILY_LIMIT=480</code> (current)<br>
         <code>EMAIL_HOURLY_LIMIT=40</code> (current)</p>
      <p style="color:#555;font-size:12px;margin-top:24px">Resource Monitor · automatic quota alert</p>
    </body></html>"""
    # Bypass the normal quota check — this warning must always get through
    ok, err = _smtp_send(f"⚠ Email quota at {pct}% — Resource Monitor", html)
    if ok:
        log.warning("Email quota warning sent (%d/%d used)", used, limit)
    else:
        log.error("Failed to send quota warning: %s", err)


def get_quota_status() -> dict:
    """Return current quota state for the snapshot (visible in dashboard)."""
    q = _load_quota()
    now_day  = _quota_key_day()
    now_hour = _quota_key_hour()
    day_count  = q["day_count"]  if q["day"]  == now_day  else 0
    hour_count = q["hour_count"] if q["hour"] == now_hour else 0
    return {
        "day_count":    day_count,
        "day_limit":    EMAIL_DAILY_LIMIT,
        "day_pct":      round(day_count / EMAIL_DAILY_LIMIT * 100, 1),
        "hour_count":   hour_count,
        "hour_limit":   EMAIL_HOURLY_LIMIT,
        "resets_in_s":  _seconds_until_midnight(),
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EMAIL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _smtp_send(subject: str, html: str) -> tuple[bool, str]:
    """
    Low-level send. Returns (success, error_message).
    Does NOT check quota — caller must gate through _check_quota() first.
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
    """
    Send an alert email, gated by quota and SMTP config checks.
    Returns True on successful delivery.
    Appends result to alerts.json regardless of outcome.
    """
    if not all([SMTP_USER, SMTP_PASS, ALERT_TO]):
        log.warning(
            "Email skipped — SMTP not fully configured. "
            "Set SMTP_USER, SMTP_PASS and ALERT_TO in your .env"
        )
        _append_alert_log(subject, "misconfigured",
                          "SMTP_USER/SMTP_PASS/ALERT_TO not set", alert_key)
        return False

    # Check quota before attempting to send
    allowed, reason = _check_quota()
    if not allowed:
        log.warning("Email suppressed (quota): %s", subject)
        _append_alert_log(subject, "quota_exceeded", reason, alert_key)
        return False

    ok, err = _smtp_send(subject, html)
    if ok:
        log.info("Email sent → %s  [%s]", ALERT_TO, subject)
        _append_alert_log(subject, "sent", "", alert_key)
    else:
        log.error("Email FAILED: %s", err)
        _append_alert_log(subject, "failed", err, alert_key)
        # If Gmail told us the daily limit is exceeded, mark quota as full
        # so we stop attempting until midnight rather than keep hitting SMTP
        if "Daily user sending limit exceeded" in err or "4.5.5" in err or "5.4.5" in err:
            log.error(
                "Gmail daily sending limit hit via SMTP response. "
                "Marking quota as exhausted until UTC midnight."
            )
            _exhaust_quota()
    return ok


def _exhaust_quota() -> None:
    """Force the daily counter to the limit so no more attempts are made today."""
    q = _load_quota()
    q["day"]       = _quota_key_day()
    q["day_count"] = EMAIL_DAILY_LIMIT
    _save_quota(q)


def test_email() -> None:
    """Send a startup test email so you know delivery works immediately."""
    if not all([SMTP_USER, SMTP_PASS, ALERT_TO]):
        log.warning("Startup email test skipped — SMTP not configured.")
        return
    log.info("Sending startup test email to %s …", ALERT_TO)
    q = get_quota_status()
    html = f"""
    <html><body style="background:#0d0d0d;color:#e0e0e0;font-family:sans-serif;padding:24px">
      <h2 style="color:#22d3a5">Resource Monitor — startup test</h2>
      <p>This email confirms that alert delivery is working correctly.</p>
      <p style="color:#888;font-size:12px">
        Started at {utcnow()}<br>
        Polling every {POLL_INTERVAL}s · Memory threshold {ALERT_THRESHOLD}%<br>
        Email quota: {q['day_count']}/{q['day_limit']} used today ·
        {q['hour_count']}/{q['hour_limit']} this hour
      </p>
    </body></html>"""
    # Test email bypasses quota — it's one email on startup, not an alert loop
    ok, err = _smtp_send("Resource Monitor started — email delivery test", html)
    if ok:
        # Count it against quota so the startup test is reflected accurately
        quota = _load_quota()
        today = _quota_key_day()
        if quota["day"] == today:
            quota["day_count"] += 1
        else:
            quota["day"] = today
            quota["day_count"] = 1
        _save_quota(quota)
        log.info("Startup test email delivered. Quota: %d/%d today.",
                 quota["day_count"], EMAIL_DAILY_LIMIT)
    else:
        log.error(
            "Startup test email FAILED: %s — alerts will not reach you "
            "until this is fixed.", err
        )


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
# PROCESS LIST
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# How many top processes to include in the snapshot
PROCESS_LIMIT = int(os.getenv("PROCESS_LIMIT", "60"))

def get_processes(container_names: set[str]) -> list[dict]:
    """
    Return the top PROCESS_LIMIT processes by CPU usage.
    Each entry includes whether it belongs to a known Docker container
    so the dashboard can offer a stop button for those.

    We call cpu_percent(interval=None) — non-blocking, uses the delta
    since the last call. The first call per-process always returns 0.0;
    subsequent polls return accurate values. This is intentional — we
    never block the poll loop for a CPU measurement interval.
    """
    procs = []
    total_ram = psutil.virtual_memory().total

    for p in psutil.process_iter([
        "pid", "name", "status", "cpu_percent",
        "memory_info", "memory_percent", "username", "cmdline",
    ]):
        try:
            info = p.info
            rss  = info["memory_info"].rss if info["memory_info"] else 0
            cmd  = " ".join(info["cmdline"] or []) if info["cmdline"] else info["name"] or ""
            # Truncate very long command lines
            if len(cmd) > 120:
                cmd = cmd[:117] + "..."

            # Check if this process name matches a running container name
            # Docker container processes typically appear as the container name
            # or as containerd-shim / docker-containerd entries referencing it
            is_docker = info["name"] in container_names

            procs.append({
                "pid":        info["pid"],
                "name":       info["name"] or "",
                "cmd":        cmd,
                "status":     info["status"] or "",
                "cpu_pct":    round(info["cpu_percent"] or 0.0, 2),
                "mem_pct":    round(info["memory_percent"] or 0.0, 2),
                "rss_mb":     b2mb(rss),
                "username":   info["username"] or "",
                "is_docker":  is_docker,
                "container_name": info["name"] if is_docker else None,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort by CPU descending, take top N
    procs.sort(key=lambda x: x["cpu_pct"], reverse=True)
    return procs[:PROCESS_LIMIT]
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

    # 3. Process list (all running processes, tagged with docker membership)
    container_names = {s["container_name"] for s in ct_stats}
    processes = get_processes(container_names)

    # 4. Service checks (reload config each poll — no restart needed)
    svc_configs = load_services()
    svc_results = run_service_checks(svc_configs) if svc_configs else []
    if svc_configs:
        alert_services(svc_results, svc_configs)

    # 5. Write snapshot
    snapshot = {
        "polled_at":    utcnow(),
        "containers":   ct_stats,
        "host":         host,
        "processes":    processes,
        "services":     svc_results,
        "email_quota":  get_quota_status(),
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