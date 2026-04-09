# Docker Memory Monitor

A lightweight Docker container that continuously watches all running containers,
logs their memory usage, and emails you when memory spikes or exceeds a threshold.

## Quick Start

```bash
# 1. Clone / copy this folder onto your server
# 2. Set up credentials
cp .env.example .env
nano .env          # fill in SMTP_USER, SMTP_PASS, ALERT_TO

# 3. Build and run
docker compose up -d --build

# 4. Watch logs
docker compose logs -f
```

## How it works

```
Every POLL_INTERVAL seconds
  ├─ List all running containers
  ├─ Fetch memory stats for each (usage, RSS, limit, %)
  ├─ Log a summary line to stdout + /var/log/docker-monitor/monitor.log
  ├─ Write a JSON snapshot to /var/log/docker-monitor/latest.json
  └─ For each container:
       ├─ If usage% >= ALERT_THRESHOLD  → send email alert
       └─ If usage jumped >= SPIKE_DELTA in one cycle → send email alert
            (respects COOLDOWN_SECONDS to avoid spam)
```

## Environment Variables

| Variable           | Default           | Description                                      |
|--------------------|-------------------|--------------------------------------------------|
| `POLL_INTERVAL`    | `30`              | Seconds between polls                            |
| `ALERT_THRESHOLD`  | `80`              | % of memory limit that triggers an alert         |
| `SPIKE_DELTA`      | `20`              | % jump in one cycle that counts as a spike       |
| `COOLDOWN_SECONDS` | `300`             | Minimum seconds between alerts for same container|
| `SMTP_HOST`        | `smtp.gmail.com`  | SMTP server hostname                             |
| `SMTP_PORT`        | `587`             | SMTP port (587 = STARTTLS)                       |
| `SMTP_USER`        | *(required)*      | SMTP login / from address                        |
| `SMTP_PASS`        | *(required)*      | SMTP password or app password                    |
| `ALERT_TO`         | *(required)*      | Recipient email for alerts                       |
| `ALERT_FROM`       | same as SMTP_USER | Sender address                                   |
| `LOG_LEVEL`        | `INFO`            | Python log level (DEBUG, INFO, WARNING, ERROR)   |
| `LOG_FILE`         | see monitor.py    | Path inside the container for the log file       |

## Gmail Setup

1. Enable 2-Factor Authentication on your Google account
2. Go to **Google Account → Security → App Passwords**
3. Create an app password for "Mail"
4. Use that 16-character password as `SMTP_PASS`

## Reading the latest snapshot

```bash
docker exec docker-memory-monitor cat /var/log/docker-monitor/latest.json | python3 -m json.tool
```

## Containers without a memory limit

If a container has no `--memory` limit set, the "limit" shown is the total host RAM,
and `usage_pct` reflects % of host RAM. The threshold alert still applies.

## Notes

- The monitor mounts `/var/run/docker.sock` **read-only** — it cannot start/stop containers.
- Alerts have a per-container cooldown to prevent email floods.
- Tested on Docker Engine 24+ with cgroups v1 and v2.
