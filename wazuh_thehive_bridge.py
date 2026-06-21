#!/usr/bin/env python3
"""
wazuh_thehive_bridge.py

Tails Wazuh's local alerts.json log and forwards alerts above a configurable
rule-level threshold to TheHive as Alerts (not full Cases — analysts triage
and promote in TheHive's UI). This is a deliberately simple bridge for a lab:
no message queue, no retry-with-backoff persistence across restarts beyond
file-offset tracking, no dedup beyond Wazuh's own alert ID.

For production use, look at the official Wazuh-TheHive integration plugin
(integrations/custom-thehive.py shipped with Wazuh) which hooks the
integrator daemon instead of tailing files. This script is a transparent,
easy-to-modify alternative that's useful for understanding the data flow
end-to-end, which is the point of a home lab.

Environment variables (read from /opt/soc-stack/.env via systemd EnvironmentFile):
    THEHIVE_API_KEY     - org-level API key from TheHive (required)
    THEHIVE_URL         - default http://localhost:9000
    WAZUH_ALERTS_PATH   - default /var/ossec/logs/alerts/alerts.json
    MIN_ALERT_LEVEL     - default 7 (Wazuh rule level, 0-15 scale)
    POLL_INTERVAL       - default 2 seconds
"""
import json
import os
import sys
import time
import logging
import requests

THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://localhost:9000").rstrip("/")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "").strip()
ALERTS_PATH = os.environ.get("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
MIN_LEVEL = int(os.environ.get("MIN_ALERT_LEVEL", "7"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "2"))
OFFSET_FILE = "/opt/soc-stack/bridge/.alerts.offset"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("bridge")

SEVERITY_MAP = {
    range(0, 4):   1,   # low
    range(4, 7):   2,   # medium
    range(7, 12):  3,   # high
    range(12, 16): 4,   # critical
}


def severity_for_level(level: int) -> int:
    for r, sev in SEVERITY_MAP.items():
        if level in r:
            return sev
    return 2


def load_offset() -> int:
    try:
        with open(OFFSET_FILE) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def save_offset(pos: int) -> None:
    os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
    with open(OFFSET_FILE, "w") as f:
        f.write(str(pos))


def build_thehive_alert(wz: dict) -> dict:
    rule = wz.get("rule", {})
    agent = wz.get("agent", {})
    level = rule.get("level", 0)

    observables = []
    src_ip = wz.get("data", {}).get("srcip")
    if src_ip:
        observables.append({"dataType": "ip", "data": src_ip, "message": "source IP from Wazuh alert"})
    agent_name = agent.get("name")
    if agent_name:
        observables.append({"dataType": "other", "data": agent_name, "message": "Wazuh agent name"})

    return {
        "title": f"[Wazuh L{level}] {rule.get('description', 'Unnamed alert')}"[:200],
        "description": (
            f"Wazuh rule ID: {rule.get('id')}\n"
            f"Rule level: {level}\n"
            f"Agent: {agent_name} ({agent.get('id')})\n"
            f"Timestamp: {wz.get('timestamp')}\n"
            f"Full log:\n```\n{wz.get('full_log', '')[:2000]}\n```"
        ),
        "type": "wazuh",
        "source": "wazuh",
        "sourceRef": str(wz.get("id", wz.get("timestamp", time.time()))),
        "severity": severity_for_level(level),
        "tags": ["wazuh", f"rule:{rule.get('id')}", f"agent:{agent_name}"],
        "tlp": 2,
        "pap": 2,
        "observables": observables,
    }


def send_to_thehive(alert: dict) -> bool:
    url = f"{THEHIVE_URL}/api/v1/alert"
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(url, headers=headers, json=alert, timeout=10)
        if resp.status_code in (200, 201):
            return True
        log.warning("TheHive rejected alert (HTTP %s): %s", resp.status_code, resp.text[:300])
        return False
    except requests.RequestException as e:
        log.error("Could not reach TheHive at %s: %s", THEHIVE_URL, e)
        return False


def tail_alerts():
    if not THEHIVE_API_KEY:
        log.error("THEHIVE_API_KEY is not set. Set it with:")
        log.error("  /opt/soc-stack/deploy-soc-stack.sh set-hive-key <key>")
        sys.exit(1)

    log.info("Bridge starting. Watching %s for alerts >= level %d", ALERTS_PATH, MIN_LEVEL)
    log.info("Forwarding to %s", THEHIVE_URL)

    while not os.path.exists(ALERTS_PATH):
        log.warning("%s does not exist yet (Wazuh manager may still be starting). Retrying in 10s...", ALERTS_PATH)
        time.sleep(10)

    offset = load_offset()
    forwarded = 0
    skipped = 0

    with open(ALERTS_PATH, "r") as f:
        f.seek(offset)
        while True:
            line = f.readline()
            if not line:
                save_offset(f.tell())
                time.sleep(POLL_INTERVAL)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                wz_alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            level = wz_alert.get("rule", {}).get("level", 0)
            if level < MIN_LEVEL:
                skipped += 1
                continue

            alert = build_thehive_alert(wz_alert)
            if send_to_thehive(alert):
                forwarded += 1
                log.info("Forwarded alert: %s (level %d)", alert["title"], level)
            else:
                log.warning("Failed to forward alert (level %d), continuing", level)

            if (forwarded + skipped) % 50 == 0:
                save_offset(f.tell())


if __name__ == "__main__":
    try:
        tail_alerts()
    except KeyboardInterrupt:
        log.info("Bridge stopped.")
