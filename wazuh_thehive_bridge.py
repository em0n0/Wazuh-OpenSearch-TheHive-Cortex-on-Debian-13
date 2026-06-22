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

    N8N_WEBHOOK_URL     - if set, alerts at/above N8N_MIN_LEVEL are ALSO
                          POSTed here as clean JSON, in parallel with the
                          direct TheHive alert above. Leave unset to disable.
    N8N_MIN_LEVEL       - default 10 (Wazuh rule level). This is the SOAR
                          escalation threshold: high-severity alerts get
                          routed through the n8n workflow for case creation,
                          tagging, and triage assignment, on top of (not
                          instead of) the plain TheHive alert this bridge
                          already creates for every alert >= MIN_ALERT_LEVEL.

This bridge intentionally keeps its own TheHive-alert path even when n8n is
configured. The bridge's direct path is the reliable, always-on record of
every alert that crosses MIN_ALERT_LEVEL. n8n's job is orchestration on top
of that: deciding which of those alerts also warrant a full Case, how it
gets tagged, and who/what it's routed to. If n8n is down, restarting, or
mid-workflow-edit, you still don't lose alert visibility in TheHive.
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

N8N_WEBHOOK_URL = os.environ.get("N8N_WEBHOOK_URL", "").strip()
N8N_MIN_LEVEL = int(os.environ.get("N8N_MIN_LEVEL", "10"))

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


def build_n8n_payload(wz: dict) -> dict:
    """
    Clean, flat JSON for n8n to branch on. Deliberately not the same shape
    as the TheHive alert payload above — n8n shouldn't need to know
    anything about TheHive's schema to make routing decisions; that
    translation happens inside the n8n workflow itself.
    """
    rule = wz.get("rule", {})
    agent = wz.get("agent", {})
    data = wz.get("data", {})
    level = rule.get("level", 0)

    return {
        "source": "wazuh",
        "wazuh_alert_id": str(wz.get("id", "")),
        "timestamp": wz.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": level,
        "rule_description": rule.get("description", "Unnamed alert"),
        "rule_groups": rule.get("groups", []),
        "rule_mitre_ids": rule.get("mitre", {}).get("id", []),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "src_ip": data.get("srcip"),
        "dst_ip": data.get("dstip"),
        "full_log": (wz.get("full_log", "") or "")[:2000],
    }


def send_to_n8n(payload: dict) -> bool:
    if not N8N_WEBHOOK_URL:
        return False
    try:
        resp = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code in (200, 201, 202):
            return True
        log.warning("n8n webhook rejected payload (HTTP %s): %s", resp.status_code, resp.text[:300])
        return False
    except requests.RequestException as e:
        # n8n being unreachable should never block the TheHive path above —
        # log and move on.
        log.error("Could not reach n8n at %s: %s", N8N_WEBHOOK_URL, e)
        return False


def tail_alerts():
    if not THEHIVE_API_KEY:
        log.error("THEHIVE_API_KEY is not set. Set it with:")
        log.error("  /opt/soc-stack/deploy-soc-stack.sh set-hive-key <key>")
        sys.exit(1)

    log.info("Bridge starting. Watching %s for alerts >= level %d", ALERTS_PATH, MIN_LEVEL)
    log.info("Forwarding to %s", THEHIVE_URL)
    if N8N_WEBHOOK_URL:
        log.info("Also forwarding alerts >= level %d to n8n at %s", N8N_MIN_LEVEL, N8N_WEBHOOK_URL)
    else:
        log.info("N8N_WEBHOOK_URL not set; n8n SOAR forwarding is disabled.")

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

            if N8N_WEBHOOK_URL and level >= N8N_MIN_LEVEL:
                n8n_payload = build_n8n_payload(wz_alert)
                if send_to_n8n(n8n_payload):
                    log.info("Routed alert to n8n SOAR workflow: %s (level %d)", n8n_payload["rule_description"], level)
                else:
                    log.warning("n8n routing failed for level %d alert (TheHive alert above was still created)", level)

            if (forwarded + skipped) % 50 == 0:
                save_offset(f.tell())


if __name__ == "__main__":
    try:
        tail_alerts()
    except KeyboardInterrupt:
        log.info("Bridge stopped.")
