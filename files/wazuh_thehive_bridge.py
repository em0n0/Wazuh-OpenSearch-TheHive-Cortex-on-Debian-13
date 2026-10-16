#!/usr/bin/env python3
"""
wazuh_thehive_bridge.py  —  v2.0

Tails Wazuh's alerts.json and forwards alerts at or above MIN_ALERT_LEVEL
to TheHive as Alerts via the v1 API.

Environment variables (loaded via systemd EnvironmentFile from /opt/soc-stack/.env):
    THEHIVE_API_KEY     API key for a TheHive org-level user (required)
                        MUST be an org-level user with analyst or org-admin profile.
                        NOT the platform superadmin (admin@thehive.local).
                        401 = wrong/expired key
                        403 = wrong org, wrong profile, or platform superadmin key
    THEHIVE_URL         TheHive base URL (default: http://localhost:9000)
    WAZUH_ALERTS_PATH   Path to Wazuh alerts log (default: /var/ossec/logs/alerts/alerts.json)
    MIN_ALERT_LEVEL     Minimum Wazuh rule level to forward (default: 7, range 0-15)
    POLL_INTERVAL       Seconds between polls when no new data (default: 2)
    N8N_WEBHOOK_URL     Optional. If set, alerts at/above N8N_MIN_LEVEL are also POSTed
                        to this n8n webhook (the workflow sends the email). Independent
                        of TheHive: an n8n outage never blocks TheHive and vice versa.
    N8N_MIN_LEVEL       Minimum Wazuh level to notify via n8n (default: 10, range 1-15)

Offset tracking:
    Read position is saved to /opt/soc-stack/bridge/.alerts.offset so the bridge
    resumes where it left off after a restart. Delete this file to reset to the
    current end of the log (useful after testing or log rotation).
"""
import json
import os
import sys
import time
import logging
import requests
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────────────────
THEHIVE_URL     = os.environ.get("THEHIVE_URL", "http://localhost:9000").rstrip("/")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "").strip()
ALERTS_PATH     = os.environ.get("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
MIN_LEVEL       = int(os.environ.get("MIN_ALERT_LEVEL", "7"))
POLL_INTERVAL   = float(os.environ.get("POLL_INTERVAL", "2"))
OFFSET_FILE     = "/opt/soc-stack/bridge/.alerts.offset"
N8N_URL         = os.environ.get("N8N_WEBHOOK_URL", "").strip()
N8N_MIN_LEVEL   = int(os.environ.get("N8N_MIN_LEVEL", "10"))

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("bridge")

# ── Severity mapping (Wazuh level 0-15 -> TheHive severity 1-4) ─────────────
def severity_for_level(level: int) -> int:
    if level < 4:  return 1  # low
    if level < 7:  return 2  # medium
    if level < 12: return 3  # high
    return 4                 # critical

# ── Offset tracking ──────────────────────────────────────────────────────────
def load_offset() -> tuple:
    """Returns (offset, file_existed)"""
    try:
        with open(OFFSET_FILE) as f:
            return int(f.read().strip()), True
    except FileNotFoundError:
        return 0, False
    except ValueError:
        return 0, True

def save_offset(pos: int) -> None:
    os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
    with open(OFFSET_FILE, "w") as f:
        f.write(str(pos))

# ── Build TheHive alert payload ──────────────────────────────────────────────
def build_alert(wz: dict) -> dict:
    rule  = wz.get("rule", {})
    agent = wz.get("agent", {})
    level = rule.get("level", 0)

    observables = []
    src_ip = wz.get("data", {}).get("srcip")
    if src_ip:
        observables.append({
            "dataType": "ip",
            "data": src_ip,
            "message": "source IP from Wazuh alert"
        })
    data = wz.get("data", {}) or {}
    seen = {src_ip} if src_ip else set()
    # Suricata eve.json events use src_ip / dest_ip
    for key, label in (("src_ip", "Suricata source IP"), ("dest_ip", "Suricata destination IP")):
        v = data.get(key)
        if v and v not in seen:
            seen.add(v)
            observables.append({"dataType": "ip", "data": v, "message": label})
    # Kismet WIPS events (soc-wips exporter)
    wips = data.get("wips") or {}
    for key, dtype, label in (("ssid", "other", "WIPS SSID"), ("bssid", "other", "WIPS BSSID"),
                              ("src_mac", "other", "WIPS source MAC")):
        v = wips.get(key)
        if v:
            observables.append({"dataType": dtype, "data": str(v), "message": label})
    extra_tags = []
    sig = (data.get("alert") or {}).get("signature")
    if sig:
        extra_tags.append("suricata")
        if (data.get("alert") or {}).get("action") == "blocked":
            extra_tags.append("ips-blocked")
    if wips:
        extra_tags += ["wips", f"wips:{wips.get('type', 'unknown')}"]
    agent_name = agent.get("name", "unknown")
    if agent_name and agent_name != "unknown":
        observables.append({
            "dataType": "other",
            "data": agent_name,
            "message": "Wazuh agent name"
        })

    return {
        "title":       f"[Wazuh L{level}] {rule.get('description', 'Unnamed alert')}"[:200],
        "description": (
            f"**Wazuh Rule:** {rule.get('id')} — {rule.get('description')}\n"
            f"**Level:** {level}\n"
            f"**Agent:** {agent_name} (ID: {agent.get('id', 'N/A')})\n"
            f"**Timestamp:** {wz.get('timestamp')}\n\n"
            f"**Full log:**\n```\n{wz.get('full_log', '')[:2000]}\n```"
        ),
        "type":        "wazuh",
        "source":      "wazuh",
        "sourceRef":   str(wz.get("id", wz.get("timestamp", time.time()))),
        "severity":    severity_for_level(level),
        "tags":        ["wazuh", f"rule:{rule.get('id')}", f"level:{level}", f"agent:{agent_name}"] + extra_tags,
        "tlp":         2,
        "pap":         2,
        "observables": observables,
    }

# ── Send to TheHive ──────────────────────────────────────────────────────────
def send_alert(alert: dict) -> bool:
    url     = f"{THEHIVE_URL}/api/v1/alert"
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type":  "application/json",
    }
    try:
        resp = requests.post(url, headers=headers, json=alert, timeout=10)
        if resp.status_code in (200, 201):
            return True
        if resp.status_code == 401:
            log.error(
                "TheHive returned 401 Unauthorized. The API key is wrong or expired.\n"
                "  Fix: sudo ./deploy-soc-stack.sh set-hive-key <new-key>"
            )
        elif resp.status_code == 403:
            log.error(
                "TheHive returned 403 Forbidden: %s\n"
                "  This means the API key belongs to a user who cannot create alerts.\n"
                "  Common causes:\n"
                "    - Key belongs to the platform superadmin (admin@thehive.local) — use an org-level user instead\n"
                "    - User profile is 'read-only' — change to 'analyst' or 'org-admin' in TheHive\n"
                "    - User is in a different organisation than expected\n"
                "  Fix: In TheHive → your org → Users → check the user's profile is analyst/org-admin",
                resp.text[:300]
            )
        else:
            log.warning("TheHive rejected alert (HTTP %s): %s", resp.status_code, resp.text[:300])
        return False
    except requests.RequestException as e:
        log.error("Could not reach TheHive at %s: %s", THEHIVE_URL, e)
        return False

# ── Notify via n8n (email) ───────────────────────────────────────────────────
def build_n8n_payload(wz: dict) -> dict:
    rule  = wz.get("rule", {})
    agent = wz.get("agent", {})
    data  = wz.get("data", {}) or {}
    return {
        "rule_id":          rule.get("id"),
        "rule_level":       rule.get("level", 0),
        "rule_description": rule.get("description"),
        "rule_mitre_ids":   (rule.get("mitre", {}) or {}).get("id", []),
        "agent_id":         agent.get("id"),
        "agent_name":       agent.get("name"),
        "agent_ip":         agent.get("ip"),
        "src_ip":           data.get("srcip"),
        "timestamp":        wz.get("timestamp"),
        "full_log":         (wz.get("full_log") or "")[:2000],
    }

def notify_n8n(wz: dict) -> bool:
    """POST one alert to the n8n webhook. Never raises; failures are logged."""
    try:
        resp = requests.post(N8N_URL, json=build_n8n_payload(wz), timeout=10)
        if resp.status_code in (200, 201, 202):
            return True
        if resp.status_code == 404:
            log.error(
                "n8n returned 404 for %s — the workflow is not active.\n"
                "  Fix: open n8n (port 5678) and switch the 'SOC - Wazuh alert email' workflow on.",
                N8N_URL,
            )
        else:
            log.warning("n8n rejected notification (HTTP %s): %s", resp.status_code, resp.text[:200])
    except requests.RequestException as e:
        log.error("Could not reach n8n at %s: %s", N8N_URL, e)
    return False

# ── Startup validation ───────────────────────────────────────────────────────
def validate_config() -> bool:
    ok = True
    if not THEHIVE_API_KEY:
        log.error(
            "THEHIVE_API_KEY is not set.\n"
            "  Fix: sudo ./deploy-soc-stack.sh set-hive-key <key>\n"
            "  The key must come from an org-level user with analyst/org-admin profile."
        )
        ok = False
    try:
        resp = requests.get(f"{THEHIVE_URL}/api/status", timeout=5)
        if resp.status_code == 200:
            log.info("TheHive reachable at %s", THEHIVE_URL)
        else:
            log.warning("TheHive returned HTTP %s on /api/status", resp.status_code)
    except requests.RequestException as e:
        log.warning("Cannot reach TheHive at %s: %s (will retry when forwarding)", THEHIVE_URL, e)
    return ok

# ── Main tail loop ───────────────────────────────────────────────────────────
def tail_alerts() -> None:
    if not validate_config():
        log.error("Startup validation failed. Exiting.")
        sys.exit(1)

    log.info("Bridge starting. Watching %s for alerts >= level %d", ALERTS_PATH, MIN_LEVEL)
    log.info("Forwarding to %s", THEHIVE_URL)
    if N8N_URL:
        log.info("n8n email notifications ON: level >= %d -> %s", N8N_MIN_LEVEL, N8N_URL)
    else:
        log.info("n8n email notifications OFF (N8N_WEBHOOK_URL not set).")

    while not os.path.exists(ALERTS_PATH):
        log.warning("%s does not exist yet (Wazuh manager starting?). Retrying in 10s...", ALERTS_PATH)
        time.sleep(10)

    offset, offset_existed = load_offset()
    forwarded = 0
    skipped   = 0

    with open(ALERTS_PATH, "r") as f:
        if not offset_existed:
            # No offset file — start from end of file (don't replay history)
            f.seek(0, 2)
            offset = f.tell()
            save_offset(offset)
            log.info("No saved offset — starting from current end of file (byte %d).", offset)
        else:
            # Offset file exists (even if 0) — honour it exactly
            f.seek(offset)
            log.info("Resuming from saved offset byte %d.", offset)

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

            # Email path first: its threshold is independent of the TheHive one.
            if N8N_URL and level >= N8N_MIN_LEVEL:
                if notify_n8n(wz_alert):
                    log.info("Notified n8n: rule %s (level %d)",
                             wz_alert.get("rule", {}).get("id"), level)

            if level < MIN_LEVEL:
                skipped += 1
                continue

            alert = build_alert(wz_alert)
            if send_alert(alert):
                forwarded += 1
                log.info("Forwarded alert: %s (level %d)", alert["title"], level)

            # Save offset periodically
            if (forwarded + skipped) % 20 == 0:
                save_offset(f.tell())

if __name__ == "__main__":
    try:
        tail_alerts()
    except KeyboardInterrupt:
        log.info("Bridge stopped.")
