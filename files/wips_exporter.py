#!/usr/bin/env python3
"""
wips_exporter.py — Kismet (passive 802.11 sensor) -> Wazuh JSON log.

Passive detection only: it never transmits. Two sources of findings:
  1. Kismet's own alerts (DEAUTHFLOOD, APSPOOF, KARMAOUI, WPSBRUTE, NONCEREUSE ...)
  2. Policy checks against YOUR allowlist (config JSON "wips" block):
       - rogue_ap     : AP seen on an SSID you own but from a BSSID not in the allowlist (evil twin)
       - open_clone   : your SSID advertised without encryption
       - unknown_open : (optional) any open network, informational

One JSON object per line is appended to the output log; Wazuh reads it as JSON and
rules in soc-ips-wazuh-rules.xml (ids 100300+) turn it into alerts.

Config (/opt/soc-stack/wips/wips.json):
  {"kismet_url":"http://127.0.0.1:2501","user":"..","password":"..",
   "own_ssids":{"HomeNet":["AA:BB:CC:DD:EE:FF"]},
   "poll_seconds":15,"out":"/var/log/soc-wips/wips.json"}
"""
import json, os, sys, time, logging, base64
import urllib.request, urllib.parse, urllib.error

CFG = sys.argv[1] if len(sys.argv) > 1 else "/opt/soc-stack/wips/wips.json"
SEV = {0: "info", 5: "low", 10: "medium", 15: "high", 20: "critical"}
log = logging.getLogger("wips")


def sev_name(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "medium"
    return SEV[min(SEV, key=lambda k: abs(k - n))]


class Kismet:
    def __init__(self, base, user, pw):
        self.base = base.rstrip("/")
        tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
        self.hdr = {"Authorization": f"Basic {tok}"}

    def _req(self, path, data=None):
        body = urllib.parse.urlencode({"json": json.dumps(data)}).encode() if data else None
        req = urllib.request.Request(self.base + path, data=body, headers=self.hdr)
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)

    def alerts_since(self, ts):
        return self._req(f"/alerts/last-time/{ts}/alerts.json")

    def aps(self):
        fields = ["kismet.device.base.macaddr", "kismet.device.base.name",
                  "kismet.device.base.channel", "kismet.device.base.crypt",
                  "kismet.device.base.signal/kismet.common.signal.last_signal",
                  "dot11.device/dot11.device.last_beaconed_ssid_record"]
        return self._req("/devices/views/phydot11_accesspoints/devices.json", {"fields": fields})


def find_key(obj, suffix):
    """first value whose key ends with suffix, searched recursively"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.endswith(suffix) and not isinstance(v, (dict, list)):
                return v
        for v in obj.values():
            r = find_key(v, suffix)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, suffix)
            if r is not None:
                return r
    return None


def g(d, *names):
    for n in names:
        if n in d and d[n] not in (None, ""):
            return d[n]
    return None


def norm_alert(a):
    return {
        "type": str(g(a, "kismet.alert.header", "kismet.alert.class") or "UNKNOWN").upper(),
        "severity": sev_name(g(a, "kismet.alert.severity")),
        "message": g(a, "kismet.alert.text") or "",
        "src_mac": g(a, "kismet.alert.source_mac", "kismet.alert.transmitter_mac"),
        "dst_mac": g(a, "kismet.alert.dest_mac"),
        "bssid": g(a, "kismet.alert.transmitter_mac"),
        "channel": g(a, "kismet.alert.channel"),
        "ts": g(a, "kismet.alert.timestamp") or time.time(),
    }


def check_aps(devices, own):
    """own: {ssid: [BSSIDs upper]} -> list of findings"""
    out = []
    for d in devices:
        bssid = str(d.get("kismet.device.base.macaddr", "")).upper()
        ssid = find_key(d, "advertisedssid.ssid") or d.get("kismet.device.base.name") or ""
        crypt = str(d.get("kismet.device.base.crypt") or find_key(d, "crypt_string") or "")
        chan = d.get("kismet.device.base.channel")
        if not bssid or ssid not in own:
            continue
        if bssid not in own[ssid]:
            out.append({"type": "ROGUE_AP", "severity": "critical", "bssid": bssid, "ssid": ssid,
                        "channel": chan, "message":
                        f"SSID '{ssid}' advertised by unknown BSSID {bssid} (evil twin / rogue AP)"})
        elif "open" in crypt.lower() or crypt.strip() in ("", "none"):
            out.append({"type": "OPEN_CLONE", "severity": "high", "bssid": bssid, "ssid": ssid,
                        "channel": chan, "message":
                        f"Your SSID '{ssid}' on {bssid} is advertising WITHOUT encryption"})
    return out


def emit(fh, rec):
    rec = {"integration": "soc-wips", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "wips": rec}
    fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    fh.flush()


def main():
    c = json.load(open(CFG))
    k = Kismet(c.get("kismet_url", "http://127.0.0.1:2501"), c["user"], c["password"])
    own = {s: [m.upper() for m in macs] for s, macs in (c.get("own_ssids") or {}).items()}
    poll = int(c.get("poll_seconds", 15))
    out = c.get("out", "/var/log/soc-wips/wips.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    last = int(time.time())
    dedupe = set()
    seen_policy = {}          # (type,bssid,ssid) -> last emit time; re-alert every 30 min
    with open(out, "a") as fh:
        while True:
            try:
                for a in k.alerts_since(last):
                    n = norm_alert(a)
                    ident = (n["ts"], n["type"], n["message"])
                    if ident in dedupe:
                        continue
                    dedupe.add(ident)
                    emit(fh, n)
                    last = max(last, int(float(n["ts"])))
                if len(dedupe) > 5000:
                    dedupe.clear()
                if own:
                    now = time.time()
                    for f in check_aps(k.aps(), own):
                        key = (f["type"], f["bssid"], f["ssid"])
                        if now - seen_policy.get(key, 0) > 1800:
                            seen_policy[key] = now
                            emit(fh, f)
            except (urllib.error.URLError, OSError, ValueError) as e:
                log.warning("kismet poll failed: %s", e)
            time.sleep(poll)


if __name__ == "__main__":
    main()
