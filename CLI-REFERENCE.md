# SOC Lab Stack — CLI Reference  (v2.0)

Companion to `deploy-soc-stack.sh`. Covers install, day-2 ops, and
troubleshooting for Wazuh + TheHive 5.2 + Cortex 3 on Debian 13 Trixie,
sized for 8GB / 4 vCPU.

---

## 1. Architecture

| Component | How it runs | Port | Purpose |
|---|---|---|---|
| Wazuh manager | native systemd | 1514, 1515, 55000 | Agent comms, rule engine |
| Wazuh indexer | native systemd (OpenSearch) | 9200 (localhost only) | Alert storage/search |
| Wazuh dashboard | native systemd | 443 | Web UI |
| Cassandra | Docker | 9042 (internal) | TheHive database |
| TheHive | Docker | 9000 | Case management |
| Cortex | Docker | 9001 | Observable enrichment/analysis |
| Cortex Elasticsearch | Docker | internal only | Cortex's search index |
| Alert bridge | systemd (Python) | — | Tails Wazuh → posts to TheHive |

---

## 2. Installation

```bash
# Full stack (recommended for first install)
sudo ./deploy-soc-stack.sh install

# Individual stages (useful for re-runs or staged installs)
sudo ./deploy-soc-stack.sh install wazuh
sudo ./deploy-soc-stack.sh install hive
sudo ./deploy-soc-stack.sh install cortex
sudo ./deploy-soc-stack.sh install bridge

# Force re-run a completed stage
sudo ./deploy-soc-stack.sh --force install hive
```

Each stage is idempotent — a marker file in `/var/lib/soc-stack/` tracks
completion and skips re-runs unless `--force` is passed.

**Expected runtime:** 15–25 minutes for a full install on 4 vCPU (most of
it is Wazuh's indexer initialising and Docker image pulls).

---

## 3. TheHive API key setup (required for the alert bridge)

This is the most common point of confusion. The API key for the bridge
**must** come from an org-level user, not the platform superadmin.

**Step-by-step:**

1. Go to `http://<host-ip>:9000` and log in as `admin@thehive.local` / `secret`
2. Click **Organisation List** → **+ Create** → name it (e.g. `SOC-Lab`) → save
3. Click into your new org → **Users** tab → **+** to create a user:
   - Login: `analyst@soc-lab.local` (or any email)
   - Full name: anything
   - Profile: **`analyst`** or **`org-admin`** ← critical
4. Click the `...` menu on that user → **Set password**
5. Click the `...` menu again → **Create API key** → copy it
6. Run on the server:

```bash
sudo ./deploy-soc-stack.sh set-hive-key <the-key-you-copied>
sudo journalctl -u wazuh-thehive-bridge -f
```

**Why not use admin@thehive.local?**
That account is the platform superadmin — it exists above all organisations
and cannot create alerts inside any org. Using its key gives a 403 error.

---

## 4. Testing the full pipeline

```bash
# Reset the offset so the bridge sees new alerts immediately
sudo rm -f /opt/soc-stack/bridge/.alerts.offset
sudo systemctl restart wazuh-thehive-bridge

# Inject a synthetic level-10 alert
sudo bash -c 'echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S)+0000\",\"rule\":{\"level\":10,\"description\":\"Pipeline test\",\"id\":\"99999\"},\"agent\":{\"id\":\"000\",\"name\":\"$(hostname)\"},\"id\":\"test-$(date +%s)\",\"full_log\":\"test\"}" >> /var/ossec/logs/alerts/alerts.json'

# Watch the bridge
sudo journalctl -u wazuh-thehive-bridge -f
```

Look for: `Forwarded alert: [Wazuh L10] Pipeline test`

Then check TheHive → **Alerts** tab. If the alert appears, the pipeline is
working end-to-end.

---

## 5. Connecting TheHive to Cortex

1. In Cortex (`http://<host-ip>:9001`) — complete the first-time setup wizard:
   - Create an organisation
   - Create a user with `read, analyze` role
   - Generate an API key for that user → copy it

2. In TheHive (`http://<host-ip>:9000`):
   - **Organisation** (top right) → **Platform Management** → **Connectors** → **Cortex**
   - Add server: URL = `http://cortex:9001` (Docker service name), paste the API key
   - Save and enable

3. Test: open any alert in TheHive → **Observables** tab → click the analyzer
   icon next to an IP or domain.

---

## 6. Status and health checks

```bash
sudo ./deploy-soc-stack.sh status
```

Shows all Wazuh services, Docker container states, bridge state, memory
usage, and live Docker stats.

---

## 7. Day-2 operations

### Wazuh services
```bash
sudo systemctl {start|stop|restart|status} wazuh-manager
sudo systemctl {start|stop|restart|status} wazuh-indexer
sudo systemctl {start|stop|restart|status} wazuh-dashboard

# Live alerts
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq .

# Manager log
sudo tail -f /var/ossec/logs/ossec.log
```

### Docker stack (TheHive / Cortex)
```bash
cd /opt/soc-stack

# Logs
sudo docker compose -f docker-compose.hive.yml logs -f thehive
sudo docker compose -f docker-compose.hive.yml logs -f cassandra
sudo docker compose -f docker-compose.cortex.yml logs -f cortex

# Restart a service
sudo docker compose -f docker-compose.hive.yml restart thehive

# Stop/start everything
sudo docker compose -f docker-compose.hive.yml down
sudo docker compose -f docker-compose.hive.yml --env-file .env up -d
```

### Alert bridge
```bash
sudo systemctl {start|stop|restart|status} wazuh-thehive-bridge
sudo journalctl -u wazuh-thehive-bridge -f

# Update API key
sudo ./deploy-soc-stack.sh set-hive-key <new-key>

# Reset offset (replay from current position)
sudo rm -f /opt/soc-stack/bridge/.alerts.offset
sudo systemctl restart wazuh-thehive-bridge
```

---

## 8. Troubleshooting

### Bridge error reference

| Error | Cause | Fix |
|---|---|---|
| `401 Unauthorized` | API key is wrong or expired | Regenerate key in TheHive, run `set-hive-key` |
| `403 Forbidden — manageAlert/create` | Key belongs to platform superadmin, or user has read-only profile | Create an org-level user with analyst/org-admin profile, use their key |
| `Connection reset by peer` | TheHive was down when bridge started | TheHive is back up — bridge will recover automatically |
| `Could not reach TheHive` | TheHive container not running | `sudo docker compose -f /opt/soc-stack/docker-compose.hive.yml up -d` |
| No alerts forwarded | Offset file pointing past new alerts | `sudo rm /opt/soc-stack/bridge/.alerts.offset && sudo systemctl restart wazuh-thehive-bridge` |

### Cortex Elasticsearch healthcheck failure
ES is often actually running fine but the Docker healthcheck fails. Start
both services with `--no-deps` to bypass the dependency check:

```bash
cd /opt/soc-stack
sudo docker compose -f docker-compose.cortex.yml up cortex-elasticsearch -d --no-deps
sleep 30
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
sudo docker compose -f docker-compose.cortex.yml up cortex -d --no-deps
```

### Wazuh indexer OOM / slow
Check heap usage:
```bash
sudo systemctl status wazuh-indexer | grep Memory
```
Re-tune heap (1500m is the recommended value for 8GB hosts):
```bash
sudo sed -i -E "s/^-Xms[0-9]+[mMgG]/-Xms1500m/; s/^-Xmx[0-9]+[mMgG]/-Xmx1500m/" \
    /etc/wazuh-indexer/jvm.options
sudo systemctl restart wazuh-indexer
```

### Common log locations
```
/var/log/soc-stack-install.log        install log
/var/ossec/logs/ossec.log             Wazuh manager
/var/ossec/logs/alerts/alerts.json    raw Wazuh alerts (what the bridge reads)
journalctl -u wazuh-thehive-bridge    alert bridge
docker compose ... logs <service>     TheHive / Cassandra / Cortex
```

---

## 9. Post-upgrade recovery

**Problem:** Running `apt upgrade` and choosing `Y` to overwrite Wazuh config
files breaks the dashboard in two ways:
1. Cert paths reset to generic names that don't match files on disk
2. `opensearch.hosts` reverts to `localhost` which resolves to IPv6 (`::1`)
   but the indexer only listens on IPv4 (`127.0.0.1`)

**Fix (run in order):**

```bash
# Step 1 — fix cert paths
sudo sed -i \
    's|certs/dashboard-key.pem|certs/wazuh-dashboard-key.pem|g;
     s|certs/dashboard.pem|certs/wazuh-dashboard.pem|g' \
    /etc/wazuh-dashboard/opensearch_dashboards.yml

# Step 2 — fix localhost -> 127.0.0.1
sudo sed -i \
    's|opensearch.hosts: https://localhost:9200|opensearch.hosts: https://127.0.0.1:9200|' \
    /etc/wazuh-dashboard/opensearch_dashboards.yml

# Step 3 — retune indexer heap (upgrade resets it to 4GB default)
sudo sed -i -E \
    "s/^-Xms[0-9]+[mMgG]/-Xms1500m/; s/^-Xmx[0-9]+[mMgG]/-Xmx1500m/" \
    /etc/wazuh-indexer/jvm.options
sudo systemctl restart wazuh-indexer

# Step 4 — restart dashboard
sudo systemctl restart wazuh-dashboard
sudo systemctl status wazuh-dashboard --no-pager | tail -3
```

Look for `Server running at https://0.0.0.0:443` to confirm it's up.

**Prevention:** Wazuh packages are held after install. To upgrade deliberately:
```bash
sudo apt-mark unhold wazuh-manager wazuh-indexer wazuh-dashboard
sudo apt upgrade wazuh-manager wazuh-indexer wazuh-dashboard
# Then run the fix steps above
sudo apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard
```

---

## 10. Sizing guidance

| RAM | Approach |
|---|---|
| 8GB | Script defaults (proven). Expect slow indexing under concurrent load. |
| 16GB | Double all heaps. Comfortable for active lab use. |
| 32GB+ | Use upstream defaults. Room for multiple agents and Cortex analyzers. |

### JVM heap tuning reference
```
Wazuh indexer:  /etc/wazuh-indexer/jvm.options         → -Xms1500m -Xmx1500m
Cassandra:      /opt/soc-stack/docker-compose.hive.yml  → MAX_HEAP_SIZE=1024M
TheHive:        /opt/soc-stack/docker-compose.hive.yml  → JVM_OPTS=-Xms1024m -Xmx1024m
Cortex ES:      /opt/soc-stack/docker-compose.cortex.yml → ES_JAVA_OPTS=-Xms512m -Xmx512m
```
After editing compose files: `sudo docker compose -f <file> up -d --force-recreate <service>`

---

## 11. File layout

```
/opt/soc-stack/
├── .env                        # secrets and API keys (chmod 600)
├── docker-compose.hive.yml
├── docker-compose.cortex.yml
├── wazuh-passwords.txt         # generated Wazuh admin credentials
├── wazuh-install-files.tar     # Wazuh certs bundle (keep this safe)
├── thehive/
│   ├── data/                   # TheHive app data
│   └── files/                  # case attachments
├── cassandra/data/
├── cortex/
│   ├── es-data/
│   └── jobs/
└── bridge/
    ├── bridge.py
    ├── requirements.txt
    ├── venv/
    └── .alerts.offset          # delete to reset read position

/var/lib/soc-stack/             # install stage markers
/var/log/soc-stack-install.log  # install log
```

---

## 12. Suricata inline IPS

Suricata runs inline via NFQUEUE (`suricata-ips.service`, queue 0). nftables table `inet soc_ips` sends **LAN-interface** traffic to the queue with `queue flags bypass`, so if Suricata is stopped or crashes, packets are accepted (fail-open) instead of blackholed. SSH, Wazuh agent ports (1514/1515/55000), DHCP and broadcast/multicast are never queued.

```bash
# config.json:  "suricata": {"enabled": true, "mode": "detect", "interface": "auto", "ssh_ports": [22]}
sudo ./deploy-soc-stack.sh install suricata --config soc.json

sudo soc-ips status              # mode, services, rule counts, alerts/blocked
sudo soc-ips mode prevent        # drop high-confidence groups (botcc, ciarmy, compromised, drop, malware, exploit_kit, worm, dshield)
sudo soc-ips mode detect         # back to log-only
sudo soc-ips update              # suricata-update + syntax test + live reload (daily timer does this too)
sudo soc-ips blocked 30          # last 30 blocked flows
sudo soc-ips selftest            # prevent mode only: fetches a harmless test page, expects a block
sudo soc-ips allow 2012345       # never drop this SID (false positive)
sudo soc-ips drop  2012345       # always drop this SID
sudo soc-ips panic-off           # EMERGENCY: remove the NFQUEUE hook now
sudo soc-ips panic-on
```

**Rollout:** run in `detect` for several days, read the alerts in Wazuh, add `allow` entries for false positives, then `mode prevent`. Tuning files live in `/etc/suricata/soc-ips/` (`enable.conf`, `disable.conf`, `modify.conf`, `drop.local`).

**Locked out?** From the console: `sudo soc-ips panic-off` (or `sudo nft delete table inet soc_ips`). Because of `bypass`, `systemctl stop suricata-ips` also restores traffic.

**RAM:** budget about 1–1.5 GB for ET Open. On the 8 GB all-in-one box, check `./deploy-soc-stack.sh status` after enabling; trim groups in `disable.conf` if memory is tight.

Wazuh rules (`/var/ossec/etc/rules/soc-ips_rules.xml`): 100201 blocked flow, 100202 blocked severity-1, 100203 repeated blocks from one source, 100210 severity-1 in detect mode, 100220 Suricata dropping packets.

## 13. Wireless IDS (Kismet, passive)

A second Wi-Fi adapter that supports monitor mode captures 802.11 frames. Kismet raises alerts (DEAUTHFLOOD, APSPOOF, KARMAOUI, WPSBRUTE, NONCEREUSE …); `wips_exporter.py` polls its REST API on 127.0.0.1:2501, adds its own rogue-AP and open-clone checks against your SSID allowlist, and writes JSON for Wazuh (rules 100300–100320).

```bash
# config.json:  "wips": {"enabled": true, "interface": "wlan1",
#                        "own_ssids": {"HomeNet": ["AA:BB:CC:DD:EE:FF"]}}
sudo ./deploy-soc-stack.sh install wips --config soc.json
systemctl status soc-kismet soc-wips-exporter
tail -f /var/log/soc-wips/wips.json
ssh -L 2501:127.0.0.1:2501 user@192.168.1.28     # Kismet UI at http://localhost:2501
```

**It is detection only.** The system never transmits and never deauthenticates anyone. Wireless "prevention" is done on the wired side: the rogue BSSID shows up in TheHive and you remove it (or enable PMF/802.11w and WPA3 on your AP). Active containment would transmit forged frames, which is unlawful in many jurisdictions and can hit neighbours' networks.

Without `own_ssids` the evil-twin check is off and only Kismet's generic alerts reach Wazuh.

Not yet verified on real hardware: the exact Kismet alert field names are read tolerantly (`kismet.alert.header/severity/text/...`); if alerts show `UNKNOWN`, inspect `curl -u user:pass http://127.0.0.1:2501/alerts/all_alerts.json` and adjust `norm_alert()`.

---

## 14. Safe Wazuh upgrade (`upgrade`)

Upgrades broke the dashboard before because `apt` offered the package maintainer's config files and answering "Y" replaced the installer's certificate paths, `127.0.0.1` binding and JVM heap. The `upgrade` command avoids that.

```bash
sudo ./deploy-soc-stack.sh upgrade            # newest version in the Wazuh repo
sudo ./deploy-soc-stack.sh upgrade 4.14.9     # a specific version
sudo ./deploy-soc-stack.sh --yes upgrade 4.14.9   # no confirmation prompt
```

What it does, in order:
1. Shows installed vs. available versions and asks to proceed.
2. Backs up `/etc/wazuh-dashboard`, `/etc/wazuh-indexer`, `/etc/filebeat`, `/var/ossec/etc` and the stack `.env` to `/var/backups/soc-stack/` (it refuses to continue without a backup).
3. Unholds the Wazuh packages, then upgrades **indexer → manager → dashboard**, one at a time, with `--force-confold` so your config files are kept.
4. Health-checks after each package (indexer on 9200, manager service, dashboard login page) and **stops at the first failure**, pointing to the logs and backup.
5. Puts `apt-mark hold` back, even on failure.
6. Lists any `*.dpkg-dist` files: the new package defaults, to diff against your config in case a release adds a setting you need.

Take a VM snapshot first if you can. Read the release notes for config changes before upgrading.
