# Wazuh + OpenSearch + TheHive + Cortex on Debian 13

A fully automated SOC home lab deployment for Debian 13 (Trixie) — built, broken, and fixed until it actually worked.

**One command deploys the full stack:**
```bash
sudo ./deploy-soc-stack.sh install
```

---

## What this is

A single deploy script and Python alert bridge that stands up a complete SOC detection and response pipeline on a single host:

| Component | Role |
|---|---|
| **Wazuh 4.14** | SIEM — agent-based threat detection, FIM, vulnerability scanning, MITRE ATT&CK mapping |
| **OpenSearch** | Indexer — alert storage and search (bundled with Wazuh) |
| **TheHive 5.2** | Case management — receives alerts, manages incidents |
| **Cortex 3** | Observable enrichment — analyzes IPs, domains, hashes via analyzer plugins |
| **Python bridge** | Custom alert forwarder — tails Wazuh's alerts.json and POSTs to TheHive's API |

Wazuh runs natively via systemd. TheHive, Cassandra, Cortex, and Cortex's Elasticsearch run in Docker. The bridge runs as a systemd service.

---

## Why Debian 13

Debian 13 (Trixie) is not an officially supported platform for any of these tools. Getting this stack running required working around several real compatibility issues — see the [what broke](#what-broke) section below.

---

## Requirements

- Debian 13 (Trixie) — fresh install recommended
- 8GB RAM minimum (proven working), 16GB comfortable
- 4+ vCPU
- 50GB+ free disk (Wazuh's vulnerability DB is large)
- Internet access during install (package downloads ~1.5GB total)

---

## Quick start

```bash
# Clone the repo
git clone https://github.com/em0n0/Wazuh-OpenSearch-TheHive-Cortex-on-Debian-13
cd Wazuh-OpenSearch-TheHive-Cortex-on-Debian-13

# Deploy everything
sudo ./deploy-soc-stack.sh install

# Check status when done
sudo ./deploy-soc-stack.sh status
```

**Expected runtime:** 15–25 minutes depending on download speed.

After install, access the stack at:
- Wazuh dashboard: `https://<host-ip>` (credentials in `/opt/soc-stack/wazuh-passwords.txt`)
- TheHive: `http://<host-ip>:9000` (default: `admin@thehive.local` / `secret`)
- Cortex: `http://<host-ip>:9001` (setup wizard on first visit)

---

## Wiring the alert bridge

After install, the bridge needs a TheHive API key from an **org-level user** (not the platform superadmin):

1. Log into TheHive → create an organisation → create a user with `analyst` profile → generate their API key
2. Feed it to the script:

```bash
sudo ./deploy-soc-stack.sh set-hive-key <api-key>
```

Alerts at Wazuh rule level ≥ 7 will automatically appear in TheHive's Alerts tab.

---

## Suricata IPS and wireless IDS (optional)

`install suricata` adds an inline Suricata IPS (NFQUEUE, fail-open, starts in detect mode, `soc-ips mode prevent` to enforce). `install wips` adds a passive Kismet wireless IDS with evil-twin/deauth detection. Both feed Wazuh and, through the bridge, TheHive. Details, rollout steps and the panic switch: CLI-REFERENCE.md sections 12 and 13. Enable them in the `--config` JSON (`suricata.enabled`, `wips.enabled`) or install them explicitly.

## Choosing components

Run `sudo ./deploy-soc-stack.sh install` with no component list and it asks, one by one, whether to install Wazuh, TheHive, Cortex, the bridge, n8n (it then asks for SMTP details), Suricata IPS (detect or prevent) and Kismet WIPS (interface and your SSIDs). Typed secrets go into a private temp config that is deleted on exit. Use `--yes` to skip the questions (installs "all" plus whatever `--config` enables), or name components explicitly (`install wazuh,hive`).

## Script reference

```bash
sudo ./deploy-soc-stack.sh install              # full stack
sudo ./deploy-soc-stack.sh install wazuh        # Wazuh only
sudo ./deploy-soc-stack.sh install hive         # TheHive + Cassandra only
sudo ./deploy-soc-stack.sh install cortex       # Cortex + ES only
sudo ./deploy-soc-stack.sh install bridge       # alert bridge only
sudo ./deploy-soc-stack.sh --force install hive # re-run a completed stage
sudo ./deploy-soc-stack.sh status               # health check all services
sudo ./deploy-soc-stack.sh set-hive-key <key>   # update TheHive API key
sudo ./deploy-soc-stack.sh uninstall            # tear everything down
```

Each stage is idempotent — completed stages are skipped on re-run unless `--force` is passed.

---

## What broke

This stack doesn't officially support Debian 13. Here's every real bug hit during development and how it was fixed — the kind of thing that doesn't show up in any tutorial:

| Bug | Fix |
|---|---|
| `software-properties-common` doesn't exist on Debian 13 | `sed` it out of the Wazuh installer before running |
| `/etc/sysctl.conf` doesn't exist on minimal installs | `touch` before appending |
| `docker: command not found` during network setup | moved `ensure_network` to after Docker install |
| TheHive loops forever on start | host volume owned by root, container runs as uid 1000 — `chown -R 1000:1000` |
| Cassandra permission denied | `chown -R 999:999` on data dir |
| `--storage-provider` is not a valid TheHive flag | correct flag is `--storage-directory` |
| TheHive starts before Cassandra is ready | `depends_on: condition: service_healthy` |
| Cortex ES healthcheck fails even when ES is running | start ES and Cortex separately with `--no-deps`, curl-wait between them |
| `apt upgrade` wipes dashboard cert paths and breaks `opensearch.hosts` | `apt-mark hold` on all Wazuh packages post-install; recovery steps in CLI-REFERENCE.md |
| `localhost` resolves to `::1` (IPv6) but indexer only binds `127.0.0.1` | hardcode `127.0.0.1` in dashboard config |
| Bridge offset file from previous install is past new file's end | detect file-not-found vs value-zero to distinguish "no offset" from "start of file" |
| TheHive API returning 403 | API key must belong to org-level user, not platform superadmin |

---

## Files

```
deploy-soc-stack.sh          # main installer and ops script
files/
├── wazuh_thehive_bridge.py  # alert bridge (tails alerts.json → TheHive API)
└── bridge-requirements.txt  # Python deps (requests)
CLI-REFERENCE.md             # day-2 ops, troubleshooting, post-upgrade recovery
```

---

## Tested on

- Debian 13 Trixie (kernel 6.12)
- 8GB RAM / 8 vCPU
- Wazuh 4.14.6
- TheHive 5.2.16
- Cortex 3.1.7
- Docker 29.6.1 / Docker Compose 5.3.0
