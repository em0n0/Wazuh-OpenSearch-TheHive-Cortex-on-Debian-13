# SOC Lab Stack — CLI Reference

Companion reference for `deploy-soc-stack.sh`. Covers install, day-2 operations,
and troubleshooting for Wazuh 4.12 + TheHive 5.2 + Cortex 3 on Debian 13, sized
for an 8GB / 4 vCPU host.

> **Resource reality check:** 8GB is the floor, not a comfort zone. Four
> JVM-based services (Wazuh indexer, Cassandra, TheHive, Cortex's ES) are
> memory-hungry by nature. The script tunes heaps down aggressively and adds
> a 4GB swap file as a safety net, but expect periods of slow indexing or
> search under load. If you can give the VM 16GB, do it — see the sizing
> table at the bottom.

---

## 1. Architecture

| Component | How it runs | Port | Purpose |
|---|---|---|---|
| Wazuh manager | native systemd | 1514/tcp, 1515/tcp, 55000/tcp | Agent comms, rule engine |
| Wazuh indexer | native systemd (OpenSearch) | 9200/tcp | Alert storage/search |
| Wazuh dashboard | native systemd | 443/tcp | Web UI |
| Cassandra | Docker | 9042/tcp (internal) | TheHive's database |
| TheHive | Docker | 9000/tcp | Case management UI/API |
| Cortex | Docker | 9001/tcp | Observable analysis/enrichment |
| Cortex's Elasticsearch | Docker | internal only | Cortex's own search index |
| n8n | Docker (SQLite backend) | 5678/tcp | SOAR orchestration: auto case creation, triage routing |
| Alert bridge | systemd (Python venv) | n/a | Tails Wazuh alerts → posts to TheHive (always) and n8n (high-severity only) |

Wazuh stays native because its installer owns OpenSearch directly and fighting
that is more trouble than it's worth. TheHive/Cortex/n8n run in Docker because
their official deployment paths are container-first and it keeps Cassandra/ES
cleanly isolated. Storage for TheHive attachments is local filesystem
(`/opt/soc-stack/thehive/files`), not S3/MinIO — one less moving part. n8n
uses its default SQLite backend rather than Postgres — fine for a single
analyst, and this 8GB budget has no room for a sixth container.

### Why two integration paths (bridge + n8n) instead of one

The Python bridge (from the original deployment) is the **reliable record**:
every Wazuh alert at or above `MIN_ALERT_LEVEL` becomes a TheHive Alert,
full stop, with no dependency on n8n being up. n8n is the **orchestration
layer** on top: it only sees alerts at or above the separate, higher
`N8N_MIN_LEVEL` threshold, and its job is deciding what *else* should happen
— a full Case (not just an Alert), tagging, assignment, and eventually
notification. If n8n is down, mid-edit, or you're iterating on workflow
logic, you don't lose alert visibility in TheHive; you only lose the SOAR
automation layer temporarily. This mirrors how most real SOC stacks are
built: a dumb-but-reliable ingest path, with a smarter orchestration layer
that's allowed to fail without taking down visibility.

---

## 2. Installation

```bash
# Full stack, all components
sudo ./deploy-soc-stack.sh install

# Just one piece (useful for staged installs or re-runs after a failure)
sudo ./deploy-soc-stack.sh install wazuh
sudo ./deploy-soc-stack.sh install hive
sudo ./deploy-soc-stack.sh install cortex
sudo ./deploy-soc-stack.sh install n8n
sudo ./deploy-soc-stack.sh install bridge

# Force re-run a stage that already completed
sudo ./deploy-soc-stack.sh --force install wazuh
```

The script is idempotent: each stage drops a marker in `/var/lib/soc-stack/`
on success and skips on re-run unless `--force` is passed. Install order
matters if running stages individually: `wazuh` and `hive`/`cortex` don't
depend on each other, but `bridge` needs Wazuh's manager running and TheHive's
API key set.

**Expected runtime:** 10–20 minutes for the full stack on a 4 vCPU host, most
of it spent on the Wazuh indexer initializing and Cortex's Elasticsearch
warming up.

### Post-install: wiring the bridge

The bridge installs but stays inactive until you give it a TheHive API key:

```bash
# 1. Log into TheHive at http://<host-ip>:9000
# 2. Org Admin -> Users -> (your user) -> generate an API key
# 3. Feed it to the script:
sudo ./deploy-soc-stack.sh set-hive-key <the-key>

# Verify it's running
sudo systemctl status wazuh-thehive-bridge
sudo journalctl -u wazuh-thehive-bridge -f
```

By default the bridge forwards Wazuh alerts at rule level ≥ 7 (Wazuh's own
0–15 severity scale). Adjust via `/opt/soc-stack/.env`:

```bash
echo "MIN_ALERT_LEVEL=10" | sudo tee -a /opt/soc-stack/.env
sudo systemctl restart wazuh-thehive-bridge
```

### Post-install: n8n SOAR setup

This is a five-step loop: import the workflow, create a TheHive API
credential inside n8n, activate the workflow, copy its webhook URL into the
bridge's config, then test it end-to-end. None of it can be scripted blindly
because it involves you clicking through n8n's setup wizard and generating
an API key — both are one-time, account-specific actions.

**Step 1 — Finish n8n's first-run setup**

Open `http://<host-ip>:5678`. First visit prompts you to create an owner
account (email/password, stored locally, never leaves your box). Skip the
optional "connect to n8n cloud" prompts — this deployment is fully
self-hosted.

**Step 2 — Import the workflow**

In n8n: **Workflows → Add workflow → Import from File**, and select
`files/n8n-wazuh-thehive-soar-workflow.json` from this repo. You'll see 7
nodes: a webhook trigger, a severity-scoring Code node, an `Is Critical?`
branch, two TheHive API calls (create case, assign), a log/notify
placeholder, and a response node.

**Step 3 — Create the TheHive API credential**

The imported workflow's two HTTP Request nodes (`Create TheHive Case`,
`Assign Triage Queue`) reference a credential named **TheHive API Key**
that doesn't exist yet — n8n will flag both nodes with a red warning until
you create it:

1. Generate an API key in TheHive: **Org Admin → Users → (your user) →
   API key**. (You can reuse the same key the Python bridge uses, or
   generate a dedicated one — a dedicated key makes revocation cleaner if
   you ever need to cut off n8n's access without touching the bridge.)
2. In n8n: **Credentials → Add Credential → Header Auth**.
3. Name: `TheHive API Key`. Header name: `Authorization`. Header value:
   `Bearer <the-key-from-step-1>`.
4. Save, then open both HTTP Request nodes in the workflow and select this
   credential from the dropdown (the placeholder `REPLACE_WITH_CREDENTIAL_ID`
   in the imported JSON resolves automatically once you pick it in the UI).

**Step 4 — Activate and grab the webhook URL**

Toggle the workflow to **Active** (top right). Open the **Wazuh Alert
Webhook** node, copy its **Production URL** (looks like
`http://<host-ip>:5678/webhook/wazuh-soar`).

**Step 5 — Point the bridge at it**

```bash
sudo ./deploy-soc-stack.sh set-n8n-webhook 'http://localhost:5678/webhook/wazuh-soar'
```

Using `localhost` here (not the host's LAN IP) is intentional — the bridge
runs on the same host as n8n's Docker container, which has its port
published to `0.0.0.0:5678`, so localhost resolves correctly and avoids a
hairpin-NAT round trip through the LAN interface.

**Test it end-to-end:**

```bash
# Manually trigger a high-severity test alert through the bridge's own logic
# by hand-posting a synthetic payload to n8n's webhook directly:
curl -X POST http://localhost:5678/webhook/wazuh-soar \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "wazuh", "wazuh_alert_id": "test-001",
    "timestamp": "2026-06-21T12:00:00Z",
    "rule_id": "100100", "rule_level": 12,
    "rule_description": "Test: multiple failed SSH logins",
    "rule_groups": ["authentication_failed"], "rule_mitre_ids": ["T1110"],
    "agent_id": "001", "agent_name": "test-agent", "agent_ip": "10.0.0.5",
    "src_ip": "203.0.113.7", "dst_ip": "10.0.0.5",
    "full_log": "Test log line for SOAR workflow validation"
  }'
```

Check **n8n → Executions** for a successful run, and TheHive for a new case
tagged `soar-auto-case`, `tier:high`. If the HTTP Request nodes show a 401,
the credential's Bearer token is wrong; if they show a connection error,
double-check `THEHIVE_URL` resolves from inside n8n's container (it should,
since both are on the `soc-net` Docker network — the default
`http://thehive:9000` baked into the workflow's HTTP Request nodes uses the
Docker service name, not localhost).

**Optional — auto-assign a default analyst:**

```bash
echo "SOC_TRIAGE_ANALYST=your-thehive-username" | sudo tee -a /opt/soc-stack/.env
cd /opt/soc-stack && docker compose -f docker-compose.n8n.yml up -d --force-recreate n8n
```

The `Assign Triage Queue` node reads this from n8n's environment and PATCHes
it onto every SOAR-created case. Leave it unset to leave cases unassigned
for manual pickup from a shared queue instead.

**Swapping the placeholder notification for a real one:** the `Log
Escalation (replace with notify)` node is a Code node that just
`console.log`s to n8n's execution log — it exists so the workflow runs
end-to-end with zero external credentials required out of the box. To wire
real notifications, delete that node in the n8n editor and connect `Assign
Triage Queue` directly to a Slack, Discord, or Send Email node instead (all
built into n8n; just drag one in and supply its credential).

---

## 3. Day-2 Operations

### Status / health

```bash
sudo ./deploy-soc-stack.sh status
```

Shows systemd state for the three Wazuh services, Docker container status for
TheHive/Cassandra/Cortex/Cortex-ES, the bridge's systemd state, and a live
`docker stats` snapshot so you can see who's eating RAM.

### Wazuh service control

```bash
sudo systemctl {start|stop|restart|status} wazuh-manager
sudo systemctl {start|stop|restart|status} wazuh-indexer
sudo systemctl {start|stop|restart|status} wazuh-dashboard

# Tail live alerts
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq .

# Tail manager logs (rule errors, decoder issues)
sudo tail -f /var/ossec/logs/ossec.log

# Validate config before restarting (catches XML errors)
sudo /var/ossec/bin/wazuh-control -t  # or: /var/ossec/bin/verify-agent-conf
```

### TheHive / Cassandra / Cortex / n8n (Docker)

```bash
cd /opt/soc-stack

# View logs
docker compose -f docker-compose.hive.yml logs -f thehive
docker compose -f docker-compose.hive.yml logs -f cassandra
docker compose -f docker-compose.cortex.yml logs -f cortex
docker compose -f docker-compose.n8n.yml logs -f n8n

# Restart a single service
docker compose -f docker-compose.hive.yml restart thehive

# Stop everything (data persists in /opt/soc-stack volumes)
docker compose -f docker-compose.hive.yml down
docker compose -f docker-compose.cortex.yml down
docker compose -f docker-compose.n8n.yml down

# Bring back up
docker compose -f docker-compose.hive.yml --env-file .env up -d
docker compose -f docker-compose.cortex.yml --env-file .env up -d
docker compose -f docker-compose.n8n.yml --env-file .env up -d
```

### Alert bridge

```bash
sudo systemctl {start|stop|restart|status} wazuh-thehive-bridge
sudo journalctl -u wazuh-thehive-bridge -f

# Re-point it at a different TheHive instance or change thresholds
sudo nano /opt/soc-stack/.env
sudo systemctl restart wazuh-thehive-bridge

# Change which n8n webhook receives high-severity alerts
sudo ./deploy-soc-stack.sh set-n8n-webhook 'http://localhost:5678/webhook/wazuh-soar'

# Change the n8n escalation threshold (separate from MIN_ALERT_LEVEL, which
# governs the always-on TheHive alert path)
echo "N8N_MIN_LEVEL=12" | sudo tee -a /opt/soc-stack/.env
sudo systemctl restart wazuh-thehive-bridge

# Temporarily disable n8n forwarding without touching MIN_ALERT_LEVEL
sudo sed -i 's/^N8N_WEBHOOK_URL=.*/N8N_WEBHOOK_URL=/' /opt/soc-stack/.env
sudo systemctl restart wazuh-thehive-bridge
```

The bridge tracks its read position in
`/opt/soc-stack/bridge/.alerts.offset`. Delete that file to replay all alerts
in `alerts.json` from the start (useful for testing, noisy in production).

---

## 4. Common Tasks

### Add a Wazuh agent

From the Wazuh dashboard: **Agents → Deploy new agent**, pick the target OS,
copy the generated install command, run it on the endpoint. Or manually:

```bash
# On the manager — register and get the agent key
sudo /var/ossec/bin/manage_agents

# On the endpoint (Linux example)
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.12.0-1_amd64.deb
sudo WAZUH_MANAGER='<manager-ip>' dpkg -i ./wazuh-agent.deb
sudo systemctl enable --now wazuh-agent
```

### Connect Cortex to TheHive

1. In Cortex: create an organization, create a user with `read`/`analyze`
   role, generate its API key.
2. In TheHive: **Org Admin → Settings → Connectors → Cortex**, add server URL
   `http://cortex:9001` (Docker service name, since both are on `soc-net`)
   and the API key from step 1.
3. Enable the analyzers you want under Cortex's org admin panel first — none
   are enabled by default.

### Pull additional Cortex analyzers

The base Cortex image doesn't bundle most analyzers (they're separate Docker
images/scripts maintained at `TheHive-Project/Cortex-Analyzers`). For a lab,
the simplest path is enabling the flavor of analyzer that just needs an API
key (VirusTotal, AbuseIPDB, etc.) via Cortex's organization admin UI under
**Analyzers**, after cloning the analyzers repo and pointing Cortex's
`job_directory` config at it. This is intentionally left as a manual step —
it's account/API-key-specific and not something to automate blindly into a
shell script.

### Check what's eating your RAM

```bash
free -h
sudo systemctl status wazuh-indexer | grep Memory
docker stats --no-stream
```

If you're swapping heavily, the indexer or Cassandra heap is the usual
suspect. See the tuning section below.

---

## 5. Uninstall

```bash
sudo ./deploy-soc-stack.sh uninstall
```

Stops and removes all Docker containers/volumes, runs Wazuh's own uninstaller
(`wazuh-install.sh -u`), removes the bridge service. You'll be prompted
separately about whether to delete `/opt/soc-stack` (which holds TheHive's
case data, Cassandra data, and generated secrets) — say no if you might
reinstall and want to keep case history.

---

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Wazuh indexer won't start, OOM in `dmesg` | Heap too high for available RAM | Check `/etc/wazuh-indexer/jvm.options`, lower `-Xms`/`-Xmx` below current, `systemctl restart wazuh-indexer` |
| TheHive container restarts in a loop | Cassandra not ready yet, or secret mismatch | `docker compose -f docker-compose.hive.yml logs thehive` — if it's a CQL connection error, wait longer (Cassandra cold start is slow, 1-2 min); if it's a secret error, check `.env` wasn't regenerated after first boot |
| Cortex shows "Elasticsearch unreachable" | cortex-elasticsearch container unhealthy | `docker compose -f docker-compose.cortex.yml logs cortex-elasticsearch` — usually `vm.max_map_count` too low or heap OOM |
| Bridge logs "Could not reach TheHive" | TheHive not up yet, or wrong URL | Confirm `curl http://localhost:9000/api/status`, check `THEHIVE_URL` in `.env` |
| Bridge logs "TheHive rejected alert (401)" | Bad/expired API key | Regenerate the key in TheHive, `set-hive-key` again |
| Bridge logs "Could not reach n8n" | n8n not up, or `N8N_WEBHOOK_URL` wrong/empty | `curl http://localhost:5678/healthz`; re-run `set-n8n-webhook` with the exact Production URL from the webhook node |
| n8n workflow nodes show a red warning badge | TheHive API credential not yet created/selected | Follow "n8n SOAR setup" Step 3 — the imported JSON references a credential by name, not by embedded secret, so it must be created once in the UI |
| n8n execution succeeds but no case appears in TheHive | `THEHIVE_URL` inside the workflow can't reach TheHive's container | Confirm both `soc-n8n` and `soc-thehive` are on the `soc-net` Docker network: `docker network inspect soc-net`; the workflow's default `http://thehive:9000` only resolves via that shared network |
| n8n webhook returns 404 on the production URL | Workflow not activated | Toggle **Active** in the top-right of the n8n workflow editor — test URLs only work while the editor is open and listening |
| Cases pile up unassigned | `SOC_TRIAGE_ANALYST` not set (this is the default/expected behavior) | Either set it (see "n8n SOAR setup" optional step) or treat it as an intentional shared-queue model and assign manually |
| Everything is slow / load average high | Expected on 8GB under concurrent load, more so with n8n added | See sizing table below; avoid running Cortex analyzer jobs and n8n workflow bursts simultaneously |
| `vm.max_map_count` errors in OpenSearch/ES logs | Sysctl not applied (rare, e.g. after a kernel update) | `sudo sysctl -w vm.max_map_count=262144` |
| Disk filling up fast | Wazuh vulnerability detection DB, or Cassandra compaction | `df -h`, check `/var/ossec/var/db` and `/opt/soc-stack/cassandra` |

### Where the logs live

```
/var/log/soc-stack-install.log          # this script's own install log
/var/ossec/logs/ossec.log               # Wazuh manager
/var/ossec/logs/alerts/alerts.json      # Wazuh alerts (raw, what the bridge tails)
/var/log/wazuh-indexer/                 # OpenSearch logs
docker compose ... logs <service>       # TheHive/Cassandra/Cortex/Cortex-ES/n8n
journalctl -u wazuh-thehive-bridge      # bridge
# n8n's own execution history (incl. the Log Escalation console.log output)
# is also browsable in its UI under Executions, separate from container logs
```

---

## 7. Manual heap tuning reference

If `status` shows memory pressure, these are the four heap settings that
matter, in order of how much headroom they tend to need:

```bash
# Wazuh indexer (OpenSearch) — biggest consumer
sudo nano /etc/wazuh-indexer/jvm.options
# look for -Xms / -Xmx, default lab setting is 1500m
sudo systemctl restart wazuh-indexer

# Cassandra — set via Docker env, edit then recreate the container
sudo nano /opt/soc-stack/docker-compose.hive.yml   # MAX_HEAP_SIZE
cd /opt/soc-stack && docker compose -f docker-compose.hive.yml up -d --force-recreate cassandra

# TheHive
sudo nano /opt/soc-stack/docker-compose.hive.yml   # JVM_OPTS
cd /opt/soc-stack && docker compose -f docker-compose.hive.yml up -d --force-recreate thehive

# Cortex's Elasticsearch
sudo nano /opt/soc-stack/docker-compose.cortex.yml # ES_JAVA_OPTS
cd /opt/soc-stack && docker compose -f docker-compose.cortex.yml up -d --force-recreate cortex-elasticsearch
```

**Rule of thumb for JVM heaps:** never exceed 50% of total host RAM across
*all* heaps combined, and never set a single heap above ~31GB (JVM
compressed-oops cutoff — irrelevant at this scale, but good to know). On an
8GB host, the defaults baked into this script (1.5G + 1G + 1G + 0.5G = 4G
total heap) already use half your RAM before the OS, Docker daemon, or
anything else gets a look-in. Don't raise them without also raising RAM.

---

## 8. Sizing guidance

| Host RAM | Recommended approach |
|---|---|
| 8GB | This script's defaults, now including n8n (≈400MB cap). Swap as a safety net. Expect occasional slowness under concurrent ingest + case work + workflow execution. Fine for solo lab/portfolio use; avoid running Cortex analyzers and n8n workflows at the same time under load. |
| 16GB | Double the JVM heaps roughly (indexer 3G, Cassandra 2G, TheHive 2G, Cortex-ES 1G), n8n can stay as-is. Comfortable for one person actively using all five services. |
| 32GB+ | Use upstream defaults (indexer 4G+). Headroom for multiple agents, larger retention, more Cortex analyzers running concurrently, and n8n workflows with larger execution history (consider switching n8n to Postgres at this scale). |

---

## 9. File layout reference

```
/opt/soc-stack/
├── .env                          # generated secrets, API keys, n8n webhook URL
├── docker-compose.hive.yml
├── docker-compose.cortex.yml
├── docker-compose.n8n.yml
├── wazuh-passwords.txt           # generated Wazuh admin/API creds
├── wazuh-install-files.tar       # Wazuh's own cert/password bundle
├── thehive/
│   ├── data/                     # TheHive app data (Lucene index, etc.)
│   └── files/                    # case attachments (local fs storage)
├── cassandra/data/                # Cassandra data dir
├── cortex/
│   ├── es-data/                  # Cortex's Elasticsearch data
│   └── jobs/                     # analyzer job scratch space
├── n8n/
│   └── data/                     # n8n's SQLite DB, workflows, credentials (encrypted), execution history
└── bridge/
    ├── bridge.py
    ├── requirements.txt
    ├── venv/
    └── .alerts.offset

/var/lib/soc-stack/                # install stage markers (*.done)
/var/log/soc-stack-install.log     # install log

<script-dir>/files/
├── wazuh_thehive_bridge.py
├── bridge-requirements.txt
└── n8n-wazuh-thehive-soar-workflow.json   # import this into n8n once (see "n8n SOAR setup")
```
