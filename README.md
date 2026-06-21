# SOC Lab

## 1. Architecture

| Component              | How it runs                 | Port                          | Purpose                               |
|------------------------|-----------------------------|-------------------------------|---------------------------------------|
| Wazuh manager          | native systemd              | 1514/tcp, 1515/tcp, 55000/tcp | Agent comms, rule engine              |
| Wazuh indexer          | native systemd (OpenSearch) | 9200/tcp                      | Alert storage/search                  |
| Wazuh dashboard        | native systemd              | 443/tcp                       | Web UI                                |
| Cassandra              | Docker                      | 9042/tcp (internal)           | TheHive's database                    |
| TheHive                | Docker                      | 9000/tcp                      | Case management UI/API                |
| Cortex                 | Docker                      | 9001/tcp                      | Observable analysis/enrichment        |
| Cortex's Elasticsearch | Docker                      | internal only                 | Cortex's own search index             |
| Alert bridge           | systemd (Python venv)       | n/a                           | Tails Wazuh alerts → posts to TheHive |

Wazuh stays native because its installer owns OpenSearch directly and fighting
that is more trouble than it's worth. TheHive/Cortex run in Docker because
their official deployment path is container-first and it keeps Cassandra/ES
cleanly isolated. Storage for TheHive attachments is local filesystem
(`/opt/soc-stack/thehive/files`), not S3/MinIO — one less moving part.

---

## 2. Installation

```bash
# Full stack, all components
sudo ./deploy-soc-stack.sh install

# Just one piece (useful for staged installs or re-runs after a failure)
sudo ./deploy-soc-stack.sh install wazuh
sudo ./deploy-soc-stack.sh install hive
sudo ./deploy-soc-stack.sh install cortex
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

### TheHive / Cassandra / Cortex (Docker)

```bash
cd /opt/soc-stack

# View logs
docker compose -f docker-compose.hive.yml logs -f thehive
docker compose -f docker-compose.hive.yml logs -f cassandra
docker compose -f docker-compose.cortex.yml logs -f cortex

# Restart a single service
docker compose -f docker-compose.hive.yml restart thehive

# Stop everything (data persists in /opt/soc-stack volumes)
docker compose -f docker-compose.hive.yml down
docker compose -f docker-compose.cortex.yml down

# Bring back up
docker compose -f docker-compose.hive.yml --env-file .env up -d
docker compose -f docker-compose.cortex.yml --env-file .env up -d
```

### Alert bridge

```bash
sudo systemctl {start|stop|restart|status} wazuh-thehive-bridge
sudo journalctl -u wazuh-thehive-bridge -f

# Re-point it at a different TheHive instance or change thresholds
sudo nano /opt/soc-stack/.env
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
|-------------------------------------------------|-----------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Wazuh indexer won't start, OOM in `dmesg`       | Heap too high for available RAM                           | Check `/etc/wazuh-indexer/jvm.options`, lower `-Xms`/`-Xmx` below current, `systemctl restart wazuh-indexer` |
| TheHive container restarts in a loop            | Cassandra not ready yet, or secret mismatch               | `docker compose -f docker-compose.hive.yml logs thehive` — if it's a CQL connection error, wait longer (Cassandra cold start is slow, 1-2 min); if it's a secret error, check `.env` wasn't regenerated after first boot |
| Cortex shows "Elasticsearch unreachable"        | cortex-elasticsearch container unhealthy                  | `docker compose -f docker-compose.cortex.yml logs cortex-elasticsearch` — usually `vm.max_map_count` too low or heap OOM |
| Bridge logs "Could not reach TheHive"           | TheHive not up yet, or wrong URL                          | Confirm `curl http://localhost:9000/api/status`, check `THEHIVE_URL` in `.env` |
| Bridge logs "TheHive rejected alert (401)"      | Bad/expired API key                                       | Regenerate the key in TheHive, `set-hive-key` again |
| Everything is slow / load average high          | Expected on 8GB under concurrent load                     | See sizing table below; consider disabling Cortex's ES `xpack` features further or reducing Wazuh's retention |
| `vm.max_map_count` errors in OpenSearch/ES logs | Sysctl not applied (rare, e.g. after a kernel update)     | `sudo sysctl -w vm.max_map_count=262144` |
| Disk filling up fast                            | Wazuh vulnerability detection DB, or Cassandra compaction | `df -h`, check `/var/ossec/var/db` and `/opt/soc-stack/cassandra` |

### Where the logs live

```
/var/log/soc-stack-install.log          # this script's own install log
/var/ossec/logs/ossec.log               # Wazuh manager
/var/ossec/logs/alerts/alerts.json      # Wazuh alerts (raw, what the bridge tails)
/var/log/wazuh-indexer/                 # OpenSearch logs
docker compose ... logs <service>       # TheHive/Cassandra/Cortex/Cortex-ES
journalctl -u wazuh-thehive-bridge      # bridge
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

| Host RAM | Recommended approach                                                                                                                           |
|----------|------------------------------------------------------------------------------------------------------------------------------------------------|
| 8GB      | This script's defaults. Swap as a safety net. Expect occasional slowness under concurrent ingest + case work. Fine for solo lab/portfolio use. |
| 16GB     | Double the heaps roughly (indexer 3G, Cassandra 2G, TheHive 2G, Cortex-ES 1G). Comfortable for one person actively using all four services.    |
| 32GB+    | Use upstream defaults (indexer 4G+). Headroom for multiple agents, larger retention, more Cortex analyzers running concurrently.               |

---

## 9. File layout reference

```
/opt/soc-stack/
├── .env                          # generated secrets, API keys
├── docker-compose.hive.yml
├── docker-compose.cortex.yml
├── wazuh-passwords.txt           # generated Wazuh admin/API creds
├── wazuh-install-files.tar       # Wazuh's own cert/password bundle
├── thehive/
│   ├── data/                     # TheHive app data (Lucene index, etc.)
│   └── files/                    # case attachments (local fs storage)
├── cassandra/data/                # Cassandra data dir
├── cortex/
│   ├── es-data/                  # Cortex's Elasticsearch data
│   └── jobs/                     # analyzer job scratch space
└── bridge/
    ├── bridge.py
    ├── requirements.txt
    ├── venv/
    └── .alerts.offset

/var/lib/soc-stack/                # install stage markers (*.done)
/var/log/soc-stack-install.log     # install log
```
