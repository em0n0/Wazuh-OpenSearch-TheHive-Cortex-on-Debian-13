#!/usr/bin/env bash
#
# deploy-soc-stack.sh
#
# Deploys an all-in-one SOC home lab on a single Debian 13 (Trixie) host:
#   - Wazuh 4.12 (manager + indexer/OpenSearch + dashboard) — native packages
#   - TheHive 5.2 + Cassandra — Docker, local filesystem storage (no MinIO)
#   - Cortex 3 + Elasticsearch (Cortex's own index backend) — Docker
#   - A lightweight Python webhook bridge: Wazuh alerts -> TheHive alerts
#
# Target spec: 8GB RAM / 4 vCPU. This is a TIGHT fit for four heavy JVM-based
# services. JVM heaps are deliberately undersized vs. upstream defaults and a
# swap file is added as a safety net. Expect slower indexing/search than a
# 16GB+ box. See the companion CLI-REFERENCE.md for day-2 operations.
#
# Usage:
#   sudo ./deploy-soc-stack.sh install        # full install, all components
#   sudo ./deploy-soc-stack.sh install wazuh  # only the Wazuh stack
#   sudo ./deploy-soc-stack.sh install hive   # only TheHive+Cassandra
#   sudo ./deploy-soc-stack.sh install cortex # only Cortex+ES
#   sudo ./deploy-soc-stack.sh install bridge # only the alert bridge
#   sudo ./deploy-soc-stack.sh status         # health check all components
#   sudo ./deploy-soc-stack.sh uninstall      # tear everything down
#
# Re-run safe: each stage checks for prior completion via marker files in
# /var/lib/soc-stack/ and skips work already done, unless --force is passed.
#
set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# Globals
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="/var/lib/soc-stack"
LOG_FILE="/var/log/soc-stack-install.log"
STACK_DIR="/opt/soc-stack"
ENV_FILE="${STACK_DIR}/.env"

WAZUH_VERSION="4.12"
WAZUH_INSTALL_URL="https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"

THEHIVE_IMAGE="strangebee/thehive:5.2"
CASSANDRA_IMAGE="cassandra:4"
CORTEX_IMAGE="thehiveproject/cortex:3.1.7"
CORTEX_ES_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:7.17.9"

FORCE=0
COMPONENT="${2:-all}"

# Conservative JVM heaps for an 8GB host. Wazuh indexer normally wants 4G;
# we cut it to 1.5G. Cortex's ES gets 512M. TheHive gets 1G. Cassandra is
# capped via Docker mem_limit + its own heap env vars.
WAZUH_INDEXER_HEAP="1500m"
CORTEX_ES_HEAP="512m"
THEHIVE_HEAP="1024m"
CASSANDRA_HEAP="1024m"

# ============================================================================
# Helpers
# ============================================================================
log()   { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
info()  { log "INFO:  $*"; }
warn()  { log "WARN:  $*"; }
err()   { log "ERROR: $*"; }
die()   { err "$*"; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)."
}

mark_done()   { mkdir -p "$STATE_DIR"; touch "${STATE_DIR}/$1.done"; }
is_done()     { [[ -f "${STATE_DIR}/$1.done" && $FORCE -eq 0 ]]; }

rand_secret() { openssl rand -hex 24; }

confirm() {
    local prompt="$1"
    read -r -p "${prompt} [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

check_resources() {
    local mem_gb cpu_count disk_gb
    mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
    cpu_count=$(nproc)
    disk_gb=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')

    info "Detected: ${mem_gb}GB RAM, ${cpu_count} vCPU, ${disk_gb}GB free on /"

    if (( mem_gb < 7 )); then
        warn "Less than 7GB RAM detected. This stack targets 8GB minimum and"
        warn "will be unstable below that. Continuing anyway, but expect OOM kills."
    fi
    if (( disk_gb < 40 )); then
        warn "Less than 40GB free disk. Wazuh's vulnerability DB alone can use"
        warn "~7-8GB during initial sync. Recommend at least 50GB total."
    fi
    if (( cpu_count < 4 )); then
        warn "Fewer than 4 vCPUs detected. Indexing/search latency will suffer."
    fi
}

# ============================================================================
# Stage 0: OS prep, swap, Docker
# ============================================================================
stage_prereqs() {
    if is_done "prereqs"; then info "Prereqs already done, skipping."; return; fi
    info "=== Stage: OS prerequisites ==="

    apt-get update -y
    apt-get install -y --no-install-recommends \
        curl wget gnupg apt-transport-https ca-certificates \
        software-properties-common openssl jq python3 python3-pip python3-venv \
        unzip lsb-release

    # Debian 13 note: the upstream wazuh-install.sh script references
    # software-properties-common in an apt check that fails on Trixie's
    # package naming. We install it ourselves above so the script's check
    # passes without needing to patch the installer.

    setup_swap
    install_docker

    mkdir -p "$STACK_DIR" "$STATE_DIR"
    mark_done "prereqs"
}

setup_swap() {
    if swapon --show | grep -q .; then
        info "Swap already active, skipping swap setup."
        return
    fi
    info "No swap detected. Adding a 4GB swap file (recommended for 8GB hosts running this stack)."
    fallocate -l 4G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    # Lower swappiness so swap is a safety net, not primary memory
    sysctl -w vm.swappiness=10
    if ! grep -q 'vm.swappiness' /etc/sysctl.conf; then
        echo 'vm.swappiness=10' >> /etc/sysctl.conf
    fi
}

install_docker() {
    if command -v docker &>/dev/null; then
        info "Docker already installed, skipping."
        return
    fi
    info "Installing Docker Engine..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
}

# Required OpenSearch system tweaks (mmap counts), applies regardless of
# whether we hit them via native Wazuh or any future container indexer.
apply_vm_max_map_count() {
    sysctl -w vm.max_map_count=262144
    if ! grep -q 'vm.max_map_count' /etc/sysctl.conf; then
        echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
    fi
}

# ============================================================================
# Stage 1: Wazuh (native, all-in-one installer)
# ============================================================================
stage_wazuh() {
    if is_done "wazuh"; then info "Wazuh already installed, skipping."; return; fi
    info "=== Stage: Wazuh ${WAZUH_VERSION} (manager + indexer + dashboard) ==="

    apply_vm_max_map_count

    local work=/tmp/wazuh-install
    mkdir -p "$work" && cd "$work"
    curl -sO "$WAZUH_INSTALL_URL"
    chmod +x wazuh-install.sh

    info "Running Wazuh all-in-one installer (this takes 5-15 minutes)..."
    bash wazuh-install.sh -a -i | tee -a "$LOG_FILE"

    # Capture generated passwords for our reference file before they scroll away
    if [[ -f wazuh-install-files.tar ]]; then
        tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt \
            > "${STACK_DIR}/wazuh-passwords.txt" 2>/dev/null || true
        mv wazuh-install-files.tar "${STACK_DIR}/wazuh-install-files.tar"
        chmod 600 "${STACK_DIR}/wazuh-passwords.txt" 2>/dev/null || true
    fi

    tune_wazuh_indexer_heap
    mark_done "wazuh"
    info "Wazuh installed. Dashboard: https://<host-ip>/  (see ${STACK_DIR}/wazuh-passwords.txt for admin creds)"
}

tune_wazuh_indexer_heap() {
    local jvm_opts="/etc/wazuh-indexer/jvm.options"
    [[ -f "$jvm_opts" ]] || { warn "jvm.options not found at $jvm_opts, skipping heap tune."; return; }

    info "Tuning Wazuh indexer JVM heap to ${WAZUH_INDEXER_HEAP} (default 4G is too much for 8G hosts)."
    sed -i -E "s/^-Xms[0-9]+[mMgG]/-Xms${WAZUH_INDEXER_HEAP}/" "$jvm_opts"
    sed -i -E "s/^-Xmx[0-9]+[mMgG]/-Xmx${WAZUH_INDEXER_HEAP}/" "$jvm_opts"
    systemctl restart wazuh-indexer
}

# ============================================================================
# Stage 2: TheHive + Cassandra (Docker, local filesystem storage)
# ============================================================================
stage_hive() {
    if is_done "hive"; then info "TheHive already installed, skipping."; return; fi
    info "=== Stage: TheHive 5.2 + Cassandra (Docker, local fs storage) ==="

    mkdir -p "${STACK_DIR}/thehive/data" "${STACK_DIR}/thehive/files" \
             "${STACK_DIR}/cassandra/data"
    chmod 700 "${STACK_DIR}/thehive/files"

    ensure_env_file
    write_hive_compose
    write_hive_config

    cd "$STACK_DIR"
    docker compose -f docker-compose.hive.yml --env-file "$ENV_FILE" up -d

    info "Waiting for TheHive to become healthy (can take 2-3 minutes on first boot)..."
    wait_for_http "http://localhost:9000/api/status" 180

    mark_done "hive"
    info "TheHive installed. UI: http://<host-ip>:9000  (default org login: admin@thehive.local / secret)"
}

write_hive_compose() {
    cat > "${STACK_DIR}/docker-compose.hive.yml" <<EOF
services:
  cassandra:
    image: ${CASSANDRA_IMAGE}
    container_name: soc-cassandra
    restart: unless-stopped
    mem_limit: 1200m
    environment:
      - CASSANDRA_CLUSTER_NAME=TheHive
      - MAX_HEAP_SIZE=${CASSANDRA_HEAP}
      - HEAP_NEWSIZE=200M
    volumes:
      - ${STACK_DIR}/cassandra/data:/var/lib/cassandra
    networks:
      - soc-net
    healthcheck:
      test: ["CMD-SHELL", "cqlsh -e 'describe cluster' || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 10

  thehive:
    image: ${THEHIVE_IMAGE}
    container_name: soc-thehive
    restart: unless-stopped
    mem_limit: 1500m
    depends_on:
      - cassandra
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms${THEHIVE_HEAP} -Xmx${THEHIVE_HEAP}
    command:
      - --secret
      - "\${THEHIVE_SECRET}"
      - --cql-hostnames
      - "cassandra"
      - --index-backend
      - "lucene"
      - --storage-provider
      - "localfs"
      - --storage-localfs-location
      - "/opt/thp/thehive/files"
    volumes:
      - ${STACK_DIR}/thehive/data:/opt/thp/thehive/data
      - ${STACK_DIR}/thehive/files:/opt/thp/thehive/files
    networks:
      - soc-net

networks:
  soc-net:
    name: soc-net
    external: true
EOF
}

write_hive_config() {
    # Placeholder for future application.conf overrides if needed; the
    # CLI flags above cover the lab configuration so this is a no-op today.
    :
}

# ============================================================================
# Stage 3: Cortex + its own Elasticsearch (Docker)
# ============================================================================
stage_cortex() {
    if is_done "cortex"; then info "Cortex already installed, skipping."; return; fi
    info "=== Stage: Cortex 3 + Elasticsearch (Docker) ==="

    mkdir -p "${STACK_DIR}/cortex/es-data" "${STACK_DIR}/cortex/jobs"
    ensure_env_file
    write_cortex_compose

    cd "$STACK_DIR"
    docker compose -f docker-compose.cortex.yml --env-file "$ENV_FILE" up -d

    info "Waiting for Cortex to become healthy (can take 1-2 minutes)..."
    wait_for_http "http://localhost:9001/api/status" 120

    mark_done "cortex"
    info "Cortex installed. UI: http://<host-ip>:9001  (create the initial superadmin via the setup wizard on first visit)"
}

write_cortex_compose() {
    cat > "${STACK_DIR}/docker-compose.cortex.yml" <<EOF
services:
  cortex-elasticsearch:
    image: ${CORTEX_ES_IMAGE}
    container_name: soc-cortex-es
    restart: unless-stopped
    mem_limit: 700m
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms${CORTEX_ES_HEAP} -Xmx${CORTEX_ES_HEAP}
    volumes:
      - ${STACK_DIR}/cortex/es-data:/usr/share/elasticsearch/data
    networks:
      - soc-net
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9200"]
      interval: 30s
      timeout: 10s
      retries: 10

  cortex:
    image: ${CORTEX_IMAGE}
    container_name: soc-cortex
    restart: unless-stopped
    mem_limit: 1000m
    depends_on:
      - cortex-elasticsearch
    ports:
      - "9001:9001"
    environment:
      - es_uri=http://cortex-elasticsearch:9200
      - job_directory=/tmp/cortex-jobs
      - docker_job_directory=/tmp/cortex-jobs
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ${STACK_DIR}/cortex/jobs:/tmp/cortex-jobs
    networks:
      - soc-net

networks:
  soc-net:
    name: soc-net
    external: true
EOF
}

# ============================================================================
# Stage 4: Wazuh -> TheHive alert bridge
# ============================================================================
stage_bridge() {
    if is_done "bridge"; then info "Alert bridge already installed, skipping."; return; fi
    info "=== Stage: Wazuh -> TheHive alert bridge ==="

    if [[ ! -f "${ENV_FILE}" ]] || ! grep -q THEHIVE_API_KEY "${ENV_FILE}" 2>/dev/null; then
        warn "THEHIVE_API_KEY not set in ${ENV_FILE}."
        warn "Create an org-level API key in TheHive (Org Admin -> Users -> your user -> API key)"
        warn "then run: ./deploy-soc-stack.sh set-hive-key <key>"
        warn "The bridge will install but stay inactive until the key is set."
    fi

    install -d -m 755 /opt/soc-stack/bridge
    cp "${SCRIPT_DIR}/files/wazuh_thehive_bridge.py" /opt/soc-stack/bridge/bridge.py
    cp "${SCRIPT_DIR}/files/bridge-requirements.txt" /opt/soc-stack/bridge/requirements.txt

    python3 -m venv /opt/soc-stack/bridge/venv
    /opt/soc-stack/bridge/venv/bin/pip install --quiet --upgrade pip
    /opt/soc-stack/bridge/venv/bin/pip install --quiet -r /opt/soc-stack/bridge/requirements.txt

    write_bridge_service
    write_bridge_filebeat_hook

    systemctl daemon-reload
    systemctl enable wazuh-thehive-bridge.service

    mark_done "bridge"
    info "Bridge installed but NOT started (needs THEHIVE_API_KEY)."
    info "Set the key, then: systemctl start wazuh-thehive-bridge"
}

write_bridge_service() {
    cat > /etc/systemd/system/wazuh-thehive-bridge.service <<EOF
[Unit]
Description=Wazuh alert -> TheHive case bridge
After=network.target docker.service wazuh-manager.service
Wants=network.target

[Service]
Type=simple
EnvironmentFile=-${ENV_FILE}
ExecStart=/opt/soc-stack/bridge/venv/bin/python3 /opt/soc-stack/bridge/bridge.py
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
}

write_bridge_filebeat_hook() {
    # The bridge tails Wazuh's alerts.json directly rather than hooking
    # Filebeat, which keeps it decoupled from the indexer pipeline and
    # working even if OpenSearch ingest is lagging.
    info "Bridge will tail /var/ossec/logs/alerts/alerts.json directly."
}

# ============================================================================
# Networking
# ============================================================================
ensure_network() {
    docker network inspect soc-net &>/dev/null || docker network create soc-net
}

ensure_env_file() {
    mkdir -p "$STACK_DIR"
    ensure_network
    if [[ -f "$ENV_FILE" ]]; then return; fi
    info "Generating ${ENV_FILE} with random secrets."
    cat > "$ENV_FILE" <<EOF
# Generated by deploy-soc-stack.sh on $(date -Iseconds)
THEHIVE_SECRET=$(rand_secret)
THEHIVE_API_KEY=
WAZUH_API_USER=wazuh-wui
EOF
    chmod 600 "$ENV_FILE"
}

wait_for_http() {
    local url="$1" timeout="$2" waited=0
    until curl -sf "$url" -o /dev/null 2>/dev/null; do
        sleep 5; waited=$((waited+5))
        if (( waited >= timeout )); then
            warn "$url did not become healthy within ${timeout}s. Check logs with 'docker compose logs'."
            return 1
        fi
    done
    info "$url is healthy (${waited}s)"
}

# ============================================================================
# Status / Uninstall
# ============================================================================
cmd_status() {
    echo "=== Wazuh ==="
    systemctl is-active wazuh-manager 2>/dev/null   | xargs echo "  manager:  "
    systemctl is-active wazuh-indexer 2>/dev/null   | xargs echo "  indexer:  "
    systemctl is-active wazuh-dashboard 2>/dev/null | xargs echo "  dashboard:"
    echo
    echo "=== Docker containers ==="
    docker ps --filter "name=soc-" --format "  {{.Names}}: {{.Status}}" 2>/dev/null || echo "  Docker not running or no containers found."
    echo
    echo "=== Alert bridge ==="
    systemctl is-active wazuh-thehive-bridge 2>/dev/null | xargs echo "  bridge:   "
    echo
    echo "=== Resource usage ==="
    free -h | head -2
    echo
    docker stats --no-stream --format "  {{.Name}}: CPU {{.CPUPerc}}  MEM {{.MemUsage}}" 2>/dev/null || true
}

cmd_set_hive_key() {
    local key="${1:-}"
    [[ -n "$key" ]] || die "Usage: $0 set-hive-key <api-key>"
    [[ -f "$ENV_FILE" ]] || die "${ENV_FILE} not found. Run install first."
    sed -i "s|^THEHIVE_API_KEY=.*|THEHIVE_API_KEY=${key}|" "$ENV_FILE"
    info "THEHIVE_API_KEY updated. Restarting bridge..."
    systemctl restart wazuh-thehive-bridge 2>/dev/null || info "Bridge not yet installed/started; will pick up key on next start."
}

cmd_uninstall() {
    confirm "This will STOP and REMOVE Wazuh, TheHive, Cortex, and all their data. Continue?" || { info "Aborted."; exit 0; }

    info "Stopping Docker stack..."
    cd "$STACK_DIR" 2>/dev/null && {
        docker compose -f docker-compose.hive.yml down -v 2>/dev/null || true
        docker compose -f docker-compose.cortex.yml down -v 2>/dev/null || true
    }
    docker network rm soc-net 2>/dev/null || true

    info "Stopping bridge..."
    systemctl stop wazuh-thehive-bridge 2>/dev/null || true
    systemctl disable wazuh-thehive-bridge 2>/dev/null || true
    rm -f /etc/systemd/system/wazuh-thehive-bridge.service

    info "Uninstalling Wazuh..."
    if [[ -f /tmp/wazuh-install/wazuh-install.sh ]]; then
        bash /tmp/wazuh-install/wazuh-install.sh -u | tee -a "$LOG_FILE" || true
    else
        warn "wazuh-install.sh not found in /tmp; remove Wazuh packages manually if needed:"
        warn "  apt-get purge wazuh-manager wazuh-indexer wazuh-dashboard"
    fi

    read -r -p "Also delete ${STACK_DIR} (TheHive/Cortex data, configs, generated secrets)? [y/N] " r
    if [[ "$r" =~ ^[Yy]$ ]]; then
        rm -rf "$STACK_DIR"
    fi

    rm -rf "$STATE_DIR"
    info "Uninstall complete."
}

# ============================================================================
# Main
# ============================================================================
main() {
    local cmd="${1:-}"

    if [[ "$cmd" == "--force" ]]; then FORCE=1; cmd="${2:-}"; COMPONENT="${3:-all}"; fi

    case "$cmd" in
        install)
            require_root
            mkdir -p "$STATE_DIR"
            touch "$LOG_FILE"
            check_resources
            ensure_network
            case "$COMPONENT" in
                all)
                    stage_prereqs
                    stage_wazuh
                    stage_hive
                    stage_cortex
                    stage_bridge
                    ;;
                wazuh)  stage_prereqs; stage_wazuh ;;
                hive)   stage_prereqs; stage_hive ;;
                cortex) stage_prereqs; stage_cortex ;;
                bridge) stage_bridge ;;
                *) die "Unknown component '$COMPONENT'. Use: all|wazuh|hive|cortex|bridge" ;;
            esac
            echo
            info "=== Install complete. Run '$0 status' to check health. ==="
            [[ -f "${STACK_DIR}/wazuh-passwords.txt" ]] && info "Wazuh credentials: ${STACK_DIR}/wazuh-passwords.txt"
            ;;
        status)
            cmd_status
            ;;
        set-hive-key)
            require_root
            cmd_set_hive_key "${2:-}"
            ;;
        uninstall)
            require_root
            cmd_uninstall
            ;;
        *)
            echo "Usage: $0 {install [all|wazuh|hive|cortex|bridge]|status|set-hive-key <key>|uninstall} [--force]"
            exit 1
            ;;
    esac
}

main "$@"
