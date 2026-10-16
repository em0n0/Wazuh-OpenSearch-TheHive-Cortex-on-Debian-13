#!/usr/bin/env bash
#
# deploy-soc-stack.sh  —  v2.0  (battle-tested on Debian 13 Trixie)
#
# Deploys an all-in-one SOC home lab on a single Debian 13 host:
#   - Wazuh 4.x  (manager + indexer/OpenSearch + dashboard)  — native packages
#   - TheHive 5.2 + Cassandra                                — Docker
#   - Cortex 3   + Elasticsearch 7.17                        — Docker
#   - Python alert bridge: Wazuh alerts -> TheHive           — systemd service
#
# Target spec: 8GB RAM / 4+ vCPU  (tight but proven to work)
#
# Usage:
#   sudo ./deploy-soc-stack.sh install              # interactive: asks which components (TheHive, Cortex, n8n, IPS, WIPS...)
#   sudo ./deploy-soc-stack.sh --yes install        # non-interactive: "all" (+ whatever the --config enables)
#   sudo ./deploy-soc-stack.sh install wazuh        # Wazuh only
#   sudo ./deploy-soc-stack.sh install hive         # TheHive + Cassandra only
#   sudo ./deploy-soc-stack.sh install cortex       # Cortex + ES only
#   sudo ./deploy-soc-stack.sh install bridge       # alert bridge only
#   sudo ./deploy-soc-stack.sh install n8n --config soc.json   # n8n email alerts
#   sudo ./deploy-soc-stack.sh install users --config soc.json # extra Wazuh users
#   sudo ./deploy-soc-stack.sh install wazuh,hive,n8n --config soc.json   # any combination
#   sudo ./deploy-soc-stack.sh install suricata --config soc.json  # inline IPS (NFQUEUE)
#   sudo ./deploy-soc-stack.sh install wips --config soc.json       # Kismet wireless IDS
#   sudo ./deploy-soc-stack.sh status               # health check all
#   sudo ./deploy-soc-stack.sh set-hive-key <key>   # update TheHive API key
#   sudo ./deploy-soc-stack.sh upgrade [4.14.9]     # safe Wazuh upgrade: backup, keep your configs, health checks
#   sudo ./deploy-soc-stack.sh uninstall            # tear down everything
#   sudo ./deploy-soc-stack.sh --force install hive # re-run a stage
#
# ─── --config FILE (written by ./soc-deploy, or by hand) ─────────────────────
# A JSON file, chmod 600, that carries secrets so they never appear in argv:
#   {
#     "wazuh_users": [ {"username":"alice","password":"S3cure!pass","role":"analyst"} ],
#     "n8n": {
#       "enabled": true, "min_level": 10, "send_test": true,
#       "smtp": {"host":"smtp.gmail.com","port":465,"user":"me@gmail.com",
#                "password":"app-password","from":"me@gmail.com"},
#       "recipients": ["soc@example.com"]
#     },
#     "suricata": { "enabled": true, "mode": "detect",          # detect (default) | prevent
#                   "interface": "auto", "ssh_ports": [22] },
#     "wips":     { "enabled": true, "interface": "wlan1",    # 2nd, monitor-mode-capable adapter
#                   "user": "kismet", "password": "...",       # optional; random if omitted
#                   "own_ssids": { "HomeNet": ["AA:BB:CC:DD:EE:FF"] } }   # your SSID -> its BSSIDs
#   }
# Roles: admin | analyst | viewer.   "install all" includes n8n only when
# n8n.enabled is true, and creates users whenever wazuh_users is non-empty.
# ─────────────────────────────────────────────────────────────────────────────
#
# ─── POST-UPGRADE WARNING ────────────────────────────────────────────────────
# If you run "apt upgrade" and choose Y to overwrite Wazuh config files, the
# dashboard will break. See CLI-REFERENCE.md § "Post-upgrade recovery".
# Wazuh packages are held after install to prevent this. To upgrade deliberately:
#   sudo apt-mark unhold wazuh-manager wazuh-indexer wazuh-dashboard
# ─────────────────────────────────────────────────────────────────────────────
#
# ─── THEHIVE API KEY REQUIREMENTS ────────────────────────────────────────────
# The API key for the alert bridge MUST belong to an org-level user (not the
# platform superadmin). The user must have the "analyst" or "org-admin" profile
# inside the organisation that will receive alerts.
# See CLI-REFERENCE.md § "TheHive API key setup" for the exact steps.
# ─────────────────────────────────────────────────────────────────────────────
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

WAZUH_INSTALL_URL="https://packages.wazuh.com/4.14/wazuh-install.sh"

THEHIVE_IMAGE="strangebee/thehive:5.2"
CASSANDRA_IMAGE="cassandra:4"
CORTEX_IMAGE="thehiveproject/cortex:3.1.7"
CORTEX_ES_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:7.17.9"

N8N_IMAGE="${N8N_IMAGE:-docker.n8n.io/n8nio/n8n:latest}"   # override to pin a version

# Endpoints used by the users stage (overridable for testing)
WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-https://127.0.0.1:9200}"
WAZUH_API_URL="${WAZUH_API_URL:-https://127.0.0.1:55000}"

FORCE=0
CONFIG_FILE=""
COMPONENTS=""     # comma-separated list, resolved in main()
ASSUME_YES=0      # --yes: skip the interactive picker
RUNTIME_CFG=""

# Built-in accounts the users stage must never touch
RESERVED_USERS="admin kibanaserver kibanaro logstash readall snapshotrestore wazuh wazuh-wui"

# Conservative JVM heaps for 8GB host
WAZUH_INDEXER_HEAP="1500m"
CORTEX_ES_HEAP="512m"
THEHIVE_HEAP="1024m"
CASSANDRA_HEAP="1024m"

# ============================================================================
# Helpers
# ============================================================================
log()  { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
info() { log "INFO:  $*"; }
warn() { log "WARN:  $*"; }
err()  { log "ERROR: $*"; }
die()  { err "$*"; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }
mark_done()    { mkdir -p "$STATE_DIR"; touch "${STATE_DIR}/$1.done"; }
is_done()      { [[ -f "${STATE_DIR}/$1.done" && $FORCE -eq 0 ]]; }
rand_secret()  { openssl rand -hex 24; }

confirm() {
    read -r -p "${1} [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

check_resources() {
    local mem_gb cpu_count disk_gb
    mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
    cpu_count=$(nproc)
    disk_gb=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')
    info "Detected: ${mem_gb}GB RAM, ${cpu_count} vCPU, ${disk_gb}GB free on /"
    [[ $mem_gb -lt 7 ]] && warn "Less than 7GB RAM — expect OOM pressure under load." || true
    [[ $disk_gb -lt 40 ]] && warn "Less than 40GB free — Wazuh vuln DB alone uses ~8GB." || true
}

wait_for_http() {
    local url="$1" timeout="$2" waited=0
    until curl -sf "$url" -o /dev/null 2>/dev/null; do
        sleep 5; waited=$((waited+5))
        (( waited >= timeout )) && { warn "${url} not healthy after ${timeout}s."; return 1; }
    done
    info "${url} is healthy (${waited}s)"
}

ensure_network() {
    docker network inspect soc-net &>/dev/null || docker network create soc-net
}

# Upsert KEY=VALUE in the stack .env (values must not contain newlines)
set_env() {
    local key="$1" val="$2" tmp
    ensure_env_file
    tmp="$(mktemp)"
    grep -v "^${key}=" "$ENV_FILE" > "$tmp" || true
    printf '%s=%s\n' "$key" "$val" >> "$tmp"
    cat "$tmp" > "$ENV_FILE"      # keep inode + 600 perms
    rm -f "$tmp"
}

# Read a jq expression from the --config file; prints "" if unset/null
cfg() {
    [[ -n "$CONFIG_FILE" ]] || { echo ""; return 0; }
    jq -r "${1} // empty" "$CONFIG_FILE"
}

load_config() {
    [[ -z "$CONFIG_FILE" ]] && return 0
    [[ -f "$CONFIG_FILE" ]] || die "Config file not found: ${CONFIG_FILE}"
    jq -e . "$CONFIG_FILE" >/dev/null 2>&1 || die "Config file is not valid JSON: ${CONFIG_FILE}"
    local mode
    mode="$(stat -c '%a' "$CONFIG_FILE")"
    [[ "$mode" == "600" || "$mode" == "400" ]] \
        || warn "Config file ${CONFIG_FILE} has mode ${mode}; it contains secrets — chmod 600 it."
    info "Loaded config: ${CONFIG_FILE}"
}

# Locate a support file next to the script (files/ subdir or flat extract)
find_file() {
    local name="$1" c
    for c in "${SCRIPT_DIR}/files/${name}" "${SCRIPT_DIR}/${name}"; do
        [[ -f "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}

ensure_env_file() {
    mkdir -p "$STACK_DIR"
    if [[ ! -f "$ENV_FILE" ]]; then
        info "Generating ${ENV_FILE} with random secrets."
        cat > "$ENV_FILE" <<EOF
# Generated by deploy-soc-stack.sh on $(date -Iseconds)
THEHIVE_SECRET=$(rand_secret)
THEHIVE_API_KEY=
EOF
        chmod 600 "$ENV_FILE"
    fi
}

# ============================================================================
# Stage 0: OS prerequisites + swap + Docker
# ============================================================================
stage_prereqs() {
    if is_done "prereqs"; then info "Prereqs already done, skipping."; return; fi
    info "=== Stage: OS prerequisites ==="

    apt-get update -y
    # NOTE: software-properties-common does NOT exist on Debian 13 (Trixie).
    # It is intentionally omitted here. The Wazuh installer is patched below
    # to remove its reference to it before execution.
    apt-get install -y --no-install-recommends \
        curl wget gnupg apt-transport-https ca-certificates \
        openssl jq python3 python3-pip python3-venv \
        unzip lsb-release

    setup_swap
    install_docker
    mkdir -p "$STACK_DIR" "$STATE_DIR"
    mark_done "prereqs"
}

setup_swap() {
    swapon --show | grep -q . && { info "Swap already active, skipping."; return; }
    info "Adding 4GB swap file (recommended for 8GB hosts running this stack)..."
    fallocate -l 4G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    sysctl -w vm.swappiness=10
    touch /etc/sysctl.conf   # may not exist on minimal Debian 13 install
    grep -q 'vm.swappiness' /etc/sysctl.conf || echo 'vm.swappiness=10' >> /etc/sysctl.conf
}

install_docker() {
    if command -v docker &>/dev/null; then info "Docker already installed, skipping."; return; fi
    info "Installing Docker Engine..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/debian \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
}

apply_vm_max_map_count() {
    sysctl -w vm.max_map_count=262144
    touch /etc/sysctl.conf   # may not exist on minimal Debian 13 install
    grep -q 'vm.max_map_count' /etc/sysctl.conf || \
        echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
}

# ============================================================================
# Stage 1: Wazuh (native all-in-one installer)
# ============================================================================
stage_wazuh() {
    if is_done "wazuh"; then info "Wazuh already installed, skipping."; return; fi
    info "=== Stage: Wazuh (manager + indexer + dashboard) ==="

    apply_vm_max_map_count

    local work=/tmp/wazuh-install
    mkdir -p "$work" && cd "$work"
    # -f = fail on HTTP errors, -L = follow redirects, -O = save with remote filename
    curl -4 -fsSLO "$WAZUH_INSTALL_URL" || die "Failed to download Wazuh installer from ${WAZUH_INSTALL_URL}"
    chmod +x wazuh-install.sh

    # Debian 13 fix: Wazuh's installer tries to apt-install software-properties-common
    # which does not exist on Debian 13 Trixie. Strip it from the script before running.
    info "Patching wazuh-install.sh for Debian 13 compatibility..."
    sed -i 's/software-properties-common//g' wazuh-install.sh

    info "Running Wazuh all-in-one installer (this takes 5-15 minutes)..."
    bash wazuh-install.sh -a -i | tee -a "$LOG_FILE"

    # Save generated passwords before they scroll away
    if [[ -f wazuh-install-files.tar ]]; then
        tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt \
            > "${STACK_DIR}/wazuh-passwords.txt" 2>/dev/null || true
        mv wazuh-install-files.tar "${STACK_DIR}/wazuh-install-files.tar"
        chmod 600 "${STACK_DIR}/wazuh-passwords.txt" 2>/dev/null || true
    fi

    tune_wazuh_indexer_heap

    # Hold packages so "apt upgrade" never overwrites our config/certs.
    # To upgrade deliberately: apt-mark unhold wazuh-manager wazuh-indexer wazuh-dashboard
    info "Holding Wazuh packages to prevent accidental config overwrites on apt upgrade..."
    apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true

    mark_done "wazuh"
    info "Wazuh installed. Dashboard: https://<host-ip>"
    info "Credentials: ${STACK_DIR}/wazuh-passwords.txt"
}

tune_wazuh_indexer_heap() {
    local jvm_opts="/etc/wazuh-indexer/jvm.options"
    [[ -f "$jvm_opts" ]] || { warn "jvm.options not found, skipping heap tune."; return; }
    info "Tuning Wazuh indexer JVM heap to ${WAZUH_INDEXER_HEAP} (default 4G is too large for 8GB hosts)."
    sed -i -E "s/^-Xms[0-9]+[mMgG]/-Xms${WAZUH_INDEXER_HEAP}/" "$jvm_opts"
    sed -i -E "s/^-Xmx[0-9]+[mMgG]/-Xmx${WAZUH_INDEXER_HEAP}/" "$jvm_opts"
    systemctl restart wazuh-indexer
}

# ============================================================================
# Stage 2: TheHive 5.2 + Cassandra
# ============================================================================
stage_hive() {
    if is_done "hive"; then info "TheHive already installed, skipping."; return; fi
    info "=== Stage: TheHive 5.2 + Cassandra ==="

    mkdir -p "${STACK_DIR}/thehive/data" \
             "${STACK_DIR}/thehive/files" \
             "${STACK_DIR}/cassandra/data"

    # TheHive container runs as uid:gid 1000:1000 — host dirs must match.
    chown -R 1000:1000 "${STACK_DIR}/thehive"
    chmod 700 "${STACK_DIR}/thehive/files"

    # Cassandra container runs as uid:gid 999:999
    chown -R 999:999 "${STACK_DIR}/cassandra/data"

    ensure_env_file
    write_hive_compose

    cd "$STACK_DIR"
    docker compose -f docker-compose.hive.yml --env-file "$ENV_FILE" up -d

    info "Waiting for TheHive to become healthy (can take 3-5 minutes on first boot)..."
    wait_for_http "http://localhost:9000/api/status" 300

    mark_done "hive"
    info "TheHive installed. UI: http://<host-ip>:9000"
    info "Default login: admin@thehive.local / secret  (change on first login)"
    info ""
    info "IMPORTANT — API key setup for the alert bridge:"
    info "  1. Log in to TheHive as admin@thehive.local"
    info "  2. Create an organisation (e.g. SOC-Lab)"
    info "  3. Create an org-level user with 'analyst' or 'org-admin' profile"
    info "  4. Generate an API key for that user"
    info "  5. Run: sudo ./deploy-soc-stack.sh set-hive-key <key>"
    info "  The key MUST belong to an org-level user, not the platform superadmin."
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
      cassandra:
        condition: service_healthy
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
      - --storage-directory
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

# ============================================================================
# Stage 3: Cortex 3 + Elasticsearch
# ============================================================================
stage_cortex() {
    if is_done "cortex"; then info "Cortex already installed, skipping."; return; fi
    info "=== Stage: Cortex 3 + Elasticsearch ==="

    mkdir -p "${STACK_DIR}/cortex/es-data" "${STACK_DIR}/cortex/jobs"

    # Elasticsearch 7.x runs as uid:gid 1000:0 inside the container
    chown -R 1000:0 "${STACK_DIR}/cortex/es-data"
    chmod 750 "${STACK_DIR}/cortex/es-data"

    ensure_env_file
    write_cortex_compose

    cd "$STACK_DIR"

    # Start ES first independently — the compose healthcheck can fail even when
    # ES is running fine due to tool availability inside the container. Starting
    # ES and Cortex separately with --no-deps avoids the dependency trap entirely.
    info "Starting Cortex Elasticsearch..."
    docker compose -f docker-compose.cortex.yml --env-file "$ENV_FILE" \
        up -d cortex-elasticsearch --no-deps

    info "Waiting for Cortex Elasticsearch to accept connections..."
    local es_wait=0
    until curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1; do
        sleep 5; es_wait=$((es_wait+5))
        if (( es_wait >= 120 )); then
            warn "ES did not respond in 120s — starting Cortex anyway and hoping for the best."
            break
        fi
    done
    [[ $es_wait -lt 120 ]] && info "Elasticsearch ready (${es_wait}s)."

    info "Starting Cortex..."
    docker compose -f docker-compose.cortex.yml --env-file "$ENV_FILE" \
        up -d cortex --no-deps

    info "Waiting for Cortex API..."
    wait_for_http "http://localhost:9001/api/status" 120

    mark_done "cortex"
    info "Cortex installed. UI: http://<host-ip>:9001"
    info "Visit the URL to complete the first-time setup wizard (create org + superadmin)."
}

write_cortex_compose() {
    cat > "${STACK_DIR}/docker-compose.cortex.yml" <<EOF
services:
  cortex-elasticsearch:
    image: ${CORTEX_ES_IMAGE}
    container_name: soc-cortex-es
    restart: unless-stopped
    mem_limit: 800m
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms${CORTEX_ES_HEAP} -Xmx${CORTEX_ES_HEAP}
    volumes:
      - ${STACK_DIR}/cortex/es-data:/usr/share/elasticsearch/data
    networks:
      - soc-net

  cortex:
    image: ${CORTEX_IMAGE}
    container_name: soc-cortex
    restart: unless-stopped
    mem_limit: 1000m
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
# Stage 4: Extra Wazuh users (dashboard logins + API RBAC rules)
#
# "Wazuh users" are really two systems:
#   * Wazuh INDEXER (OpenSearch security) users  -> these are the dashboard logins
#   * Wazuh API RBAC (rules mapped to roles)     -> only enforced when the
#     dashboard runs with run_as: true (OFF by default; see CLI-REFERENCE.md)
# We create the indexer user + role mappings (always effective) and the API
# rules (harmless until run_as is enabled). Built-in accounts are never touched.
# ============================================================================

# curl with basic-auth credentials handed over on a private fd, never in argv
curl_auth() {
    local user="$1" pass="$2"; shift 2
    local esc="${pass//\\/\\\\}"; esc="${esc//\"/\\\"}"
    curl -sk -K <(printf 'user = "%s:%s"\n' "$user" "$esc") "$@"
}

# _http USER PASS METHOD URL [curl args]   (JSON body on stdin with --data-binary @-)
# Sets HTTP_CODE and HTTP_BODY. Returns 1 only when the connection itself failed.
_http() {
    local out
    out="$(curl_auth "$1" "$2" -X "$3" -H 'Content-Type: application/json' \
            -w $'\n%{http_code}' "$4" "${@:5}")" || { HTTP_CODE=000; HTTP_BODY=""; return 1; }
    HTTP_CODE="${out##*$'\n'}"
    HTTP_BODY="${out%$'\n'*}"
}

wazuh_pw() {   # wazuh_pw indexer_password | api_password | api_username ...
    sed -n "s/^[[:space:]]*${1}: '\(.*\)'[[:space:]]*$/\1/p" \
        "${STACK_DIR}/wazuh-passwords.txt" 2>/dev/null | head -1
}

is_reserved_user() {
    local u="$1" r
    local -a reserved=()
    IFS=' ' read -ra reserved <<< "$RESERVED_USERS"   # IFS is $'\n\t' globally
    for r in "${reserved[@]}"; do [[ "$u" == "$r" ]] && return 0; done
    return 1
}

# IFS is $'\n\t' in this script, so space-separated lists must be split explicitly
indexer_roles_for() {
    case "$1" in
        admin)   echo "all_access" ;;
        analyst) echo "kibana_user readall wazuh_ui_admin" ;;
        viewer)  echo "kibana_user readall wazuh_ui_user" ;;
    esac
}
api_roles_for() {
    case "$1" in
        admin)   echo "administrator" ;;
        analyst) echo "agents_admin cluster_readonly" ;;
        viewer)  echo "readonly" ;;
    esac
}

stage_users() {
    local count
    count="$(jq -r '(.wazuh_users // []) | length' "$CONFIG_FILE" 2>/dev/null || echo 0)"
    if [[ "$count" == "0" ]]; then info "No extra Wazuh users requested, skipping."; return 0; fi
    info "=== Stage: extra Wazuh users (${count}) ==="

    local idx_user idx_pass api_user api_pass
    idx_user="$(wazuh_pw indexer_username)"; idx_pass="$(wazuh_pw indexer_password)"
    api_user="$(wazuh_pw api_username)";     api_pass="$(wazuh_pw api_password)"
    if [[ -z "$idx_pass" ]]; then
        warn "Cannot read indexer admin password from ${STACK_DIR}/wazuh-passwords.txt — skipping users."
        warn "Run 'install users' again after restoring that file."
        return 0
    fi
    idx_user="${idx_user:-admin}"

    info "Waiting for the Wazuh indexer to accept authenticated requests..."
    local waited=0
    until _http "$idx_user" "$idx_pass" GET "${WAZUH_INDEXER_URL}/" && [[ "$HTTP_CODE" == "200" ]]; do
        sleep 5; waited=$((waited+5))
        if (( waited >= 180 )); then
            warn "Indexer not reachable (last HTTP ${HTTP_CODE:-000}) — skipping users."; return 0
        fi
    done

    _http "$idx_user" "$idx_pass" GET "${WAZUH_INDEXER_URL}/_plugins/_security/api/roles" || true
    local roles_json="${HTTP_BODY:-}"
    jq -e . <<< "$roles_json" >/dev/null 2>&1 || roles_json='{}'

    # Wazuh API token (best effort: RBAC rules only)
    local token=""
    if [[ -n "$api_pass" ]]; then
        token="$(curl_auth "${api_user:-wazuh}" "$api_pass" -X POST \
                  "${WAZUH_API_URL}/security/user/authenticate?raw=true" 2>/dev/null || true)"
        [[ "$token" == eyJ* ]] || { warn "Could not get a Wazuh API token — API RBAC rules will be skipped."; token=""; }
    fi

    local i name role pw body ok=0 failed=0
    for (( i=0; i<count; i++ )); do
        name="$(jq -r ".wazuh_users[$i].username // empty" "$CONFIG_FILE")"
        role="$(jq -r ".wazuh_users[$i].role // empty" "$CONFIG_FILE")"
        pw="$(jq -r ".wazuh_users[$i].password // empty" "$CONFIG_FILE")"

        if [[ ! "$name" =~ ^[A-Za-z0-9_.-]{3,32}$ ]]; then warn "Skipping invalid username '${name}'."; failed=$((failed+1)); continue; fi
        if is_reserved_user "$name"; then warn "Skipping '${name}': built-in account, will not modify."; failed=$((failed+1)); continue; fi
        case "$role" in admin|analyst|viewer) ;; *) warn "Skipping '${name}': unknown role '${role}'."; failed=$((failed+1)); continue ;; esac
        if (( ${#pw} < 8 )); then warn "Skipping '${name}': password shorter than 8 characters."; failed=$((failed+1)); continue; fi

        # 1) indexer internal user (create or reset password)
        body="$(PW="$pw" jq -nc '{password: env.PW, backend_roles: [], attributes: {created_by: "soc-deploy"}}')"
        _http "$idx_user" "$idx_pass" PUT \
            "${WAZUH_INDEXER_URL}/_plugins/_security/api/internalusers/${name}" \
            --data-binary @- <<< "$body" || true
        if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "201" ]]; then
            warn "Indexer user '${name}' failed (HTTP ${HTTP_CODE}): $(echo "$HTTP_BODY" | head -c 200)"
            failed=$((failed+1)); continue
        fi

        # 2) map the user into indexer roles (only roles that exist)
        local -a want=() r
        IFS=' ' read -ra want <<< "$(indexer_roles_for "$role")"
        for r in "${want[@]}"; do
            if ! jq -e --arg r "$r" 'has($r)' <<< "$roles_json" >/dev/null 2>&1; then
                info "  (indexer role '${r}' not present on this install — skipped)"; continue
            fi
            local cur new
            _http "$idx_user" "$idx_pass" GET "${WAZUH_INDEXER_URL}/_plugins/_security/api/rolesmapping/${r}" || true
            if [[ "$HTTP_CODE" == "200" ]]; then
                cur="$(jq -c --arg r "$r" '.[$r] | {users:(.users//[]), backend_roles:(.backend_roles//[]), hosts:(.hosts//[]), and_backend_roles:(.and_backend_roles//[])}' <<< "$HTTP_BODY")"
            else
                cur='{"users":[],"backend_roles":[],"hosts":[],"and_backend_roles":[]}'
            fi
            new="$(jq -c --arg u "$name" '.users = ((.users + [$u]) | unique)' <<< "$cur")"
            _http "$idx_user" "$idx_pass" PUT "${WAZUH_INDEXER_URL}/_plugins/_security/api/rolesmapping/${r}" \
                --data-binary @- <<< "$new" || true
            [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" ]] \
                || warn "  role mapping ${r} for '${name}' failed (HTTP ${HTTP_CODE})"
        done

        # 3) Wazuh API RBAC rule  user_name == name  ->  role(s)
        if [[ -n "$token" ]]; then
            api_rbac_link "$token" "$name" "$role" || warn "  API RBAC link for '${name}' incomplete (non-fatal)."
        fi

        info "  created/updated '${name}' (${role})"
        ok=$((ok+1))
    done

    info "Users stage: ${ok} ok, ${failed} skipped/failed."
    info "Dashboard login: https://<host-ip>  with the new username/password."
    info "NOTE: analyst vs viewer differences in the Wazuh app are enforced by API RBAC only"
    info "      once the dashboard runs with run_as: true (see CLI-REFERENCE.md)."
}

# api_rbac_link TOKEN NAME ROLE  — create rule soc_user_NAME and attach it to API roles
api_rbac_link() {
    local token="$1" name="$2" role="$3" rule_id rid rname
    local -a rnames=()
    local hdr; hdr="header = \"Authorization: Bearer ${token}\""
    _api() { local m="$1" p="$2"; shift 2
        local out; out="$(curl -sk -K <(printf '%s\n' "$hdr") -X "$m" -H 'Content-Type: application/json' \
            -w $'\n%{http_code}' "${WAZUH_API_URL}${p}" "$@")" || { HTTP_CODE=000; HTTP_BODY=""; return 1; }
        HTTP_CODE="${out##*$'\n'}"; HTTP_BODY="${out%$'\n'*}"; }

    _api GET "/security/rules?limit=500&select=id,name" || return 1
    rule_id="$(jq -r --arg n "soc_user_${name}" '.data.affected_items[]? | select(.name==$n) | .id' <<< "$HTTP_BODY" | head -1)"
    if [[ -z "$rule_id" ]]; then
        local rb; rb="$(jq -nc --arg n "soc_user_${name}" --arg u "$name" '{name:$n, rule:{FIND:{user_name:$u}}}')"
        _api POST "/security/rules" --data-binary @- <<< "$rb" || return 1
        rule_id="$(jq -r '.data.affected_items[0].id // empty' <<< "$HTTP_BODY")"
    fi
    [[ -n "$rule_id" ]] || return 1

    _api GET "/security/roles?limit=500&select=id,name" || return 1
    local roles_body="$HTTP_BODY"
    IFS=' ' read -ra rnames <<< "$(api_roles_for "$role")"
    for rname in "${rnames[@]}"; do
        rid="$(jq -r --arg n "$rname" '.data.affected_items[]? | select(.name==$n) | .id' <<< "$roles_body" | head -1)"
        [[ -n "$rid" ]] || { info "  (API role '${rname}' not found — skipped)"; continue; }
        _api POST "/security/roles/${rid}/rules?rule_ids=${rule_id}" || true
    done
}

# ============================================================================
# Stage 5: n8n (email notifications)
#   Bridge --POST--> n8n webhook --> "Send Email" node (SMTP) --> recipients
#   Threshold is applied in the bridge (N8N_MIN_LEVEL) so low-level noise never
#   reaches n8n at all.
# ============================================================================
n8n_compose() { ( cd "$STACK_DIR" && docker compose -f docker-compose.n8n.yml --env-file "$ENV_FILE" "$@" ); }

write_n8n_compose() {
    local tz; tz="$(timedatectl show -p Timezone --value 2>/dev/null || true)"; tz="${tz:-UTC}"
    cat > "${STACK_DIR}/docker-compose.n8n.yml" <<EOF
services:
  n8n:
    image: ${N8N_IMAGE}
    container_name: soc-n8n
    restart: unless-stopped
    mem_limit: 512m
    ports:
      - "5678:5678"
    environment:
      - N8N_ENCRYPTION_KEY=\${N8N_ENCRYPTION_KEY}
      - N8N_SECURE_COOKIE=false
      - N8N_DIAGNOSTICS_ENABLED=false
      - N8N_PERSONALIZATION_ENABLED=false
      - GENERIC_TIMEZONE=${tz}
      - TZ=${tz}
      - NODE_OPTIONS=--max-old-space-size=384
    volumes:
      - ${STACK_DIR}/n8n/data:/home/node/.n8n
    networks:
      - soc-net

networks:
  soc-net:
    name: soc-net
    external: true
EOF
}

stage_n8n() {
    if is_done "n8n"; then info "n8n already installed, skipping."; return; fi
    info "=== Stage: n8n email alerts ==="
    [[ -n "$CONFIG_FILE" ]] || die "n8n needs SMTP settings. Run ./soc-deploy, or pass --config FILE (see script header)."

    local host port user pass from min_level recips secure
    host="$(cfg '.n8n.smtp.host')";   port="$(cfg '.n8n.smtp.port')"
    user="$(cfg '.n8n.smtp.user')";   pass="$(cfg '.n8n.smtp.password')"
    from="$(cfg '.n8n.smtp.from')";   min_level="$(cfg '.n8n.min_level')"
    recips="$(jq -r '(.n8n.recipients // []) | join(", ")' "$CONFIG_FILE")"
    min_level="${min_level:-10}"

    [[ -n "$host" && -n "$port" && -n "$from" && -n "$recips" ]] \
        || die "n8n config incomplete: need smtp.host, smtp.port, smtp.from and at least one recipient."
    [[ "$port" =~ ^[0-9]+$ ]] || die "smtp.port must be a number."
    [[ "$min_level" =~ ^[0-9]+$ ]] && (( min_level >= 1 && min_level <= 15 )) \
        || die "n8n.min_level must be an integer 1-15."
    local mail_re='^[^@[:space:],]+@[^@[:space:],]+\.[^@[:space:],]+$' addr
    [[ "$from" =~ $mail_re ]] || die "smtp.from '${from}' is not a valid email address."
    while IFS= read -r addr; do
        [[ "$addr" =~ $mail_re ]] || die "Recipient '${addr}' is not a valid email address."
    done < <(jq -r '.n8n.recipients[]' "$CONFIG_FILE")

    # Port 465 = implicit TLS; everything else = STARTTLS when offered
    secure=false; [[ "$port" == "465" ]] && secure=true

    local wf_tpl; wf_tpl="$(find_file n8n-email-workflow.template.json)" \
        || die "n8n-email-workflow.template.json not found next to this script."

    mkdir -p "${STACK_DIR}/n8n/data"
    chown -R 1000:1000 "${STACK_DIR}/n8n/data"
    grep -q '^N8N_ENCRYPTION_KEY=.' "$ENV_FILE" 2>/dev/null || set_env N8N_ENCRYPTION_KEY "$(rand_secret)"
    write_n8n_compose

    # Build import files in a private dir; credentials are encrypted by n8n on import
    local imp="${STACK_DIR}/n8n/import"
    rm -rf "$imp"; install -d -m 700 -o 1000 -g 1000 "$imp"
    (
        umask 077
        PASS="$pass" jq -n --arg host "$host" --argjson port "$port" --arg user "$user" \
            --argjson secure "$secure" \
            '[{id:"socSmtp01", name:"SOC SMTP", type:"smtp",
               data:{host:$host, port:$port, user:$user, password:env.PASS, secure:$secure, disableStartTls:false}}]' \
            > "${imp}/credentials.json"
        jq --arg from "$from" --arg to "$recips" \
            '(.nodes[] | select(.name=="Send Email") | .parameters) |= (.fromEmail=$from | .toEmail=$to)' \
            "$wf_tpl" > "${imp}/workflow.json"
    )
    chown 1000:1000 "${imp}/credentials.json" "${imp}/workflow.json"

    info "Pulling n8n image (${N8N_IMAGE})..."
    n8n_compose pull n8n || warn "Image pull failed; trying with a local copy if one exists."

    info "Importing SMTP credential and workflow..."
    n8n_compose run --rm -T --no-deps -v "${imp}:/import:ro" n8n import:credentials --input=/import/credentials.json \
        || die "n8n credential import failed."
    n8n_compose run --rm -T --no-deps -v "${imp}:/import:ro" n8n import:workflow --input=/import/workflow.json \
        || die "n8n workflow import failed."
    # Activate: older n8n = update:workflow, newer = publish:workflow
    n8n_compose run --rm -T --no-deps n8n update:workflow --id=socWazuhMail01 --active=true \
        || n8n_compose run --rm -T --no-deps n8n publish:workflow --id=socWazuhMail01 \
        || warn "Could not activate the workflow from the CLI — switch it on in the n8n UI (top-right toggle)."
    rm -rf "$imp"     # plaintext SMTP password must not linger on disk

    n8n_compose up -d n8n
    info "Waiting for n8n to become healthy..."
    wait_for_http "http://localhost:5678/healthz" 120 || warn "n8n did not report healthy; check: docker logs soc-n8n"

    # Wire the bridge
    set_env N8N_WEBHOOK_URL "http://127.0.0.1:5678/webhook/wazuh-email"
    set_env N8N_MIN_LEVEL "$min_level"
    if systemctl is-active --quiet wazuh-thehive-bridge 2>/dev/null; then
        systemctl restart wazuh-thehive-bridge && info "Bridge restarted with n8n settings."
    fi

    if jq -e '.n8n.send_test != false' "$CONFIG_FILE" >/dev/null 2>&1; then
        info "Sending a test alert through n8n to: ${recips}"
        sleep 5
        local code
        code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
            -d '{"rule_level":15,"rule_id":"TEST","rule_description":"SOC lab test email - n8n pipeline works","agent_name":"soc-deploy","full_log":"This is a test message sent at install time."}' \
            http://127.0.0.1:5678/webhook/wazuh-email || true)"
        if [[ "$code" == "200" ]]; then
            info "Test accepted by n8n. Check the inbox; if nothing arrives see n8n -> Executions (http://<host-ip>:5678)."
        else
            warn "Test webhook returned HTTP ${code:-000}. If 404, the workflow is not active yet: open http://<host-ip>:5678, create the owner account, and toggle it on."
        fi
    fi

    mark_done "n8n"
    info "n8n installed. UI: http://<host-ip>:5678 (first visit asks you to create an owner account)."
    info "Alerts at Wazuh level >= ${min_level} will be emailed."
}

# ============================================================================
# Stage 6: Alert bridge (Wazuh -> TheHive)
# ============================================================================
stage_bridge() {
    if is_done "bridge"; then info "Bridge already installed, skipping."; return; fi
    info "=== Stage: Wazuh -> TheHive alert bridge ==="

    local bridge_src=""
    for candidate in \
        "${SCRIPT_DIR}/files/wazuh_thehive_bridge.py" \
        "${SCRIPT_DIR}/wazuh_thehive_bridge.py"; do
        [[ -f "$candidate" ]] && { bridge_src="$candidate"; break; }
    done
    [[ -n "$bridge_src" ]] || die "wazuh_thehive_bridge.py not found next to this script."

    local req_src=""
    for candidate in \
        "${SCRIPT_DIR}/files/bridge-requirements.txt" \
        "${SCRIPT_DIR}/files/bridge-requiremens.txt" \
        "${SCRIPT_DIR}/bridge-requirements.txt" \
        "${SCRIPT_DIR}/bridge-requiremens.txt"; do
        [[ -f "$candidate" ]] && { req_src="$candidate"; break; }
    done

    install -d -m 755 /opt/soc-stack/bridge
    cp "$bridge_src" /opt/soc-stack/bridge/bridge.py

    if [[ -n "$req_src" ]]; then
        cp "$req_src" /opt/soc-stack/bridge/requirements.txt
    else
        echo "requests==2.32.3" > /opt/soc-stack/bridge/requirements.txt
    fi

    python3 -m venv /opt/soc-stack/bridge/venv
    /opt/soc-stack/bridge/venv/bin/pip install --quiet --upgrade pip
    /opt/soc-stack/bridge/venv/bin/pip install --quiet -r /opt/soc-stack/bridge/requirements.txt

    cat > /etc/systemd/system/wazuh-thehive-bridge.service <<EOF
[Unit]
Description=Wazuh alert -> TheHive bridge
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

    systemctl daemon-reload
    systemctl enable wazuh-thehive-bridge.service

    if grep -q 'THEHIVE_API_KEY=.' "$ENV_FILE" 2>/dev/null; then
        systemctl start wazuh-thehive-bridge
        info "Bridge installed and started."
    else
        warn "THEHIVE_API_KEY not set — bridge installed but NOT started."
        warn "Set it with: sudo ./deploy-soc-stack.sh set-hive-key <key>"
        warn ""
        warn "The key must come from an org-level user (analyst or org-admin profile),"
        warn "NOT from the platform superadmin (admin@thehive.local)."
    fi

    mark_done "bridge"
}

# ============================================================================
# Shared: wire a log file / rules into the native Wazuh manager
# ============================================================================
wazuh_add_json_localfile() {
    # $1 = marker, $2 = log path
    local marker="$1" path="$2" conf=/var/ossec/etc/ossec.conf
    [[ -f "$conf" ]] || { warn "Wazuh not installed; skipping localfile for ${path}."; return 0; }
    if grep -q "soc-stack:${marker}" "$conf"; then return 0; fi
    cp -a "$conf" "${conf}.bak.${marker}"
    cat >> "$conf" <<XML

<!-- soc-stack:${marker} -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>${path}</location>
  </localfile>
</ossec_config>
XML
}

wazuh_install_ips_rules() {
    local src dst=/var/ossec/etc/rules/soc-ips_rules.xml
    [[ -d /var/ossec/etc/rules ]] || { warn "Wazuh rules dir missing; skipping custom rules."; return 0; }
    src="$(find_file soc-ips-wazuh-rules.xml)" || die "soc-ips-wazuh-rules.xml not found next to this script."
    install -m 660 -o wazuh -g wazuh "$src" "$dst" 2>/dev/null || install -m 660 "$src" "$dst"
    if [[ -x /var/ossec/bin/wazuh-analysisd ]] && ! /var/ossec/bin/wazuh-analysisd -t 2>/tmp/soc-rules-test.log; then
        cat /tmp/soc-rules-test.log | tail -5
        rm -f "$dst"; die "Wazuh rejected soc-ips_rules.xml (removed). See output above."
    fi
}

wazuh_reload() {
    systemctl is-active --quiet wazuh-manager && systemctl restart wazuh-manager || true
}

# ============================================================================
# Stage: Suricata inline IPS (NFQUEUE, fail-open, detect -> prevent tiering)
# ============================================================================
stage_suricata() {
    if is_done "suricata"; then info "Suricata IPS already installed, skipping."; return; fi
    info "=== Stage: Suricata inline IPS ==="

    local iface mode ssh_ports exempt_ports D=/etc/suricata/soc-ips
    iface="$(cfg '.suricata.interface')"
    if [[ -z "$iface" || "$iface" == "auto" ]]; then
        iface="$(ip -o -4 route show default | awk '{print $5; exit}')"
    fi
    [[ -n "$iface" ]] || die "Cannot determine LAN interface. Set suricata.interface in the config."
    ip link show "$iface" >/dev/null 2>&1 || die "Interface ${iface} not found."
    mode="$(cfg '.suricata.mode')"; mode="${mode:-detect}"
    [[ "$mode" == detect || "$mode" == prevent ]] || die "suricata.mode must be detect or prevent."
    ssh_ports="$(jq -r '(.suricata.ssh_ports // [22]) | map(tostring) | join(", ")' "${CONFIG_FILE:-/dev/null}" 2>/dev/null || echo 22)"
    [[ -n "$ssh_ports" ]] || ssh_ports=22
    # Never queue management + agent traffic: losing it would blind/lock you out
    exempt_ports="${ssh_ports}, 1514, 1515, 55000"
    info "Inline on ${iface}; mode=${mode}; exempt TCP ports: ${exempt_ports}"

    local mem_gb; mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
    [[ $mem_gb -lt 8 ]] && warn "Suricata+ET Open needs ~1-1.5GB RAM; this host has ${mem_gb}GB." || true

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y -qq suricata suricata-update nftables jq curl >>"$LOG_FILE" 2>&1 \
        || die "apt install of suricata/nftables failed (see ${LOG_FILE})."
    systemctl disable --now suricata 2>/dev/null || true     # distro unit: we run our own

    install -d -m 755 "$D"
    echo "$mode" > "$D/mode"
    [[ -f "$D/enable.conf"  ]] || echo "# SIDs/groups to force-enable (suricata-update enable.conf syntax)" > "$D/enable.conf"
    [[ -f "$D/modify.conf"  ]] || echo "# modify.conf:  <sid> \"regex\" \"replacement\"" > "$D/modify.conf"
    [[ -f "$D/drop.local"   ]] || echo "# extra drop.conf lines (SIDs, group:xxx.rules, re:regex)" > "$D/drop.local"
    [[ -f "$D/disable.conf" ]] || cat > "$D/disable.conf" <<'CONF'
# Noisy / low-value groups for a home lab (edit freely, then: soc-ips update)
group:decoder-events.rules
group:stream-events.rules
group:emerging-info.rules
group:emerging-policy.rules
group:emerging-games.rules
group:emerging-p2p.rules
group:emerging-chat.rules
CONF
    cp "$(find_file soc-ips-local.rules)" "$D/local.rules" || die "soc-ips-local.rules not found."
    install -m 755 "$(find_file soc-ips)" /usr/local/sbin/soc-ips || die "files/soc-ips not found."

    # --- Suricata config: layered on the distro file so upgrades keep working
    cat > /etc/suricata/soc-ips.yaml <<'YAML'
%YAML 1.1
---
include: /etc/suricata/suricata.yaml
nfq:
  mode: accept        # verdict per packet; 'drop' rules are enforced
  fail-open: yes      # queue full -> accept, never stall the host
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
detect:
  profile: low        # smaller RAM footprint
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            tagged-packets: no
        - dns
        - tls
        - stats:
            totals: yes
            threads: no
YAML

    # --- nftables: only LAN traffic is queued; SSH/agent/DHCP/bcast exempt; bypass = fail-open
    cat > /etc/suricata/soc-ips.nft <<NFT
add table inet soc_ips
delete table inet soc_ips
table inet soc_ips {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname != "${iface}" return
    meta pkttype { broadcast, multicast } return
    tcp dport { ${exempt_ports} } return
    tcp sport { ${exempt_ports} } return
    udp dport { 67, 68 } return
    queue flags bypass to 0
  }
  chain output {
    type filter hook output priority -10; policy accept;
    oifname != "${iface}" return
    meta pkttype { broadcast, multicast } return
    tcp sport { ${exempt_ports} } return
    tcp dport { ${exempt_ports} } return
    udp dport { 67, 68 } return
    queue flags bypass to 0
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname != "${iface}" oifname != "${iface}" return
    queue flags bypass to 0
  }
}
NFT
    nft -c -f /etc/suricata/soc-ips.nft || die "Generated nft ruleset is invalid."

    echo nfnetlink_queue > /etc/modules-load.d/soc-ips.conf
    modprobe nfnetlink_queue 2>/dev/null || warn "Could not load nfnetlink_queue (kernel lacks NFQUEUE?)."

    cat > /etc/systemd/system/suricata-ips.service <<'UNIT'
[Unit]
Description=Suricata inline IPS (NFQUEUE 0)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/bin/suricata -T -c /etc/suricata/soc-ips.yaml -l /var/log/suricata
ExecStart=/usr/bin/suricata -c /etc/suricata/soc-ips.yaml -q 0
Restart=on-failure
RestartSec=5
TimeoutStartSec=300
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
    cat > /etc/systemd/system/soc-ips-nft.service <<'UNIT'
[Unit]
Description=SOC IPS: NFQUEUE hook (fail-open)
After=suricata-ips.service
BindsTo=suricata-ips.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/suricata/soc-ips.nft
ExecStop=-/usr/sbin/nft delete table inet soc_ips

[Install]
WantedBy=multi-user.target
UNIT
    cat > /etc/systemd/system/soc-ips-update.service <<'UNIT'
[Unit]
Description=Update Suricata rules (soc-ips)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/soc-ips update
UNIT
    cat > /etc/systemd/system/soc-ips-update.timer <<'UNIT'
[Unit]
Description=Daily Suricata rule update
[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload

    info "Downloading ET Open rules (first run)..."
    /usr/local/sbin/soc-ips update || die "Initial rule update failed."

    systemctl enable --now suricata-ips.service
    # wait for suricata to finish loading before hooking the queue (bypass covers the gap anyway)
    local waited=0
    until journalctl -u suricata-ips -n 50 --no-pager 2>/dev/null | grep -q "engine started\|Engine started" || (( waited >= 180 )); do
        sleep 5; waited=$((waited+5))
    done
    systemctl enable --now soc-ips-nft.service soc-ips-update.timer

    # Wazuh: ingest eve.json + custom rules
    wazuh_add_json_localfile suricata /var/log/suricata/eve.json
    wazuh_install_ips_rules
    wazuh_reload

    info "Suricata IPS is running in '${mode}' mode. Panic switch: soc-ips panic-off"
    [[ "$mode" == detect ]] && info "Review alerts for a few days, then:  soc-ips mode prevent  ->  soc-ips selftest"
    mark_done "suricata"
}

# ============================================================================
# Stage: Kismet wireless IDS (passive) + Wazuh exporter
# ============================================================================
stage_wips() {
    if is_done "wips"; then info "WIPS already installed, skipping."; return; fi
    info "=== Stage: Kismet wireless IDS ==="

    local wif kuser kpass
    wif="$(cfg '.wips.interface')"
    [[ -n "$wif" ]] || die "wips.interface (a monitor-capable Wi-Fi adapter, e.g. wlan1) is required in the config."
    ip link show "$wif" >/dev/null 2>&1 || warn "Interface ${wif} not present right now (plug the adapter in before starting)."
    kuser="$(cfg '.wips.user')"; kuser="${kuser:-kismet}"
    kpass="$(cfg '.wips.password')"; kpass="${kpass:-$(rand_secret)}"
    [[ "$(jq -r '(.wips.own_ssids // {}) | length' "$CONFIG_FILE")" == 0 ]] \
        && warn "wips.own_ssids is empty: rogue-AP/evil-twin detection is OFF (only Kismet's generic alerts)." || true

    export DEBIAN_FRONTEND=noninteractive
    if [[ ! -f /etc/apt/sources.list.d/kismet.list ]]; then
        curl -4 -fsSL https://www.kismetwireless.net/repos/kismet-release.gpg.key | gpg --dearmor \
            > /usr/share/keyrings/kismet-archive-keyring.gpg
        echo 'deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/trixie trixie main' \
            > /etc/apt/sources.list.d/kismet.list
    fi
    echo "kismet-capture-common kismet-capture-common/install-setuid boolean true" | debconf-set-selections
    apt-get update -qq || warn "apt update reported errors."
    apt-get install -y -qq kismet-core kismet-capture-linux-wifi jq >>"$LOG_FILE" 2>&1 \
        || die "Kismet install failed (see ${LOG_FILE})."

    id soc-wips &>/dev/null || useradd -r -m -d /var/lib/soc-wips -s /usr/sbin/nologin soc-wips
    usermod -aG kismet soc-wips
    install -d -o soc-wips -g soc-wips -m 750 /var/log/kismet /var/log/soc-wips /opt/soc-stack/wips

    # --- Kismet site config (REST only on localhost)
    {
        echo "# generated by deploy-soc-stack.sh"
        echo "httpd_bind_address=127.0.0.1"
        echo "httpd_username=${kuser}"
        echo "httpd_password=${kpass}"
        echo "source=${wif}:name=wips,hop=true"
        echo "log_prefix=/var/log/kismet/"
        echo "log_types=kismet"
        local i=0 ssid macs
        while IFS= read -r ssid; do
            [[ -n "$ssid" ]] || continue
            i=$((i+1))
            macs="$(jq -r --arg s "$ssid" '.wips.own_ssids[$s] | join(",")' "$CONFIG_FILE")"
            echo "apspoof=own${i}:ssid=\"${ssid}\",validmacs=\"${macs}\""
        done < <(jq -r '(.wips.own_ssids // {}) | keys[]' "$CONFIG_FILE")
    } > /etc/kismet/kismet_site.conf
    chown root:soc-wips /etc/kismet/kismet_site.conf; chmod 640 /etc/kismet/kismet_site.conf

    # --- exporter
    install -m 755 "$(find_file wips_exporter.py)" /opt/soc-stack/wips/wips_exporter.py \
        || die "wips_exporter.py not found next to this script."
    jq -n --arg u "$kuser" --arg p "$kpass" \
        --argjson own "$(jq -c '.wips.own_ssids // {}' "$CONFIG_FILE")" \
        '{kismet_url:"http://127.0.0.1:2501",user:$u,password:$p,own_ssids:$own,poll_seconds:15,out:"/var/log/soc-wips/wips.json"}' \
        > /opt/soc-stack/wips/wips.json
    chown soc-wips:soc-wips /opt/soc-stack/wips/wips.json; chmod 600 /opt/soc-stack/wips/wips.json

    cat > /etc/systemd/system/soc-kismet.service <<'UNIT'
[Unit]
Description=Kismet wireless IDS (passive monitor)
After=network.target

[Service]
User=soc-wips
Group=soc-wips
SupplementaryGroups=kismet
WorkingDirectory=/var/lib/soc-wips
ExecStart=/usr/bin/kismet --no-ncurses --silent
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
    cat > /etc/systemd/system/soc-wips-exporter.service <<'UNIT'
[Unit]
Description=Kismet -> Wazuh WIPS exporter
After=soc-kismet.service
Wants=soc-kismet.service

[Service]
User=soc-wips
ExecStart=/usr/bin/python3 /opt/soc-stack/wips/wips_exporter.py /opt/soc-stack/wips/wips.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
    cat > /etc/logrotate.d/soc-wips <<'LR'
/var/log/soc-wips/wips.json {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    copytruncate
}
LR
    systemctl daemon-reload
    systemctl disable --now kismet 2>/dev/null || true
    systemctl enable --now soc-kismet.service soc-wips-exporter.service

    wazuh_add_json_localfile wips /var/log/soc-wips/wips.json
    wazuh_install_ips_rules
    wazuh_reload

    info "WIPS running on ${wif} (passive: it never transmits or deauths)."
    info "Kismet UI: http://127.0.0.1:2501  user=${kuser}  (SSH-tunnel to it; password in /opt/soc-stack/wips/wips.json)"
    mark_done "wips"
}

# ============================================================================
# Status
# ============================================================================
cmd_status() {
    echo "=== Wazuh ==="
    systemctl is-active wazuh-manager  2>/dev/null | xargs echo "  manager:  "
    systemctl is-active wazuh-indexer  2>/dev/null | xargs echo "  indexer:  "
    systemctl is-active wazuh-dashboard 2>/dev/null | xargs echo "  dashboard:"
    echo
    echo "=== Docker containers ==="
    docker ps --filter "name=soc-" --format "  {{.Names}}: {{.Status}}" 2>/dev/null \
        || echo "  (Docker not running or no containers)"
    echo
    echo "=== Alert bridge ==="
    systemctl is-active wazuh-thehive-bridge 2>/dev/null | xargs echo "  bridge:   "
    if [[ -f "$ENV_FILE" ]] && grep -q '^N8N_WEBHOOK_URL=.' "$ENV_FILE"; then
        echo "  n8n email: on (level >= $(sed -n 's/^N8N_MIN_LEVEL=//p' "$ENV_FILE" | head -1))"
    else
        echo "  n8n email: off"
    fi
    echo
    echo "=== Suricata IPS / Wireless IDS ==="
    if [[ -x /usr/local/sbin/soc-ips ]]; then /usr/local/sbin/soc-ips status | sed 's/^/  /'; else echo "  suricata: not installed"; fi
    systemctl is-active soc-kismet 2>/dev/null | xargs echo "  kismet:   "
    systemctl is-active soc-wips-exporter 2>/dev/null | xargs echo "  wips exp: "
    echo
    echo "=== Memory ==="
    free -h | head -2
    echo
    docker stats --no-stream \
        --format "  {{.Name}}: CPU {{.CPUPerc}}  MEM {{.MemUsage}}" 2>/dev/null || true
}

# ============================================================================
# set-hive-key
# ============================================================================
cmd_set_hive_key() {
    local key="${1:-}"
    [[ -n "$key" ]] || die "Usage: $0 set-hive-key <api-key>"
    [[ -f "$ENV_FILE" ]] || die "${ENV_FILE} not found. Run install first."
    sed -i "s|^THEHIVE_API_KEY=.*|THEHIVE_API_KEY=${key}|" "$ENV_FILE"
    info "THEHIVE_API_KEY updated. Restarting bridge..."
    systemctl restart wazuh-thehive-bridge 2>/dev/null \
        || info "Bridge not yet installed; will use key when started."
}

# ============================================================================
# Uninstall
# ============================================================================
cmd_uninstall() {
    confirm "This will STOP and REMOVE Wazuh, TheHive, Cortex, and all data. Continue?" \
        || { info "Aborted."; exit 0; }

    info "Stopping Docker stack..."
    cd "$STACK_DIR" 2>/dev/null && {
        docker compose -f docker-compose.hive.yml down -v 2>/dev/null || true
        docker compose -f docker-compose.cortex.yml down -v 2>/dev/null || true
        [[ -f docker-compose.n8n.yml ]] && \
            docker compose -f docker-compose.n8n.yml --env-file "$ENV_FILE" down -v 2>/dev/null || true
    }
    docker network rm soc-net 2>/dev/null || true

    info "Removing Suricata IPS / WIPS (if present)..."
    systemctl disable --now soc-ips-nft.service soc-ips-update.timer suricata-ips.service \
        soc-wips-exporter.service soc-kismet.service 2>/dev/null || true
    nft delete table inet soc_ips 2>/dev/null || true
    rm -f /etc/systemd/system/{suricata-ips,soc-ips-nft,soc-ips-update,soc-kismet,soc-wips-exporter}.service \
          /etc/systemd/system/soc-ips-update.timer /usr/local/sbin/soc-ips /etc/modules-load.d/soc-ips.conf \
          /var/ossec/etc/rules/soc-ips_rules.xml
    [[ -f /var/ossec/etc/ossec.conf.bak.suricata ]] && warn "ossec.conf still has soc-stack localfile blocks; remove them manually (see ossec.conf.bak.*)."

    info "Stopping bridge..."
    systemctl stop wazuh-thehive-bridge 2>/dev/null || true
    systemctl disable wazuh-thehive-bridge 2>/dev/null || true
    rm -f /etc/systemd/system/wazuh-thehive-bridge.service
    systemctl daemon-reload

    info "Uninstalling Wazuh..."
    apt-mark unhold wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
    if [[ -f /tmp/wazuh-install/wazuh-install.sh ]]; then
        bash /tmp/wazuh-install/wazuh-install.sh -u | tee -a "$LOG_FILE" || true
    else
        warn "Wazuh installer not cached. Remove manually:"
        warn "  apt-get purge wazuh-manager wazuh-indexer wazuh-dashboard filebeat"
    fi

    read -r -p "Also delete ${STACK_DIR} (all data, certs, secrets)? [y/N] " r
    [[ "$r" =~ ^[Yy]$ ]] && rm -rf "$STACK_DIR"

    rm -rf "$STATE_DIR"
    info "Uninstall complete."
}

# ============================================================================
# Interactive component picker (used when `install` is run with no component list)
# ============================================================================
ask_yn() {   # ask_yn "question" y|n  -> 0 = yes
    local d="${2:-n}" a hint="[y/N]"
    [[ "$d" == y ]] && hint="[Y/n]"
    read -r -p "$1 $hint " a || a=""
    a="${a:-$d}"
    [[ "$a" =~ ^[Yy] ]]
}

cfg_set() {  # cfg_set <jq-filter> [jq args...]  -> edits the runtime config in place
    local filter="$1"; shift
    local tmp; tmp="$(mktemp)"; chmod 600 "$tmp"
    jq "$@" "$filter" "$CONFIG_FILE" > "$tmp" && cat "$tmp" > "$CONFIG_FILE"
    rm -f "$tmp"
}

prompt_components() {
    echo
    echo "Choose what to install (Enter = default shown in brackets)."
    echo "Approximate RAM: Wazuh ~3GB, TheHive+Cassandra ~2.5GB, Cortex+ES ~1.2GB, n8n ~0.3GB, Suricata ~1-1.5GB, Kismet ~0.2GB"
    echo
    # Work on a private runtime copy of the config so typed secrets never touch argv
    local rt; rt="$(mktemp)"; chmod 600 "$rt"
    if [[ -n "$CONFIG_FILE" ]]; then cat "$CONFIG_FILE" > "$rt"; else echo '{}' > "$rt"; fi
    RUNTIME_CFG="$rt"; CONFIG_FILE="$rt"
    trap 'rm -f "${RUNTIME_CFG:-}"' EXIT

    local list=() hive=0
    ask_yn "Install Wazuh (manager + indexer + dashboard)?" y && list+=(wazuh)
    if ask_yn "Install TheHive (case management)?" y; then list+=(hive); hive=1; fi
    ask_yn "Install Cortex (analyzers / enrichment)?" y && list+=(cortex)
    if (( hive )) && ask_yn "Install the Wazuh -> TheHive alert bridge?" y; then list+=(bridge); fi

    if ask_yn "Install n8n email alerts?" n; then
        local h p u pw f r
        read -r -p "  SMTP host [smtp.gmail.com]: " h; h="${h:-smtp.gmail.com}"
        read -r -p "  SMTP port [465]: " p; p="${p:-465}"
        read -r -p "  SMTP user: " u
        read -r -s -p "  SMTP password (hidden): " pw; echo
        read -r -p "  From address [${u}]: " f; f="${f:-$u}"
        read -r -p "  Recipients (comma-separated): " r
        cfg_set '.n8n = {enabled:true, min_level:10, send_test:true,
                 smtp:{host:$h, port:($p|tonumber), user:$u, password:$pw, from:$f},
                 recipients:($r|split(",")|map(gsub("^\\s+|\\s+$";"")))}' \
            --arg h "$h" --arg p "$p" --arg u "$u" --arg pw "$pw" --arg f "$f" --arg r "$r"
        list+=(n8n)
    fi

    if ask_yn "Install Suricata inline IPS (NFQUEUE, fail-open)?" n; then
        local m
        read -r -p "  Start mode - detect (log only) or prevent (drop)? [detect]: " m; m="${m:-detect}"
        [[ "$m" == detect || "$m" == prevent ]] || { warn "Unknown mode '${m}', using detect."; m=detect; }
        cfg_set '.suricata = ((.suricata // {}) + {enabled:true, mode:$m})' --arg m "$m"
        list+=(suricata)
    fi

    if ask_yn "Install Kismet wireless IDS (needs a 2nd monitor-mode Wi-Fi adapter)?" n; then
        local wi ssid macs
        read -r -p "  Monitor-mode interface (e.g. wlan1): " wi
        cfg_set '.wips = ((.wips // {}) + {enabled:true, interface:$i})' --arg i "$wi"
        echo "  Your own SSIDs enable evil-twin detection. Blank SSID to finish."
        while read -r -p "  SSID: " ssid && [[ -n "$ssid" ]]; do
            read -r -p "  Valid BSSIDs for '${ssid}' (comma-separated MACs): " macs
            cfg_set '.wips.own_ssids[$s] = ($m|split(",")|map(gsub("\\s";"")|ascii_upcase))' \
                --arg s "$ssid" --arg m "$macs"
        done
        list+=(wips)
    fi

    if [[ "$(jq -r '(.wazuh_users // []) | length' "$CONFIG_FILE")" != "0" && " ${list[*]} " == *" wazuh "* ]]; then
        list+=(users)
    fi

    (( ${#list[@]} > 0 )) || die "Nothing selected."
    echo
    echo "Selected: ${list[*]}"
    ask_yn "Proceed?" y || { info "Aborted."; exit 0; }
    COMPONENTS="$(IFS=,; echo "${list[*]}")"
}

# ============================================================================
# Upgrade Wazuh safely (keeps YOUR config files; backup; per-package health check)
# ============================================================================
WAZUH_PKGS_ORDER="wazuh-indexer wazuh-manager wazuh-dashboard"   # Wazuh upgrade order

upgrade_health() {   # $1 = package; returns 0 when the service answers
    local code i
    case "$1" in
        wazuh-indexer)
            for i in $(seq 1 24); do
                code="$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:9200 2>/dev/null || true)"
                [[ "$code" == 200 || "$code" == 401 ]] && return 0; sleep 5
            done; return 1 ;;
        wazuh-manager)
            for i in $(seq 1 12); do
                systemctl is-active --quiet wazuh-manager && return 0; sleep 5
            done; return 1 ;;
        wazuh-dashboard)
            for i in $(seq 1 24); do
                code="$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:443/app/login 2>/dev/null || true)"
                [[ "$code" == 200 || "$code" == 302 ]] && return 0; sleep 5
            done; return 1 ;;
    esac
}

cmd_upgrade() {
    # $1 = optional target version, e.g. 4.14.9  (default: newest in the repo)
    local target="${1:-}" ts bak pkg cur cand verarg installed=()
    ts="$(date +%Y%m%d-%H%M%S)"
    bak="/var/backups/soc-stack/wazuh-pre-upgrade-${ts}.tar.gz"

    local -a order=()
    IFS=' ' read -ra order <<< "$WAZUH_PKGS_ORDER"     # global IFS has no space
    for pkg in "${order[@]}"; do
        dpkg -s "$pkg" &>/dev/null && installed+=("$pkg")
    done
    (( ${#installed[@]} > 0 )) || die "No Wazuh packages installed on this host."

    apt-get update -qq || warn "apt update reported errors."
    echo "Package            installed -> available"
    for pkg in "${installed[@]}"; do
        cur="$(dpkg-query -W -f='${Version}' "$pkg")"
        cand="$(apt-cache policy "$pkg" | awk '/Candidate:/ {print $2}')"
        printf '  %-16s %s -> %s\n' "$pkg" "$cur" "${target:-$cand}"
    done
    echo "Order: ${installed[*]}.  Your existing config files will be KEPT (no overwrite)."
    if [[ $ASSUME_YES -eq 0 ]]; then confirm "Proceed with the upgrade?" || { info "Aborted."; exit 0; }; fi

    info "Backing up configs to ${bak}"
    install -d -m 700 /var/backups/soc-stack
    tar czf "$bak" --ignore-failed-read \
        /etc/wazuh-dashboard /etc/wazuh-indexer /etc/filebeat /var/ossec/etc \
        /usr/share/wazuh-dashboard/data/wazuh/config "$ENV_FILE" 2>/dev/null || true
    [[ -s "$bak" ]] || die "Backup was not created at ${bak}; refusing to upgrade."
    chmod 600 "$bak"
    info "Backup done. (On a VM, also take a snapshot now.)"

    # Always put the hold back, even on failure
    trap 'apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard >/dev/null 2>&1 || true' RETURN
    apt-mark unhold "${installed[@]}" >/dev/null

    for pkg in "${installed[@]}"; do
        verarg="$pkg"
        if [[ -n "$target" ]]; then
            cand="$(apt-cache madison "$pkg" | awk -v v="$target" '$3 ~ "^"v"-" {print $3; exit}')"
            [[ -n "$cand" ]] || { err "Version ${target} of ${pkg} not found in the repo."; return 1; }
            verarg="${pkg}=${cand}"
        fi
        info "Upgrading ${pkg}..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef \
            "$verarg" 2>&1 | tee -a "$LOG_FILE" | tail -5 || { err "apt failed for ${pkg}."; return 1; }
        systemctl daemon-reload
        systemctl restart "$pkg" 2>/dev/null || true
        if upgrade_health "$pkg"; then
            info "${pkg}: healthy after upgrade."
        else
            err "${pkg} did not come back healthy."
            err "Logs: journalctl -u ${pkg} -n 80   |   configs backed up in ${bak}"
            err "Check certificate paths, 127.0.0.1 vs localhost, and JVM heap (see CLI-REFERENCE.md section 9)."
            return 1
        fi
    done

    local new; new="$(find /etc/wazuh-dashboard /etc/wazuh-indexer /etc/filebeat /var/ossec/etc \
        \( -name '*.dpkg-dist' -o -name '*.dpkg-new' \) 2>/dev/null || true)"
    if [[ -n "$new" ]]; then
        warn "The new package defaults differ from your kept config in these files."
        warn "Review for NEW settings you may need (diff <yours> <file.dpkg-dist>):"
        echo "$new" | sed 's/^/    /'
    fi
    info "Upgrade complete. Packages are held again. Versions:"
    for pkg in "${installed[@]}"; do dpkg-query -W -f='  ${Package} ${Version}\n' "$pkg"; done
}

# ============================================================================
# Main
# ============================================================================
# Canonical order matters: users need Wazuh up; n8n sets bridge env; bridge last.
ALL_STAGES="prereqs wazuh users hive cortex n8n bridge suricata wips"

resolve_components() {
    # $1 = "all" or comma-separated list of wazuh,hive,cortex,n8n,bridge,users
    local want="$1" c out=""
    if [[ "$want" == "all" ]]; then
        out="wazuh hive cortex bridge"
        [[ "$(cfg '.n8n.enabled')" == "true" ]] && out="${out} n8n"
        [[ "$(jq -r '(.wazuh_users // []) | length' "${CONFIG_FILE:-/dev/null}" 2>/dev/null || echo 0)" != "0" ]] \
            && out="${out} users"
        # Opt-in: IPS and WIPS only join "all" when enabled in the config
        [[ "$(cfg '.suricata.enabled')" == "true" ]] && out="${out} suricata"
        [[ "$(cfg '.wips.enabled')" == "true" ]] && out="${out} wips"
    else
        local -a parts=()
        IFS=',' read -ra parts <<< "$want"
        for c in "${parts[@]}"; do
            case "$c" in
                wazuh|hive|cortex|n8n|bridge|users|suricata|wips) out="${out} ${c}" ;;
                *) die "Unknown component '${c}'. Use: all or any of wazuh,hive,cortex,n8n,bridge,users,suricata,wips (comma-separated)." ;;
            esac
        done
    fi
    # Emit in canonical order, de-duplicated
    local s
    local -a order=()
    IFS=' ' read -ra order <<< "$ALL_STAGES"
    for s in "${order[@]}"; do
        if [[ " ${out} " == *" ${s} "* ]]; then echo "$s"; fi
    done
    return 0
}

run_install() {
    require_root
    mkdir -p "$STATE_DIR"
    touch "$LOG_FILE"
    load_config
    check_resources

    if [[ -z "$COMPONENTS" ]]; then
        if [[ -t 0 && $ASSUME_YES -eq 0 ]]; then prompt_components; else COMPONENTS=all; fi
    fi

    local -a stages=()
    local s
    while IFS= read -r s; do [[ -n "$s" ]] && stages+=("$s"); done < <(resolve_components "${COMPONENTS:-all}")
    (( ${#stages[@]} > 0 )) || die "Nothing to install."
    info "Stages: ${stages[*]}"

    # Docker-backed or installer-backed stages need prereqs (+ the shared network)
    local needs_prereqs=0 needs_net=0
    for s in "${stages[@]}"; do
        case "$s" in
            wazuh) needs_prereqs=1 ;;
            hive|cortex|n8n) needs_prereqs=1; needs_net=1 ;;
            suricata|wips) : ;;   # self-contained apt installs
        esac
    done
    (( needs_prereqs )) && stage_prereqs
    (( needs_net )) && ensure_network

    for s in "${stages[@]}"; do
        case "$s" in
            wazuh)  stage_wazuh ;;
            users)  stage_users ;;
            hive)   stage_hive ;;
            cortex) stage_cortex ;;
            n8n)    stage_n8n ;;
            bridge) stage_bridge ;;
            suricata) stage_suricata ;;
            wips)   stage_wips ;;
        esac
    done

    echo
    info "=== Install complete. Run '$0 status' to check health. ==="
    [[ -f "${STACK_DIR}/wazuh-passwords.txt" ]] && \
        info "Wazuh credentials: ${STACK_DIR}/wazuh-passwords.txt"
    return 0
}

usage() {
    echo "Usage: $0 [--force] [--yes] install [all|wazuh,hive,cortex,n8n,bridge,users,suricata,wips] [--config FILE]"
    echo "       $0 status | set-hive-key <key> | upgrade [wazuh-version] | uninstall"
}

main() {
    local -a args=()
    while (( $# )); do
        case "$1" in
            --force)  FORCE=1 ;;
            -y|--yes) ASSUME_YES=1 ;;
            --config) shift; CONFIG_FILE="${1:-}"; [[ -n "$CONFIG_FILE" ]] || die "--config needs a file path." ;;
            --config=*) CONFIG_FILE="${1#--config=}" ;;
            -h|--help) usage; exit 0 ;;
            *) args+=("$1") ;;
        esac
        shift
    done
    local cmd="${args[0]:-}"
    COMPONENTS="${args[1]:-}"

    case "$cmd" in
        install)      run_install ;;
        status)       cmd_status ;;
        set-hive-key) require_root; cmd_set_hive_key "${args[1]:-}" ;;
        uninstall)    require_root; cmd_uninstall ;;
        upgrade)      require_root; touch "$LOG_FILE"; cmd_upgrade "${args[1]:-}" ;;
        *)            usage; exit 1 ;;
    esac
}

# Allow `source deploy-soc-stack.sh` for testing without running main
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
