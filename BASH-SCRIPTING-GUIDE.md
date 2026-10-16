# How to Write a Bash Deployment Script — A Learning Guide

This document teaches you how to write a deployment script the way `deploy-soc-stack.sh` was written. Every pattern, technique, and decision is explained from first principles with examples drawn directly from the script.

By the end you should be able to write your own idempotent, staged, safe bash deployment script for any multi-component system.

---

## Table of Contents

1. [The mindset: what makes a deployment script good](#1-the-mindset)
2. [The shebang and safety flags](#2-the-shebang-and-safety-flags)
3. [Global variables](#3-global-variables)
4. [Helper functions: logging, dying, confirming](#4-helper-functions)
5. [Idempotency: making stages skippable](#5-idempotency)
6. [Checking system resources before doing anything](#6-checking-resources)
7. [Waiting for services: the polling loop](#7-waiting-for-services)
8. [Writing config files from inside bash: heredocs](#8-heredocs)
9. [Generating secrets at install time](#9-generating-secrets)
10. [Stages: breaking the install into pieces](#10-stages)
11. [The main() dispatcher pattern](#11-the-main-dispatcher)
12. [Docker inside a deploy script](#12-docker-inside-a-deploy-script)
13. [Writing systemd service files from bash](#13-systemd-service-files)
14. [Fixing third-party installer quirks](#14-patching-third-party-installers)
15. [File permissions and container user IDs](#15-file-permissions-and-container-uids)
16. [Common bash pitfalls and how to avoid them](#16-common-pitfalls)
17. [How to test and validate your script](#17-testing-and-validation)

---

## 1. The mindset

Before writing a single line, ask four questions about your script:

**1. Is it idempotent?**
Running it twice should not break anything. If Wazuh is already installed, the script should detect that and skip it. If a file already exists, don't overwrite it blindly.

**2. Is it re-enterable?**
If it fails halfway through, can you run it again and pick up where it left off? A script that has to be run from scratch every time a single step fails is painful in practice.

**3. Does it fail loudly?**
If something goes wrong, the script should stop immediately and tell you exactly what failed and where. Silent failures are much harder to debug than noisy ones.

**4. Is it readable in six months?**
You or someone else will read this script later. Comments should explain *why*, not *what*. The code already shows what it does — comments add the reasoning behind decisions.

`deploy-soc-stack.sh` was designed with all four in mind. Every pattern in it serves one of these goals.

---

## 2. The shebang and safety flags

Every script in this codebase starts with:

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
```

**Line 1 — the shebang:**
```bash
#!/usr/bin/env bash
```
`/usr/bin/env bash` is preferred over `/bin/bash` because it finds bash wherever it lives on the system, rather than hardcoding a path that might not exist on every distro.

**Line 2 — safety flags:**
```bash
set -euo pipefail
```

This is three flags combined:

| Flag | What it does | Why |
|---|---|---|
| `-e` | Exit immediately if any command returns non-zero | Prevents silent failures from cascading |
| `-u` | Treat unset variables as errors | Catches typos like `$STAC_DIR` instead of `$STACK_DIR` |
| `-o pipefail` | Fail if any command in a pipeline fails | Without this, `false | true` would succeed |

**A critical `-e` gotcha:**
```bash
# This BREAKS under set -e because [[ ]] returns exit code 1 when false
[[ $mem_gb -lt 7 ]] && warn "Low RAM"

# This is SAFE — || true swallows the non-zero exit code
[[ $mem_gb -lt 7 ]] && warn "Low RAM" || true
```

The script hit exactly this bug in production — the resource check was silently killing the script when the system had *enough* RAM, because `[[ 8 -lt 7 ]]` returns exit code 1 (false), and `set -e` interpreted that as a fatal error. The fix is `|| true` on any conditional that is expected to be false.

**Line 3 — IFS:**
```bash
IFS=$'\n\t'
```
`IFS` is the Internal Field Separator — it controls how bash splits strings into words. The default includes spaces, which means a filename with a space in it can split unexpectedly into multiple arguments. Setting it to only newlines and tabs prevents this class of bug.

---

## 3. Global variables

All configuration is declared at the top of the script before any functions:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="/var/lib/soc-stack"
LOG_FILE="/var/log/soc-stack-install.log"
STACK_DIR="/opt/soc-stack"
ENV_FILE="${STACK_DIR}/.env"

WAZUH_INSTALL_URL="https://packages.wazuh.com/4.14/wazuh-install.sh"

THEHIVE_IMAGE="strangebee/thehive:5.2"
CASSANDRA_IMAGE="cassandra:4"
```

**Why globals at the top:**
- Easy to change versions or paths in one place
- Anyone reading the script knows what can be configured without reading every function
- Functions reference the globals by name, making the code self-documenting

**`SCRIPT_DIR` explained:**
```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
```
This is the canonical way to get the directory the script lives in, regardless of where you run it from. Breaking it down:
- `${BASH_SOURCE[0]}` — the path to this script file
- `dirname` — strips the filename, leaving the directory
- `cd ... && pwd` — resolves any relative paths or symlinks to an absolute path

This matters because the script needs to find files relative to itself (`files/wazuh_thehive_bridge.py`). If you used `$PWD` instead, the path would break if you ran the script from a different directory.

**`FORCE` and `COMPONENT`:**
```bash
FORCE=0
COMPONENT="${2:-all}"
```
`${2:-all}` means "use the second argument, or `all` if it wasn't provided." This is bash's default-value syntax: `${variable:-default}`.

---

## 4. Helper functions

The script defines a small set of helper functions used throughout. This avoids repetition and makes the main logic readable.

### Logging

```bash
log()  { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
info() { log "INFO:  $*"; }
warn() { log "WARN:  $*"; }
err()  { log "ERROR: $*"; }
die()  { err "$*"; exit 1; }
```

Every output goes through `log()`, which:
1. Prepends a timestamp
2. Prints to the terminal (`echo`)
3. Appends to a log file (`tee -a`)

This means every run is automatically logged. When something breaks you can run `cat /var/log/soc-stack-install.log` and see the full history.

`$*` means "all arguments as a single string." This lets you write `info "hello world"` and get the whole string.

`die()` calls `err()` then exits with code 1. This is the clean way to abort on fatal errors:
```bash
[[ -n "$bridge_src" ]] || die "wazuh_thehive_bridge.py not found"
```
Read as: "bridge_src must be non-empty, otherwise die." The `||` (or) operator runs the right side only if the left side fails. `[[ -n "$bridge_src" ]]` returns non-zero when the variable is empty.

### Confirming destructive actions

```bash
confirm() {
    read -r -p "${1} [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}
```

Used before the uninstall command:
```bash
confirm "This will STOP and REMOVE everything. Continue?" || { info "Aborted."; exit 0; }
```

`read -r` reads a line without interpreting backslashes. `-p` shows a prompt. The `=~` operator does regex matching — `^[Yy]$` matches exactly `y` or `Y`.

---

## 5. Idempotency

The most important design pattern in the script is the marker-file system:

```bash
mark_done() { mkdir -p "$STATE_DIR"; touch "${STATE_DIR}/$1.done"; }
is_done()   { [[ -f "${STATE_DIR}/$1.done" && $FORCE -eq 0 ]]; }
```

Every stage starts with:
```bash
stage_wazuh() {
    if is_done "wazuh"; then info "Wazuh already installed, skipping."; return; fi
    # ... actual install work ...
    mark_done "wazuh"
}
```

How it works:
- `mark_done "wazuh"` creates `/var/lib/soc-stack/wazuh.done`
- `is_done "wazuh"` checks if that file exists AND `FORCE` is 0
- If both are true, the stage is skipped
- `--force` sets `FORCE=1`, which makes `is_done` return false even if the marker exists

This means:
- Running the script twice doesn't reinstall anything
- If the script fails mid-install, re-running it picks up from the last incomplete stage
- You can force a specific stage to re-run with `--force install wazuh`

The markers live in `/var/lib/soc-stack/` because that is the standard FHS location for persistent state data from local programs.

---

## 6. Checking resources

```bash
check_resources() {
    local mem_gb cpu_count disk_gb
    mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
    cpu_count=$(nproc)
    disk_gb=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')
    info "Detected: ${mem_gb}GB RAM, ${cpu_count} vCPU, ${disk_gb}GB free on /"
    [[ $mem_gb -lt 7 ]] && warn "Less than 7GB RAM." || true
    [[ $disk_gb -lt 40 ]] && warn "Less than 40GB free." || true
}
```

**`/proc/meminfo`** is a virtual file Linux provides for reading system memory stats. `awk` extracts the `MemTotal` line and converts from kilobytes to gigabytes.

**`local`** declares variables as function-scoped. Without `local`, `mem_gb` would be a global variable and could clash with other code. Always use `local` inside functions.

**`$( )` — command substitution:**
```bash
mem_gb=$(awk '/MemTotal/ ...' /proc/meminfo)
```
The `$( )` syntax runs the command inside and substitutes its output as a string. This is preferred over backticks because it is easier to read and can be nested.

---

## 7. Waiting for services

Many deployment scripts need to wait for a service to become ready before continuing. The pattern used here is a polling loop:

```bash
wait_for_http() {
    local url="$1" timeout="$2" waited=0
    until curl -sf "$url" -o /dev/null 2>/dev/null; do
        sleep 5; waited=$((waited+5))
        (( waited >= timeout )) && { warn "${url} not healthy after ${timeout}s."; return 1; }
    done
    info "${url} is healthy (${waited}s)"
}
```

**`until`** is the opposite of `while` — it loops until the condition is true (while it is false).

**`curl -sf`** flags:
- `-s` — silent (no progress bar)
- `-f` — fail on HTTP error codes (4xx, 5xx)
- `-o /dev/null` — discard the response body
- `2>/dev/null` — discard stderr

The curl command succeeds (exit 0) only when the URL returns a 2xx HTTP response. Until that happens, the loop sleeps 5 seconds and increments the counter.

**`(( waited >= timeout ))`** — arithmetic evaluation. Double parentheses let you write math without `$` signs. Returns exit code 0 if the expression is non-zero (truthy).

**`$((waited+5))`** — arithmetic expansion. Returns the result of the arithmetic as a string.

---

## 8. Heredocs

A heredoc lets you embed multi-line text directly in a bash script. The script uses this extensively to write config files:

```bash
cat > "${STACK_DIR}/docker-compose.hive.yml" <<EOF
services:
  cassandra:
    image: ${CASSANDRA_IMAGE}
    container_name: soc-cassandra
    mem_limit: 1200m
EOF
```

**How it works:**
- `<<EOF` starts a heredoc that ends at the next line containing only `EOF`
- Everything between the two `EOF` markers is sent to stdin of `cat`
- `cat >` redirects that stdin to the file
- Variables like `${CASSANDRA_IMAGE}` are expanded normally

**Variable expansion in heredocs:**
By default, variables ARE expanded inside heredocs. To write a heredoc where variables should NOT be expanded, quote the delimiter:

```bash
cat > /tmp/example.sh <<'EOF'
echo "This $variable will NOT be expanded"
EOF
```

The single quotes around `'EOF'` tell bash to treat the heredoc literally.

The script uses both forms — unquoted `<<EOF` when it wants to embed actual values into compose files, and would use `<<'EOF'` when writing files that contain their own `$` references.

**Writing the systemd service file:**
```bash
cat > /etc/systemd/system/wazuh-thehive-bridge.service <<EOF
[Unit]
Description=Wazuh alert -> TheHive bridge
After=network.target docker.service wazuh-manager.service

[Service]
Type=simple
EnvironmentFile=-${ENV_FILE}
ExecStart=/opt/soc-stack/bridge/venv/bin/python3 /opt/soc-stack/bridge/bridge.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

`${ENV_FILE}` is expanded here — the actual path gets written into the service file. The `-` prefix on `EnvironmentFile=-` means "don't fail if this file doesn't exist."

---

## 9. Generating secrets

```bash
rand_secret() { openssl rand -hex 24; }
```

```bash
ensure_env_file() {
    mkdir -p "$STACK_DIR"
    if [[ ! -f "$ENV_FILE" ]]; then
        cat > "$ENV_FILE" <<EOF
THEHIVE_SECRET=$(rand_secret)
THEHIVE_API_KEY=
EOF
        chmod 600 "$ENV_FILE"
    fi
}
```

**`openssl rand -hex 24`** generates 24 cryptographically random bytes and prints them as 48 hex characters. This is the right way to generate secrets in bash — do not use `$RANDOM` (only 15 bits of entropy) or date-based hashes.

**`chmod 600`** sets permissions to owner-read/owner-write only. No other user on the system can read the file.

**`[[ ! -f "$ENV_FILE" ]]`** — the `-f` test returns true if the file exists and is a regular file. The `!` negates it. This block only runs if the env file doesn't already exist, preventing secrets from being regenerated on every run.

---

## 10. Stages

The script is broken into discrete stages, each encapsulated in a function:

```
stage_prereqs()  -> apt packages, swap, Docker
stage_wazuh()    -> download and run Wazuh installer, tune JVM
stage_hive()     -> create dirs, fix permissions, write compose, start containers
stage_cortex()   -> same pattern, but start ES and Cortex separately
stage_bridge()   -> find source files, create venv, write systemd unit
```

Each stage follows the same pattern:
1. Check if already done, skip if so
2. Log that the stage is starting
3. Do the work
4. Mark as done
5. Log the result

**Finding files in multiple locations:**
The bridge stage needs to locate `wazuh_thehive_bridge.py` which might be in `files/` or flat alongside the script:

```bash
local bridge_src=""
for candidate in \
    "${SCRIPT_DIR}/files/wazuh_thehive_bridge.py" \
    "${SCRIPT_DIR}/wazuh_thehive_bridge.py"; do
    [[ -f "$candidate" ]] && { bridge_src="$candidate"; break; }
done
[[ -n "$bridge_src" ]] || die "wazuh_thehive_bridge.py not found"
```

The loop tries each candidate path in order. When it finds one that exists, it saves the path and `break`s. If none are found, `bridge_src` remains empty and `die` is called. This is more robust than hardcoding a single path.

---

## 11. The main() dispatcher

The entry point is a `main()` function at the bottom of the script:

```bash
main() {
    local cmd="${1:-}"
    [[ "$cmd" == "--force" ]] && { FORCE=1; cmd="${2:-}"; COMPONENT="${3:-all}"; }

    case "$cmd" in
        install)
            require_root
            check_resources
            case "$COMPONENT" in
                all)    stage_prereqs; ensure_network; stage_wazuh; stage_hive; stage_cortex; stage_bridge ;;
                wazuh)  stage_prereqs; ensure_network; stage_wazuh ;;
                hive)   stage_prereqs; ensure_network; stage_hive ;;
                cortex) stage_prereqs; ensure_network; stage_cortex ;;
                bridge) stage_bridge ;;
                *) die "Unknown component '$COMPONENT'." ;;
            esac
            ;;
        status)       cmd_status ;;
        set-hive-key) require_root; cmd_set_hive_key "${2:-}" ;;
        uninstall)    require_root; cmd_uninstall ;;
        *)
            echo "Usage: $0 {install|status|set-hive-key <key>|uninstall}"
            exit 1
            ;;
    esac
}

main "$@"
```

**Why `main()` at the bottom:**
Bash executes top-to-bottom, but functions must be defined before they are called. By putting `main()` last and calling it with `main "$@"` on the final line, all helper functions are defined by the time `main` runs. `$@` passes all the script's arguments to `main`.

**`case` statement:**
`case` is bash's switch/match construct. It is cleaner than a chain of `if/elif/else` when matching a variable against multiple patterns. The `*)` at the end is the catch-all (default case).

**`--force` handling:**
```bash
[[ "$cmd" == "--force" ]] && { FORCE=1; cmd="${2:-}"; COMPONENT="${3:-all}"; }
```
If the first argument is `--force`, set the flag and shift the argument positions. This allows:
```bash
./deploy-soc-stack.sh install hive           # normal
./deploy-soc-stack.sh --force install hive   # force re-run
```

**`require_root()`:**
```bash
require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }
```
`$EUID` is the effective user ID. Root's UID is 0. This check is only applied to commands that need root — `status` deliberately does not require it so any user can check the stack health.

---

## 12. Docker inside a deploy script

**Creating a network idempotently:**
```bash
ensure_network() {
    docker network inspect soc-net &>/dev/null || docker network create soc-net
}
```
`docker network inspect` returns non-zero if the network doesn't exist. The `||` runs `docker network create` only if the inspect fails. `&>/dev/null` discards both stdout and stderr.

**Starting services in the right order:**
The Cortex stage demonstrates how to work around a broken healthcheck dependency:

```bash
# Start ES first
docker compose -f docker-compose.cortex.yml up -d cortex-elasticsearch --no-deps

# Wait for it to actually respond
until curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1; do
    sleep 5
done

# Then start Cortex
docker compose -f docker-compose.cortex.yml up -d cortex --no-deps
```

`--no-deps` tells Docker Compose to start only the named service, ignoring dependency declarations in the compose file. This bypasses the healthcheck-based dependency that was causing problems and replaces it with an explicit curl-based wait that is more reliable.

**`mem_limit` in compose files:**
```yaml
mem_limit: 1500m
```
Without memory limits, any single container can consume all available RAM and cause OOM kills on other services. Size them conservatively — slightly slower is better than starving neighbouring services.

---

## 13. Systemd service files

The key sections of a service file:

```ini
[Unit]
Description=Wazuh alert -> TheHive bridge
After=network.target docker.service wazuh-manager.service
Wants=network.target
```
`After=` declares ordering — this service starts only after the listed units are active. `Wants=` is a weaker dependency — it tries to start `network.target` but doesn't fail if it doesn't.

```ini
[Service]
Type=simple
EnvironmentFile=-/opt/soc-stack/.env
ExecStart=/opt/soc-stack/bridge/venv/bin/python3 /opt/soc-stack/bridge/bridge.py
Restart=on-failure
RestartSec=5
```
- `Type=simple` — the process doesn't fork; systemd tracks the main PID directly
- `EnvironmentFile=-` — load environment variables from the file; `-` means don't fail if missing
- `Restart=on-failure` — restart the service if it exits with a non-zero code
- `RestartSec=5` — wait 5 seconds before restarting (prevents tight crash loops)

After writing the file:
```bash
systemctl daemon-reload          # tell systemd to re-read unit files
systemctl enable servicename     # create the symlink for auto-start on boot
systemctl start servicename      # start it now
```

---

## 14. Patching third-party installers

Sometimes an upstream installer does something incompatible with your environment. The clean approach is to patch the installer before running it:

```bash
curl -4 -fsSLO "$WAZUH_INSTALL_URL"
chmod +x wazuh-install.sh

# Debian 13 fix: installer tries to install software-properties-common
# which doesn't exist on Trixie. Strip it before running.
sed -i 's/software-properties-common//g' wazuh-install.sh

bash wazuh-install.sh -a -i | tee -a "$LOG_FILE"
```

**`sed -i`** edits a file in-place. `s/old/new/g` replaces all occurrences of `old` with `new`. Here, `software-properties-common` is replaced with an empty string — effectively deleting it from the installer.

**`curl -4 -fsSLO`** flags:
- `-4` — force IPv4 (avoids IPv6 timeout when IPv6 is broken on the network)
- `-f` — fail on HTTP errors (returns non-zero instead of saving an error page)
- `-s` — silent
- `-S` — show errors even when silent
- `-L` — follow redirects
- `-O` — save with the remote filename

The `-f` flag is the critical one. Without it, `curl` returns exit code 0 even when the server returns a 403 or 404, silently saving an HTML error page as your installer. Then bash tries to execute the HTML and produces confusing errors.

---

## 15. File permissions and container UIDs

This is one of the most common sources of mysterious failures when mounting volumes into Docker containers.

When you create a directory with `mkdir`, it is owned by the user who ran the command — usually root when running a deploy script. But containers run processes as specific non-root users internally.

**TheHive example:**
```bash
mkdir -p "${STACK_DIR}/thehive/data" "${STACK_DIR}/thehive/files"
# TheHive container runs as uid:gid 1000:1000
chown -R 1000:1000 "${STACK_DIR}/thehive"
chmod 700 "${STACK_DIR}/thehive/files"
```

If you don't do this, the container process tries to write to a root-owned directory and gets `Permission denied`. The container then fails to start, often with a confusing error message that doesn't mention permissions at all.

**How to find the right UID:**
Run the container temporarily and check:
```bash
docker run --rm strangebee/thehive:5.2 id
```
Or read the error message carefully — `ERROR the directory '/path' is not writable, needs uid:gid 1000:1000` tells you exactly what you need.

**Different containers, different UIDs:**
```bash
chown -R 1000:1000 "${STACK_DIR}/thehive"       # TheHive: uid 1000, gid 1000
chown -R 999:999   "${STACK_DIR}/cassandra"     # Cassandra: uid 999, gid 999
chown -R 1000:0    "${STACK_DIR}/cortex/es-data" # ES 7.x: uid 1000, gid 0 (root group)
```

Each official Docker image makes its own choices about what user to run as. There is no universal answer — look it up per image.

---

## 16. Common pitfalls

### Pitfall 1: Unquoted variables

```bash
# WRONG — breaks if STACK_DIR contains spaces
mkdir -p $STACK_DIR/thehive

# CORRECT
mkdir -p "${STACK_DIR}/thehive"
```

Always quote variable references with `"${}"`. The curly braces make the boundary of the variable name explicit, and the double quotes prevent word-splitting and glob expansion.

### Pitfall 2: set -e and arithmetic

```bash
# WRONG — exits the script when mem_gb >= 7, because [[ ]] returns 1 (false)
[[ $mem_gb -lt 7 ]] && warn "Low RAM"

# CORRECT — || true swallows the non-zero exit code
[[ $mem_gb -lt 7 ]] && warn "Low RAM" || true
```

### Pitfall 3: Failing silently on curl errors

```bash
# WRONG — saves an HTML error page, returns exit 0
curl -sO https://example.com/installer.sh

# CORRECT — fails on HTTP errors
curl -fsSLO https://example.com/installer.sh || die "Download failed"
```

### Pitfall 4: Not waiting for services

```bash
# WRONG — starts TheHive before Cassandra is ready
docker compose up -d

# CORRECT — wait for the dependency explicitly
docker compose up -d cassandra --no-deps
until curl -sf http://localhost:9042; do sleep 5; done
docker compose up -d thehive --no-deps
```

### Pitfall 5: Overwriting secrets on re-run

```bash
# WRONG — regenerates a new secret every time, breaking existing deployments
THEHIVE_SECRET=$(openssl rand -hex 24)

# CORRECT — only generate if the file doesn't exist yet
if [[ ! -f "$ENV_FILE" ]]; then
    echo "THEHIVE_SECRET=$(openssl rand -hex 24)" > "$ENV_FILE"
fi
```

### Pitfall 6: Not declaring local variables

```bash
# WRONG — mem_gb is a global, can clash with other code
check_resources() {
    mem_gb=$(awk ...)
}

# CORRECT
check_resources() {
    local mem_gb
    mem_gb=$(awk ...)
}
```

### Pitfall 7: Using cd without checking if it worked

```bash
# WRONG — if cd fails, subsequent commands run in the wrong directory
cd "$STACK_DIR"
docker compose up -d

# CORRECT — combine with &&
cd "$STACK_DIR" && docker compose up -d
```

---

## 17. Testing and validation

### Syntax checking

```bash
bash -n deploy-soc-stack.sh
```
`-n` parses the script without executing it, catching syntax errors. Always run this before deploying.

### Static analysis with shellcheck

```bash
sudo apt install shellcheck
shellcheck deploy-soc-stack.sh
```

shellcheck catches unquoted variables, deprecated syntax, unreachable code, and incorrect use of `[` vs `[[`. It is the best static analysis tool available for bash.

### Testing idempotency

Run the install twice:
```bash
sudo ./deploy-soc-stack.sh install
sudo ./deploy-soc-stack.sh install  # should skip all stages
```

### Testing failure recovery

Interrupt the script mid-install (Ctrl+C), then re-run it. Completed stages should be skipped and the interrupted stage should re-run.

### Debug tracing with bash -x

```bash
sudo bash -x ./deploy-soc-stack.sh install 2>&1 | head -100
```
`-x` prints each command before executing it, prefixed with `+`. This is invaluable for debugging — you can see exactly what command failed and with what arguments.

---

## Summary: the patterns to remember

| Pattern | Why it matters |
|---|---|
| `set -euo pipefail` | Fail fast and loud — don't let errors cascade silently |
| Marker files for idempotency | Re-runnable without breaking anything |
| All config as globals at the top | Single place to change versions and paths |
| Helper functions for logging | Every action is timestamped and persisted to a log file |
| `local` in all functions | Prevents variable leakage between functions |
| `${variable:-default}` | Safe defaults without crashing on unset variables |
| `|| true` on conditionals | Prevents false-returning conditions from triggering `set -e` |
| `curl -fsSL` not `curl -s` | Fail on HTTP errors, not silently |
| `chown` before mounting volumes | Containers run as non-root users internally |
| Heredocs for config files | Write multi-line files cleanly from within the script |
| `main "$@"` at the bottom | All functions defined before main runs |
| `shellcheck` before shipping | Catches a large class of bash bugs statically |
