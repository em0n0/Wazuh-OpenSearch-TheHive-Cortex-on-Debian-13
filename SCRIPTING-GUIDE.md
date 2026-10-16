# How to Write a Production-Quality Deployment Shell Script

A learning reference based on `deploy-soc-stack.sh` — a real script that deploys
Wazuh + TheHive + Cortex on Debian 13. Every pattern explained here came from
solving a real problem, not from theory.

---

## Table of Contents

1. [The mindset before you write a line](#1-the-mindset-before-you-write-a-line)
2. [The shebang and safety flags](#2-the-shebang-and-safety-flags)
3. [Global variables](#3-global-variables)
4. [Helper functions — the foundation](#4-helper-functions--the-foundation)
5. [Idempotency — making re-runs safe](#5-idempotency--making-re-runs-safe)
6. [Staged architecture](#6-staged-architecture)
7. [Writing heredocs for config files](#7-writing-heredocs-for-config-files)
8. [Error handling patterns](#8-error-handling-patterns)
9. [Waiting for services](#9-waiting-for-services)
10. [The main() function and argument parsing](#10-the-main-function-and-argument-parsing)
11. [Common bash traps and how to avoid them](#11-common-bash-traps-and-how-to-avoid-them)
12. [Python scripts alongside bash](#12-python-scripts-alongside-bash)
13. [The debugging mindset](#13-the-debugging-mindset)

---

## 1. The mindset before you write a line

Before writing any code, answer three questions:

**What does this script need to do?**
Define the scope clearly. Our script needs to: install packages, configure
Docker containers, write config files, start services, and handle re-runs
gracefully. Knowing this upfront shapes every design decision.

**Who runs this script and how often?**
A deployment script is typically run once (full install) and occasionally
again (re-run a broken stage, add a component). Design for both. Make re-runs
safe and fast — skipping work already done rather than repeating it.

**What can go wrong?**
Think through failure modes before writing. What if Docker isn't installed?
What if the download fails? What if a service doesn't start? A good script
handles these gracefully rather than failing silently or leaving the system
in a broken state.

---

## 2. The shebang and safety flags

Every script starts with two critical lines:

```bash
#!/usr/bin/env bash
set -euo pipefail
```

**`#!/usr/bin/env bash`** — the shebang.
Uses `env` to find bash rather than hardcoding `/bin/bash`. This is more
portable — on some systems bash lives somewhere unexpected. `bash` not `sh`
because we use bash-specific features throughout.

**`set -euo pipefail`** — the safety net. This is three flags combined:

```bash
set -e   # exit immediately if any command fails (returns non-zero)
set -u   # treat unset variables as errors instead of empty strings
set -o pipefail  # if any command in a pipe fails, the whole pipe fails
```

Without these, a script can silently continue past errors. With them, a
failure anywhere stops execution immediately. Example of why this matters:

```bash
# Without set -e: this continues even if the download fails
curl -s http://example.com/installer.sh > installer.sh
bash installer.sh   # runs a potentially empty or broken file

# With set -e: stops at the curl failure
curl -fsSL http://example.com/installer.sh > installer.sh  # -f = fail on HTTP errors
bash installer.sh
```

**`IFS=$'\n\t'`** — sets the Internal Field Separator to newline and tab only
(not space). This prevents word splitting on filenames or values that contain
spaces, which causes subtle bugs.

```bash
# Without IFS fix: this breaks if STACK_DIR contains a space
for f in $STACK_DIR; do ...   # bad

# With IFS fix: spaces in paths are handled correctly
IFS=$'\n\t'
```

---

## 3. Global variables

Define all configuration at the top. This makes the script easy to modify
without hunting through the code:

```bash
# ============================================================================
# Globals
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="/var/lib/soc-stack"
LOG_FILE="/var/log/soc-stack-install.log"
STACK_DIR="/opt/soc-stack"
ENV_FILE="${STACK_DIR}/.env"

THEHIVE_IMAGE="strangebee/thehive:5.2"
CASSANDRA_IMAGE="cassandra:4"

WAZUH_INDEXER_HEAP="1500m"
```

**`SCRIPT_DIR`** deserves special attention:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
```

This finds the directory the script lives in, regardless of where you call it
from. Broken it down:
- `${BASH_SOURCE[0]}` — path to the current script file
- `dirname` — strips the filename, leaving just the directory path
- `cd ... && pwd` — changes to that directory and prints the absolute path

This matters when the script needs to reference files next to itself (like
`files/wazuh_thehive_bridge.py`). If you used `$PWD` instead, it would break
whenever someone runs the script from a different directory.

**Why uppercase for globals?** Convention. Uppercase = global/environment
variable. Lowercase = local variable inside a function. This makes scope
immediately visible when reading.

---

## 4. Helper functions — the foundation

Define small, focused helper functions before your main logic. They make the
rest of the script readable:

```bash
# Logging with timestamp, written to both screen and log file
log()  { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
info() { log "INFO:  $*"; }
warn() { log "WARN:  $*"; }
err()  { log "ERROR: $*"; }
die()  { err "$*"; exit 1; }
```

`tee -a` is key here — it prints to stdout AND appends to a log file
simultaneously. The `-a` flag appends rather than overwriting. This means
you always have a full record of what happened, even if the terminal scrolled
past it.

**`die()`** is a clean exit pattern:
```bash
die()  { err "$*"; exit 1; }

# Usage — reads like English
[[ -f "$required_file" ]] || die "Required file not found: $required_file"
```

**Root check:**
```bash
require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }
```

`$EUID` is the effective user ID. Root is always 0. Check this at the very
start of privileged operations, not buried somewhere in the middle.

**Random secrets:**
```bash
rand_secret() { openssl rand -hex 24; }
```

`openssl rand -hex 24` generates 24 random bytes and outputs them as 48
hex characters. Safe, strong, no external dependencies beyond openssl which
is always present. Used for generating TheHive's session secret.

---

## 5. Idempotency — making re-runs safe

Idempotency means running the script twice has the same effect as running it
once. This is critical for deployment scripts — installs fail partway through
all the time, and you need to be able to re-run without starting from scratch.

The pattern used here is marker files:

```bash
mark_done() { mkdir -p "$STATE_DIR"; touch "${STATE_DIR}/$1.done"; }
is_done()   { [[ -f "${STATE_DIR}/$1.done" && $FORCE -eq 0 ]]; }
```

Each stage creates a `.done` marker on success:

```bash
stage_prereqs() {
    if is_done "prereqs"; then info "Prereqs already done, skipping."; return; fi
    
    # ... do the actual work ...
    
    mark_done "prereqs"   # only reached if everything above succeeded
}
```

If the stage fails before `mark_done`, the marker is never written, so the
next run will attempt it again. If it succeeds, the marker is written and
subsequent runs skip it.

The `FORCE` flag overrides this:
```bash
FORCE=0  # global, set to 1 by --force argument

is_done() { [[ -f "${STATE_DIR}/$1.done" && $FORCE -eq 0 ]]; }
```

```bash
# Usage
sudo ./deploy-soc-stack.sh --force install hive
```

**Idempotency in individual operations:**

Not just the stages — individual operations should also be idempotent:

```bash
# BAD: appends duplicate lines if run twice
echo 'vm.swappiness=10' >> /etc/sysctl.conf

# GOOD: only appends if the line doesn't already exist
grep -q 'vm.swappiness' /etc/sysctl.conf || echo 'vm.swappiness=10' >> /etc/sysctl.conf
```

```bash
# BAD: fails if Docker network already exists
docker network create soc-net

# GOOD: only creates if it doesn't exist
docker network inspect soc-net &>/dev/null || docker network create soc-net
```

```bash
# BAD: tries to install Docker even if already installed
apt-get install docker-ce

# GOOD: skips if already present
if command -v docker &>/dev/null; then info "Docker already installed, skipping."; return; fi
```

---

## 6. Staged architecture

Breaking the script into stages (`stage_prereqs`, `stage_wazuh`, `stage_hive`,
etc.) is one of the most important structural decisions. Here's why:

**Stages enable selective execution:**
```bash
case "$COMPONENT" in
    all)    stage_prereqs; ensure_network; stage_wazuh; stage_hive; stage_cortex; stage_bridge ;;
    wazuh)  stage_prereqs; ensure_network; stage_wazuh ;;
    hive)   stage_prereqs; ensure_network; stage_hive ;;
    cortex) stage_prereqs; ensure_network; stage_cortex ;;
    bridge) stage_bridge ;;
esac
```

This lets you run `install hive` to only deploy TheHive, or re-run just
`install cortex` when that stage fails, without touching the rest.

**Each stage is a function:**

```bash
stage_hive() {
    if is_done "hive"; then info "TheHive already installed, skipping."; return; fi
    info "=== Stage: TheHive 5.2 + Cassandra ==="

    # ... all TheHive-related work ...

    mark_done "hive"
    info "TheHive installed."
}
```

A stage function should:
1. Check if already done → skip if so
2. Log that it's starting
3. Do its work
4. Call `mark_done` only on success
5. Log what to do next

**Order matters and should be explicit:**

```bash
stage_prereqs   # installs Docker — must come first
ensure_network  # creates Docker network — needs Docker to exist
stage_wazuh     # native install, doesn't need Docker network
stage_hive      # needs Docker and the soc-net network
stage_cortex    # needs Docker and the soc-net network
stage_bridge    # needs Wazuh and TheHive to be installed
```

The bug that bit us: `ensure_network` was originally called before
`stage_prereqs`, so Docker didn't exist when the network creation was
attempted. Moving it after prereqs fixed it.

---

## 7. Writing heredocs for config files

Heredocs let you write multi-line strings directly in bash. Used extensively
for generating Docker Compose files:

```bash
cat > "${STACK_DIR}/docker-compose.hive.yml" <<EOF
services:
  cassandra:
    image: ${CASSANDRA_IMAGE}
    container_name: soc-cassandra
    restart: unless-stopped
    mem_limit: 1200m
    environment:
      - MAX_HEAP_SIZE=${CASSANDRA_HEAP}
    volumes:
      - ${STACK_DIR}/cassandra/data:/var/lib/cassandra
    networks:
      - soc-net
EOF
```

**Variable expansion in heredocs:**

With `<<EOF` (unquoted): variables ARE expanded inside the heredoc.
With `<<'EOF'` (quoted): variables are NOT expanded, written literally.

```bash
# Variables expanded — ${CASSANDRA_IMAGE} becomes its value
cat > file.yml <<EOF
image: ${CASSANDRA_IMAGE}
EOF

# Variables NOT expanded — written as literal ${CASSANDRA_IMAGE}
cat > file.yml <<'EOF'
image: ${CASSANDRA_IMAGE}
EOF
```

Use the quoted form when generating scripts or config files that should
contain their own `$VARIABLE` references (e.g., a Docker Compose file that
uses Compose's own variable substitution).

**Escaping inside heredocs:**

When the heredoc contains shell special characters that need to appear
literally in the output, escape with backslash:

```bash
cat > /etc/systemd/system/my-service.service <<EOF
[Service]
ExecStart=/usr/bin/python3 /opt/my-app/app.py
EnvironmentFile=-/opt/my-app/.env
EOF
```

The `-` before the path in `EnvironmentFile=-` is not a bash thing — it's
systemd syntax meaning "don't fail if this file is missing". Heredocs pass
it through unchanged.

---

## 8. Error handling patterns

**`|| die` for critical operations:**

```bash
curl -4 -fsSLO "$WAZUH_INSTALL_URL" || die "Failed to download Wazuh installer"
```

If curl fails, `die` is called, which logs the error and exits with code 1.
Clean and readable.

**`|| true` to suppress expected failures under `set -e`:**

```bash
apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
```

`apt-mark hold` might not exist on all systems, or the packages might not
be installed yet. We don't want the script to exit because of this. `|| true`
makes the overall expression always return 0, so `set -e` doesn't trigger.

**Arithmetic comparisons under `set -e`:**

This is a classic trap:

```bash
# This EXITS the script when disk_gb >= 40, because (( false )) returns exit code 1
(( disk_gb < 40 )) && warn "Low disk space"

# Fix: add || true so the expression always evaluates to 0
[[ $disk_gb -lt 40 ]] && warn "Low disk space" || true
```

Under `set -e`, any command returning non-zero exits the script. `(( expr ))`
returns 1 when the expression is false (i.e., 0). So `(( 208 < 40 ))` returns
1 (false), which `set -e` treats as a failure. The fix: use `[[ ]]` with
`|| true` to ensure the overall expression always succeeds.

**`2>/dev/null` for expected noise:**

```bash
docker network inspect soc-net &>/dev/null || docker network create soc-net
```

`&>/dev/null` redirects both stdout and stderr to `/dev/null`. Used when a
command might print error output for expected "failure" cases (like "network
not found") that we're handling ourselves.

**Conditional file existence checks:**

```bash
[[ -f "$jvm_opts" ]] || { warn "jvm.options not found, skipping."; return; }
```

`{ ... }` groups multiple commands. This reads: "if the file doesn't exist,
warn and return from the function." The `||` means "if the left side fails
(file doesn't exist), do the right side."

---

## 9. Waiting for services

Services don't start instantly. A common mistake is starting a service and
immediately trying to use it. The right pattern is a polling loop:

```bash
wait_for_http() {
    local url="$1" timeout="$2" waited=0
    until curl -sf "$url" -o /dev/null 2>/dev/null; do
        sleep 5; waited=$((waited+5))
        (( waited >= timeout )) && { warn "${url} not healthy after ${timeout}s."; return 1; }
    done
    info "${url} is healthy (${waited}s)"
}

# Usage
wait_for_http "http://localhost:9000/api/status" 300
```

`until` loops until the condition is true (opposite of `while`). Each
iteration sleeps 5 seconds and checks elapsed time. If the timeout is reached,
it warns rather than dying — sometimes a service is just slow.

**For non-HTTP services (like Elasticsearch on port 9200):**

```bash
local es_wait=0
until curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1; do
    sleep 5; es_wait=$((es_wait+5))
    if (( es_wait >= 120 )); then
        warn "ES did not respond in 120s — continuing anyway."
        break
    fi
done
```

**Why not just `sleep 30`?**

A fixed sleep is fragile — too short on a slow machine, wastes time on a fast
one. A polling loop adapts to actual service startup time and gives you
accurate timing information in the logs.

---

## 10. The main() function and argument parsing

Wrapping everything in `main()` and calling it at the end is a clean pattern:

```bash
main() {
    local cmd="${1:-}"
    
    # Handle --force flag
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
            echo "Usage: $0 {install [all|wazuh|hive|cortex|bridge]|status|set-hive-key <key>|uninstall}"
            exit 1
            ;;
    esac
}

main "$@"   # call main with all script arguments
```

**`"${1:-}"`** — the `:-` syntax provides a default value. If `$1` is unset
or empty, the expression evaluates to the default (empty string here). Without
this, `set -u` would exit on an unset variable.

**`case` statements** are cleaner than `if/elif` chains for command dispatch.
The `*)` at the end is the catch-all (like `default` in a switch statement).

**`"$@"`** — passes all arguments to `main()` as separate quoted words,
preserving any spaces in arguments.

---

## 11. Common bash traps and how to avoid them

These are the bugs that hit the script during development:

**Trap 1: Unquoted variables**
```bash
# BAD: breaks if path contains spaces
cd $STACK_DIR

# GOOD: always quote variables
cd "$STACK_DIR"
```

**Trap 2: `set -e` exits on false arithmetic**
```bash
# BAD: exits when condition is false
(( count < 5 ))

# GOOD: use [[ ]] with || true, or arithmetic in if
[[ $count -lt 5 ]] && do_something || true
# OR
if (( count < 5 )); then do_something; fi
```

**Trap 3: `curl` silently saving error pages**
```bash
# BAD: saves whatever the server returns, even a 403 HTML page
curl -sO https://example.com/script.sh
bash script.sh   # runs HTML, fails mysteriously

# GOOD: -f makes curl fail on HTTP errors
curl -fsSLO https://example.com/script.sh
bash script.sh
```

**Trap 4: `localhost` resolving to IPv6**
```bash
# BAD: on Debian 13, localhost resolves to ::1 (IPv6)
# if the service only listens on 127.0.0.1 (IPv4), this fails
curl http://localhost:9200

# GOOD: use explicit IPv4 address, or force IPv4
curl http://127.0.0.1:9200
curl -4 http://localhost:9200
```

**Trap 5: Docker `depends_on` without health conditions**
```bash
# BAD: Cassandra "started" doesn't mean it's ready to accept connections
depends_on:
  - cassandra

# GOOD: wait for the healthcheck to pass
depends_on:
  cassandra:
    condition: service_healthy
```

**Trap 6: Host directory ownership for Docker bind mounts**
```bash
# BAD: directory created by root, container runs as uid 1000
mkdir -p /opt/soc-stack/thehive/files
docker run -v /opt/soc-stack/thehive/files:/data ...
# Container gets "permission denied"

# GOOD: match the container's expected uid:gid
mkdir -p /opt/soc-stack/thehive/files
chown -R 1000:1000 /opt/soc-stack/thehive
docker run -v /opt/soc-stack/thehive/files:/data ...
```

**Trap 7: Offset files and sentinel values**
```bash
# BAD: treats 0 as "no saved offset" — can't deliberately seek to start
if [[ $offset -eq 0 ]]; then
    seek_to_end
fi

# GOOD: check whether the file existed, not what value it contains
offset, file_existed = load_offset()
if not file_existed:
    seek_to_end
else:
    seek_to(offset)   # honours explicit 0
```

---

## 12. Python scripts alongside bash

Complex logic (API calls, JSON parsing, stateful file tailing) belongs in
Python, not bash. The pattern used for the alert bridge:

**Bash installs and manages the service. Python does the work.**

```bash
# In the bash script: install Python, create venv, install deps, write systemd unit
python3 -m venv /opt/soc-stack/bridge/venv
/opt/soc-stack/bridge/venv/bin/pip install -r requirements.txt

cat > /etc/systemd/system/wazuh-thehive-bridge.service <<EOF
[Unit]
Description=Wazuh alert -> TheHive bridge
After=network.target

[Service]
EnvironmentFile=-/opt/soc-stack/.env
ExecStart=/opt/soc-stack/bridge/venv/bin/python3 /opt/soc-stack/bridge/bridge.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wazuh-thehive-bridge.service
```

**The Python script reads its config from environment variables**, which
systemd loads from the `.env` file via `EnvironmentFile`. This keeps secrets
out of the script itself and makes the key easy to update:

```python
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "").strip()
THEHIVE_URL     = os.environ.get("THEHIVE_URL", "http://localhost:9000")
MIN_LEVEL       = int(os.environ.get("MIN_ALERT_LEVEL", "7"))
```

**Virtual environments for isolation:**

Using `python3 -m venv` creates an isolated Python environment in
`/opt/soc-stack/bridge/venv/`. Installing packages into it
(`venv/bin/pip install`) doesn't affect the system Python. Running the script
with `venv/bin/python3` ensures it uses exactly the packages you installed,
regardless of what else is on the system.

---

## 13. The debugging mindset

The script went through 13 bug fixes during real deployment. The process for
finding each one was the same:

**Step 1: Read the actual error**

Not the symptom. The error. `docker: command not found` when creating a
network tells you Docker isn't installed yet — which tells you the network
creation is running before the Docker install stage.

**Step 2: Add `-x` to trace execution**

```bash
sudo bash -x ./deploy-soc-stack.sh install 2>&1 | head -60
```

`-x` prints every command before executing it, with a `+` prefix. You can
see exactly which line the script is on when it fails, what variables
expanded to, and what order things are running.

**Step 3: Test the minimal reproduction**

Before fixing the script, reproduce the failure manually in a terminal:

```bash
# Does TheHive actually reject a missing directory? Test it:
mkdir /tmp/test-dir   # owned by root
docker run --rm -v /tmp/test-dir:/data ubuntu ls -la /data
# → permission denied? Yes → chown fixes it
```

**Step 4: Fix the root cause, not the symptom**

The `localhost` → `::1` issue: the symptom was "dashboard can't connect to
indexer". The root cause was IPv6/IPv4 mismatch. Fixing the symptom
(restarting services) doesn't help. Fixing the root cause (changing
`localhost` to `127.0.0.1`) does.

**Step 5: Make the fix idempotent**

Every fix should work on a clean system and on a partially-installed system.
Test both.

---

## Summary: the patterns that matter most

| Pattern | Why it matters |
|---|---|
| `set -euo pipefail` | Fails loudly instead of silently continuing past errors |
| Helper functions first | Makes the main logic readable |
| Idempotency via marker files | Safe to re-run after failures |
| Staged architecture | Run only what you need |
| Heredocs for config | Config lives in the script, not separate files |
| `|| true` on optional commands | Prevents `set -e` from killing the script on expected failures |
| `[[ ]]` over `[ ]` | Safer string comparisons, no word splitting issues |
| Always quote variables | Prevents word splitting on spaces |
| Python for complex logic | JSON, HTTP, state management belong in Python not bash |
| Polling loops not `sleep` | Adapts to actual service startup time |

The most important thing isn't any individual pattern — it's treating the
script like production code. Write it to be read, not just to run. Comment
the non-obvious decisions. Handle failures explicitly. Make it easy to debug
when something goes wrong, because something will go wrong.
