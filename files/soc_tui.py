#!/usr/bin/env python3
"""
soc_tui.py — terminal UI for deploy-soc-stack.sh   (launched by ./soc-deploy)

Collects choices (components, extra Wazuh users, n8n email settings), writes
them to a private 0600 JSON file, then runs

    deploy-soc-stack.sh install <components> --config <file>

while showing per-stage progress and the live log.  Secrets travel in the
config file, never in argv.

Layers:
  * core (stdlib only): validators, config builder, runner helpers, plain mode
  * Textual UI: imported lazily, so `--plain` works with just python3

Usage:  soc_tui.py [--plain] [--force] [--deploy-script PATH]
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# ───────────────────────────── core: constants ──────────────────────────────

STACK_DIR = Path(os.environ.get("SOC_STACK_DIR", "/opt/soc-stack"))

# (key, label, default-on)
COMPONENTS = [
    ("wazuh",  "Wazuh  (manager + indexer + dashboard, native)", True),
    ("hive",   "TheHive 5 + Cassandra  (Docker)",                True),
    ("cortex", "Cortex 3 + Elasticsearch  (Docker)",             True),
    ("bridge", "Alert bridge  Wazuh -> TheHive  (systemd)",      True),
    ("n8n",    "n8n email alerts  (Docker, asks for SMTP)",      False),
    ("users",  "Extra Wazuh dashboard users  (admin/analyst/viewer)", False),
]
STAGE_ORDER = ["prereqs", "wazuh", "users", "hive", "cortex", "n8n", "bridge"]
STAGE_LABEL = {
    "prereqs": "OS prerequisites + Docker + swap",
    "wazuh":   "Wazuh",
    "users":   "Extra Wazuh users",
    "hive":    "TheHive + Cassandra",
    "cortex":  "Cortex + Elasticsearch",
    "n8n":     "n8n email alerts",
    "bridge":  "Alert bridge",
}
ROLES = ("admin", "analyst", "viewer")
RESERVED_USERS = {"admin", "kibanaserver", "kibanaro", "logstash", "readall",
                  "snapshotrestore", "wazuh", "wazuh-wui"}

# Wazuh alert levels users can pick as the e-mail threshold
LEVEL_HINTS = {7: "medium", 10: "high (recommended)", 12: "high+", 13: "critical", 15: "maximum"}
LEVELS = [4, 7, 10, 12, 13, 15]
GMAIL = {"host": "smtp.gmail.com", "port": "465"}

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
EMAIL_RE = re.compile(r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

# ───────────────────────────── core: validation ─────────────────────────────

def valid_username(name: str) -> str | None:
    """Return an error message, or None if OK."""
    if not USER_RE.match(name):
        return "Username: 3-32 chars, letters/digits/._- only."
    if name.lower() in RESERVED_USERS:
        return f"'{name}' is a built-in account and cannot be used."
    return None


def valid_password(pw: str) -> str | None:
    if not 8 <= len(pw) <= 64:
        return "Password must be 8-64 characters."
    if re.search(r"\s", pw):
        return "Password must not contain whitespace."
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw)
            and re.search(r"\d", pw) and re.search(r"[^A-Za-z0-9]", pw)):
        return "Password needs upper, lower, digit and a symbol."
    return None


def valid_email(addr: str) -> bool:
    return bool(EMAIL_RE.match(addr))


def parse_recipients(text: str) -> tuple[list[str], list[str]]:
    """Split on comma/semicolon/whitespace; returns (valid, invalid)."""
    items = [t for t in re.split(r"[,\s;]+", text.strip()) if t]
    good = [t for t in items if valid_email(t)]
    bad = [t for t in items if not valid_email(t)]
    return good, bad


def validate_smtp(host: str, port: str, sender: str, recips: str) -> str | None:
    if not host.strip():
        return "SMTP host is required."
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return "SMTP port must be a number (465 for SSL, 587 for STARTTLS)."
    if not valid_email(sender.strip()):
        return "'From' must be a valid email address."
    good, bad = parse_recipients(recips)
    if bad:
        return f"Invalid recipient address: {bad[0]}"
    if not good:
        return "Enter at least one recipient."
    return None

# ───────────────────────────── core: config & run ───────────────────────────

def build_config(users: list[dict], n8n: dict | None) -> dict:
    cfg: dict = {}
    if users:
        cfg["wazuh_users"] = [
            {"username": u["username"], "password": u["password"], "role": u["role"]} for u in users
        ]
    if n8n:
        cfg["n8n"] = {
            "enabled": True,
            "min_level": int(n8n["min_level"]),
            "send_test": bool(n8n.get("send_test", True)),
            "smtp": {
                "host": n8n["host"].strip(),
                "port": int(n8n["port"]),
                "user": n8n.get("user", "").strip(),
                "password": n8n.get("password", ""),
                "from": n8n["from"].strip(),
            },
            "recipients": parse_recipients(n8n["recipients"])[0],
        }
    return cfg


def write_config(cfg: dict) -> str:
    """Write cfg to a 0600 file (tmpfs if available). Caller must unlink it."""
    base = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
    fd, path = tempfile.mkstemp(prefix="soc-deploy-", suffix=".json", dir=base)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def find_deploy_script(explicit: str | None = None) -> Path:
    cands = []
    if explicit:
        cands.append(Path(explicit))
    if os.environ.get("SOC_DEPLOY_SH"):
        cands.append(Path(os.environ["SOC_DEPLOY_SH"]))
    here = Path(__file__).resolve().parent
    cands += [here / "deploy-soc-stack.sh", here.parent / "deploy-soc-stack.sh"]
    for c in cands:
        if c.is_file():
            return c
    raise FileNotFoundError("deploy-soc-stack.sh not found next to soc_tui.py (or its parent dir).")


def planned_stages(selected: list[str]) -> list[str]:
    """Mirror the script's stage ordering so the progress list matches reality."""
    sel = set(selected)
    out = []
    if sel & {"wazuh", "hive", "cortex", "n8n"}:
        out.append("prereqs")
    out += [s for s in STAGE_ORDER if s != "prereqs" and s in sel]
    return out


def stage_from_line(line: str) -> str | None:
    """Map a '=== Stage: ... ===' log line to a stage key."""
    if "=== Stage:" not in line:
        return None
    low = line.lower()
    for needle, key in (("extra wazuh users", "users"), ("alert bridge", "bridge"),
                        ("os prerequisites", "prereqs"), ("n8n", "n8n"),
                        ("cortex", "cortex"), ("thehive", "hive"), ("wazuh", "wazuh")):
        if needle in low:
            return key
    return None


def install_argv(script: Path, selected: list[str], cfg_path: str | None, force: bool) -> list[str]:
    argv = ["bash", str(script)]
    if force:
        argv.append("--force")
    argv += ["install", ",".join(selected)]
    if cfg_path:
        argv += ["--config", cfg_path]
    return argv


def host_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "<host-ip>"


def read_wazuh_creds() -> dict:
    """Parse wazuh-passwords.txt -> {'indexer': (user, pw), 'api': (user, pw)} (best effort)."""
    out: dict = {}
    p = STACK_DIR / "wazuh-passwords.txt"
    try:
        text = p.read_text()
    except OSError:
        return out
    def grab(k: str) -> str | None:
        m = re.search(rf"^\s*{k}:\s*'(.*)'\s*$", text, re.M)
        return m.group(1) if m else None
    iu, ip, au, ap = grab("indexer_username"), grab("indexer_password"), grab("api_username"), grab("api_password")
    if ip:
        out["indexer"] = (iu or "admin", ip)
    if ap:
        out["api"] = (au or "wazuh", ap)
    return out

# ───────────────────────────── plain (prompt) mode ──────────────────────────

def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    v = input(f"{prompt}{suffix}: ").strip()
    return v or default


def _yn(prompt: str, default: bool) -> bool:
    d = "Y/n" if default else "y/N"
    v = input(f"{prompt} [{d}]: ").strip().lower()
    return default if not v else v.startswith("y")


def run_plain(script: Path, force: bool) -> int:
    print("\n== SOC lab installer (plain mode) ==\n")
    selected = [k for k, label, default in COMPONENTS if _yn(f"Install {label}?", default)]
    if not selected:
        print("Nothing selected.")
        return 0

    users: list[dict] = []
    if "users" in selected:
        print("\nAdd Wazuh dashboard users (blank username to finish). Roles: admin / analyst / viewer.")
        while True:
            name = _ask("  username")
            if not name:
                break
            err = valid_username(name)
            if err:
                print("   !", err); continue
            role = _ask("  role", "analyst")
            if role not in ROLES:
                print("   ! role must be one of", ", ".join(ROLES)); continue
            pw = getpass.getpass("  password: ")
            err = valid_password(pw)
            if err:
                print("   !", err); continue
            if getpass.getpass("  confirm : ") != pw:
                print("   ! passwords differ"); continue
            users.append({"username": name, "password": pw, "role": role})
            print(f"   + added {name} ({role})")
        if not users:
            selected.remove("users")

    n8n = None
    if "n8n" in selected:
        print("\nn8n email settings")
        prov = _ask("  provider (gmail/smtp)", "gmail").lower()
        host, port = (GMAIL["host"], GMAIL["port"]) if prov.startswith("g") else ("", "587")
        while True:
            host = _ask("  SMTP host", host)
            port = _ask("  SMTP port", port)
            user = _ask("  SMTP username (blank = no auth)")
            password = getpass.getpass("  SMTP password / app password: ") if user else ""
            sender = _ask("  From address", user)
            recips = _ask("  Recipients (comma separated)")
            err = validate_smtp(host, port, sender, recips)
            if err:
                print("   !", err); continue
            break
        print("  Levels:", ", ".join(f"{l}{' ('+LEVEL_HINTS[l]+')' if l in LEVEL_HINTS else ''}" for l in LEVELS))
        while True:
            lvl = _ask("  Email alerts at Wazuh level >=", "10")
            if lvl.isdigit() and 1 <= int(lvl) <= 15:
                break
            print("   ! enter a number 1-15")
        n8n = {"host": host, "port": port, "user": user, "password": password, "from": sender,
               "recipients": recips, "min_level": int(lvl), "send_test": _yn("  Send a test email after install?", True)}

    print("\nSummary:", ", ".join(selected))
    if users:
        print("  users :", ", ".join(f"{u['username']}({u['role']})" for u in users))
    if n8n:
        print(f"  n8n   : {n8n['host']}:{n8n['port']} -> {n8n['recipients']}  (level >= {n8n['min_level']})")
    if not _yn("\nStart install?", True):
        return 0

    cfg = build_config(users, n8n)
    cfg_path = write_config(cfg) if cfg else None
    try:
        return subprocess.call(install_argv(script, selected, cfg_path, force))
    finally:
        if cfg_path:
            try: os.unlink(cfg_path)
            except OSError: pass

# ───────────────────────────── Textual UI ───────────────────────────────────

def run_textual(script: Path, force: bool) -> int:
    import asyncio
    from rich.text import Text
    from textual import on
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.screen import Screen
    from textual.widgets import (Button, Checkbox, DataTable, Footer, Header, Input,
                                 Label, RichLog, Select, SelectionList, Static)

    class State:
        selected: list[str] = []
        users: list[dict] = []
        n8n: dict | None = None
        force: bool = force
        last_rc: int | None = None

    S = State()

    # ── helpers ──
    def err_label(screen: Screen, msg: str) -> None:
        screen.query_one("#err", Label).update(msg)

    class Base(Screen):
        BINDINGS = [("escape", "back", "Back")]

        def action_back(self) -> None:
            if len(self.app.screen_stack) > 2:
                self.app.pop_screen()

    # ── main menu ──
    class MenuScreen(Screen):
        def compose(self) -> ComposeResult:
            yield Header()
            with Vertical(classes="card"):
                yield Label("SOC Lab Deployer", classes="title")
                yield Label("Wazuh + TheHive + Cortex + n8n on Debian 13", classes="muted")
                yield Button("Install / add components", id="install", variant="primary")
                yield Button("Status dashboard", id="status")
                yield Button("Set TheHive API key", id="key")
                yield Button("Quit", id="quit")
            yield Footer()

        @on(Button.Pressed)
        def pressed(self, ev: Button.Pressed) -> None:
            bid = ev.button.id
            if bid == "install":
                self.app.push_screen(ComponentScreen())
            elif bid == "status":
                self.app.push_screen(StatusScreen())
            elif bid == "key":
                self.app.push_screen(KeyScreen())
            elif bid == "quit":
                self.app.exit(0)

    # ── component selection ──
    class ComponentScreen(Base):
        def compose(self) -> ComposeResult:
            yield Header()
            with Vertical(classes="card"):
                yield Label("1. Choose components", classes="title")
                yield SelectionList[str](*[(label, key, default) for key, label, default in COMPONENTS], id="comps")
                yield Checkbox("Force re-run of stages that already completed", value=S.force, id="force")
                yield Label("", id="err", classes="error")
                with Horizontal(classes="row"):
                    yield Button("Back", id="back")
                    yield Button("Next", id="next", variant="primary")
            yield Footer()

        @on(Button.Pressed, "#back")
        def _back(self) -> None:
            self.app.pop_screen()

        @on(Button.Pressed, "#next")
        def _next(self) -> None:
            sel = list(self.query_one("#comps", SelectionList).selected)
            if not sel:
                return err_label(self, "Select at least one component.")
            S.selected = [k for k, _, _ in COMPONENTS if k in sel]
            S.force = self.query_one("#force", Checkbox).value
            self.app.push_screen(next_screen_after("components"))

    # ── users ──
    class UsersScreen(Base):
        def compose(self) -> ComposeResult:
            yield Header()
            with Vertical(classes="card"):
                yield Label("2. Extra Wazuh dashboard users", classes="title")
                yield Label("The built-in 'admin' stays as is. Add more logins below.", classes="muted")
                with Horizontal(classes="row"):
                    yield Input(placeholder="username", id="u_name")
                    yield Input(placeholder="password", password=True, id="u_pw")
                    yield Select([(r, r) for r in ROLES], value="analyst", allow_blank=False, id="u_role")
                    yield Button("Add", id="add", variant="success")
                yield DataTable(id="tbl", cursor_type="row")
                yield Label("", id="err", classes="error")
                with Horizontal(classes="row"):
                    yield Button("Back", id="back")
                    yield Button("Remove selected", id="rm")
                    yield Button("Next", id="next", variant="primary")
            yield Footer()

        def on_mount(self) -> None:
            t = self.query_one("#tbl", DataTable)
            t.add_columns("username", "role", "password")
            for u in S.users:
                t.add_row(u["username"], u["role"], "********", key=u["username"])

        @on(Button.Pressed, "#add")
        def _add(self) -> None:
            name = self.query_one("#u_name", Input).value.strip()
            pw = self.query_one("#u_pw", Input).value
            role = self.query_one("#u_role", Select).value
            msg = valid_username(name) or valid_password(pw)
            if not msg and any(u["username"] == name for u in S.users):
                msg = f"'{name}' is already in the list."
            if msg:
                return err_label(self, msg)
            S.users.append({"username": name, "password": pw, "role": str(role)})
            self.query_one("#tbl", DataTable).add_row(name, str(role), "********", key=name)
            self.query_one("#u_name", Input).value = ""
            self.query_one("#u_pw", Input).value = ""
            err_label(self, "")

        @on(Button.Pressed, "#rm")
        def _rm(self) -> None:
            t = self.query_one("#tbl", DataTable)
            if t.row_count == 0:
                return
            key = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
            S.users[:] = [u for u in S.users if u["username"] != key]
            t.remove_row(key)

        @on(Button.Pressed, "#back")
        def _back(self) -> None:
            self.app.pop_screen()

        @on(Button.Pressed, "#next")
        def _next(self) -> None:
            if not S.users:
                S.selected = [s for s in S.selected if s != "users"]   # nothing to create
            self.app.push_screen(next_screen_after("users"))

    # ── n8n ──
    class N8nScreen(Base):
        def compose(self) -> ComposeResult:
            cur = S.n8n or {}
            yield Header()
            with VerticalScroll(classes="card"):
                yield Label("3. n8n email alerts", classes="title")
                yield Select([("Gmail (App Password)", "gmail"), ("Generic SMTP", "smtp")],
                             value=cur.get("provider", "gmail"), allow_blank=False, id="prov")
                yield Label("", id="hint", classes="muted")
                with Horizontal(classes="row"):
                    yield Input(value=cur.get("host", GMAIL["host"]), placeholder="smtp host", id="host")
                    yield Input(value=cur.get("port", GMAIL["port"]), placeholder="port", id="port", type="integer", max_length=5)
                yield Input(value=cur.get("user", ""), placeholder="SMTP username (usually your email)", id="user")
                yield Input(value=cur.get("password", ""), placeholder="SMTP password / app password", password=True, id="pw")
                yield Input(value=cur.get("from", ""), placeholder="From address (blank = username)", id="from")
                yield Input(value=cur.get("recipients", ""), placeholder="Recipients, comma separated", id="to")
                yield Label("Send email for Wazuh alerts at level >=", classes="muted")
                yield Select([(f"{l}" + (f"  - {LEVEL_HINTS[l]}" if l in LEVEL_HINTS else ""), l) for l in LEVELS],
                             value=cur.get("min_level", 10), allow_blank=False, id="lvl")
                yield Checkbox("Send a test email after install", value=cur.get("send_test", True), id="test")
                yield Label("", id="err", classes="error")
                with Horizontal(classes="row"):
                    yield Button("Back", id="back")
                    yield Button("Next", id="next", variant="primary")
            yield Footer()

        def on_mount(self) -> None:
            self._apply_provider(initial=True)

        def _apply_provider(self, initial: bool = False) -> None:
            prov = self.query_one("#prov", Select).value
            hint = self.query_one("#hint", Label)
            if prov == "gmail":
                hint.update("Gmail needs 2-Step Verification + an App Password (myaccount.google.com/apppasswords). Your normal password will not work.")
                if not initial or not (S.n8n or {}).get("host"):
                    self.query_one("#host", Input).value = GMAIL["host"]
                    self.query_one("#port", Input).value = GMAIL["port"]
            else:
                hint.update("Port 465 = SSL, 587 = STARTTLS. Leave username blank for an open relay.")

        @on(Select.Changed, "#prov")
        def _prov_changed(self) -> None:
            self._apply_provider()

        @on(Button.Pressed, "#back")
        def _back(self) -> None:
            self.app.pop_screen()

        @on(Button.Pressed, "#next")
        def _next(self) -> None:
            g = lambda i: self.query_one(f"#{i}", Input).value
            user = g("user").strip()
            sender = g("from").strip() or user
            msg = validate_smtp(g("host"), g("port"), sender, g("to"))
            if not msg and self.query_one("#prov", Select).value == "gmail" and not (user and g("pw")):
                msg = "Gmail needs your address as username and an App Password."
            if msg:
                return err_label(self, msg)
            S.n8n = {"provider": str(self.query_one("#prov", Select).value),
                     "host": g("host").strip(), "port": g("port").strip(), "user": user,
                     "password": g("pw"), "from": sender, "recipients": g("to"),
                     "min_level": int(self.query_one("#lvl", Select).value),
                     "send_test": self.query_one("#test", Checkbox).value}
            self.app.push_screen(ReviewScreen())

    def next_screen_after(step: str) -> Screen:
        order = [("components", None), ("users", UsersScreen), ("n8n", N8nScreen)]
        started = False
        for name, cls in order:
            if name == step:
                started = True
                continue
            if started and name in S.selected:
                return cls()
        return ReviewScreen()

    # ── review ──
    class ReviewScreen(Base):
        def compose(self) -> ComposeResult:
            yield Header()
            with VerticalScroll(classes="card"):
                yield Label("4. Review", classes="title")
                yield Static(self._summary(), id="summary")
                yield Label("A full install pulls several GB and takes roughly 15-30 minutes.", classes="muted")
                with Horizontal(classes="row"):
                    yield Button("Back", id="back")
                    yield Button("Start install", id="go", variant="success")
            yield Footer()

        def _summary(self) -> str:
            lines = ["Components : " + ", ".join(S.selected) + ("   (force re-run)" if S.force else "")]
            if "users" in S.selected:
                lines.append("Users      : " + ", ".join(f"{u['username']} ({u['role']})" for u in S.users))
            if "n8n" in S.selected and S.n8n:
                n = S.n8n
                lines += [f"n8n SMTP   : {n['host']}:{n['port']}  user={n['user'] or '(none)'}  password=********",
                          f"From       : {n['from']}",
                          f"Recipients : {', '.join(parse_recipients(n['recipients'])[0])}",
                          f"Threshold  : Wazuh level >= {n['min_level']}" + ("   (test email will be sent)" if n["send_test"] else "")]
            return "\n".join(lines)

        @on(Button.Pressed, "#back")
        def _back(self) -> None:
            self.app.pop_screen()

        @on(Button.Pressed, "#go")
        def _go(self) -> None:
            self.app.push_screen(RunScreen())

    # ── live run ──
    class RunScreen(Base):
        BINDINGS = []   # no accidental Esc while installing

        def __init__(self) -> None:
            super().__init__()
            self.stages = planned_stages(S.selected)
            self.state = {s: "pending" for s in self.stages}
            self.proc: asyncio.subprocess.Process | None = None
            self.cfg_path: str | None = None
            self.aborted = False

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal():
                with Vertical(id="side"):
                    yield Label("Progress", classes="title")
                    yield Static("", id="stages")
                    yield Button("Abort", id="abort", variant="error")
                    yield Button("Dashboard", id="dash", disabled=True, variant="primary")
                    yield Button("Quit", id="quit", disabled=True)
                yield RichLog(id="log", highlight=False, markup=False, wrap=True, max_lines=5000)
            yield Footer()

        def on_mount(self) -> None:
            self._render_stages()
            self.run_worker(self._run(), exclusive=True)

        def _render_stages(self) -> None:
            icon = {"pending": "[ ]", "running": "[>]", "done": "[x]", "failed": "[!]"}
            txt = "\n".join(f"{icon[self.state[s]]} {STAGE_LABEL[s]}" for s in self.stages)
            self.query_one("#stages", Static).update(txt)

        def _log(self, line: str) -> None:
            t = Text(line)
            if line.startswith("[") and "ERROR:" in line:
                t.stylize("bold red")
            elif "WARN:" in line:
                t.stylize("yellow")
            elif "=== " in line:
                t.stylize("bold cyan")
            self.query_one("#log", RichLog).write(t)

        def _set(self, stage: str, st: str) -> None:
            if stage in self.state:
                self.state[stage] = st
                self._render_stages()

        async def _run(self) -> None:
            cfg = build_config(S.users if "users" in S.selected else [], S.n8n if "n8n" in S.selected else None)
            self.cfg_path = write_config(cfg) if cfg else None
            argv = install_argv(script, S.selected, self.cfg_path, S.force)
            self._log("$ " + " ".join(a if a != self.cfg_path else "<config>" for a in argv))
            try:
                self.proc = await asyncio.create_subprocess_exec(
                    *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT, start_new_session=True,
                    env={**os.environ, "TERM": "dumb", "NO_COLOR": "1"})
                current: str | None = None
                buf = ""
                assert self.proc.stdout
                while True:
                    chunk = await self.proc.stdout.read(4096)
                    if not chunk:
                        break
                    buf += ANSI_RE.sub("", chunk.decode(errors="replace"))
                    parts = re.split(r"[\r\n]+", buf)
                    buf = parts.pop()
                    for line in parts:
                        if not line.strip():
                            continue
                        self._log(line)
                        st = stage_from_line(line)
                        if st:
                            if current:
                                self._set(current, "done")
                            current = st
                            self._set(st, "running")
                if buf.strip():
                    self._log(buf)
                rc = await self.proc.wait()
            except Exception as e:                      # noqa: BLE001
                self._log(f"ERROR: could not run deploy script: {e}")
                rc = 127
                current = None
            finally:
                if self.cfg_path:
                    try: os.unlink(self.cfg_path)
                    except OSError: pass
            S.last_rc = rc
            if rc == 0:
                for s in self.stages:
                    self.state[s] = "done"
                self._log("== Install finished successfully. Press Dashboard. ==")
            else:
                if current:
                    self.state[current] = "failed"
                self._log("== Install FAILED (exit %s)%s. Scroll up for the error; log: /var/log/soc-stack-install.log =="
                          % (rc, " - aborted" if self.aborted else ""))
            self._render_stages()
            self.query_one("#abort", Button).disabled = True
            self.query_one("#dash", Button).disabled = False
            self.query_one("#quit", Button).disabled = False

        @on(Button.Pressed, "#abort")
        def _abort(self) -> None:
            if self.proc and self.proc.returncode is None:
                self.aborted = True
                try:
                    os.killpg(self.proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

        @on(Button.Pressed, "#dash")
        def _dash(self) -> None:
            self.app.push_screen(StatusScreen())

        @on(Button.Pressed, "#quit")
        def _quit(self) -> None:
            self.app.exit(S.last_rc or 0)

    # ── status dashboard ──
    class StatusScreen(Base):
        BINDINGS = [("escape", "back", "Back"), ("r", "refresh", "Refresh"), ("p", "toggle_pw", "Show/hide passwords")]

        def __init__(self) -> None:
            super().__init__()
            self.reveal = False

        def compose(self) -> ComposeResult:
            yield Header()
            with Vertical(classes="card"):
                yield Label("Status", classes="title")
                yield Static("", id="access")
                yield RichLog(id="out", highlight=False, markup=False, wrap=True)
                with Horizontal(classes="row"):
                    yield Button("Refresh", id="refresh", variant="primary")
                    yield Button("Back", id="back")
            yield Footer()

        def on_mount(self) -> None:
            self.action_refresh()

        def _access_text(self) -> str:
            ip = host_ip()
            creds = read_wazuh_creds()
            def pw(v: str) -> str:
                return v if self.reveal else "******** (press p)"
            lines = [f"Wazuh dashboard : https://{ip}",
                     f"TheHive         : http://{ip}:9000",
                     f"Cortex          : http://{ip}:9001",
                     f"n8n             : http://{ip}:5678"]
            if "indexer" in creds:
                u, p = creds["indexer"]
                lines.append(f"Wazuh login     : {u} / {pw(p)}")
            lines.append(f"Credentials file: {STACK_DIR}/wazuh-passwords.txt")
            return "\n".join(lines)

        def action_toggle_pw(self) -> None:
            self.reveal = not self.reveal
            self.query_one("#access", Static).update(self._access_text())

        def action_refresh(self) -> None:
            self.query_one("#access", Static).update(self._access_text())
            self.query_one("#out", RichLog).clear()
            self.run_worker(self._load(), exclusive=True)

        async def _load(self) -> None:
            log = self.query_one("#out", RichLog)
            try:
                p = await asyncio.create_subprocess_exec(
                    "bash", str(script), "status", stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                out, _ = await p.communicate()
                log.write(Text(ANSI_RE.sub("", out.decode(errors="replace"))))
            except Exception as e:                      # noqa: BLE001
                log.write(Text(f"Could not run status: {e}"))

        @on(Button.Pressed, "#refresh")
        def _r(self) -> None:
            self.action_refresh()

        @on(Button.Pressed, "#back")
        def _b(self) -> None:
            self.app.pop_screen()

    # ── set TheHive key ──
    class KeyScreen(Base):
        def compose(self) -> ComposeResult:
            yield Header()
            with Vertical(classes="card"):
                yield Label("Set TheHive API key", classes="title")
                yield Label("Must belong to an ORG-level user (analyst/org-admin), not admin@thehive.local.", classes="muted")
                yield Input(placeholder="API key", password=True, id="key")
                yield Label("", id="err", classes="error")
                yield RichLog(id="out", highlight=False, markup=False, wrap=True)
                with Horizontal(classes="row"):
                    yield Button("Back", id="back")
                    yield Button("Save", id="save", variant="primary")
            yield Footer()

        @on(Button.Pressed, "#back")
        def _b(self) -> None:
            self.app.pop_screen()

        @on(Button.Pressed, "#save")
        def _s(self) -> None:
            key = self.query_one("#key", Input).value.strip()
            if not key:
                return err_label(self, "Paste the API key first.")
            self.run_worker(self._save(key), exclusive=True)

        async def _save(self, key: str) -> None:
            p = await asyncio.create_subprocess_exec(
                "bash", str(script), "set-hive-key", key, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await p.communicate()
            self.query_one("#out", RichLog).write(Text(ANSI_RE.sub("", out.decode(errors="replace"))))
            err_label(self, "Saved." if p.returncode == 0 else f"Failed (exit {p.returncode}).")

    # ── app ──
    class SocApp(App):
        TITLE = "SOC Lab Deployer"
        CSS = """
        .card { padding: 1 2; margin: 1 2; border: round $primary; height: auto; max-height: 100%; }
        .title { text-style: bold; color: $accent; margin-bottom: 1; }
        .muted { color: $text-muted; margin-bottom: 1; }
        .error { color: $error; height: auto; }
        .row { height: auto; margin-top: 1; }
        .row > * { margin-right: 1; }
        Button { margin-bottom: 1; }
        #side { width: 30; padding: 1; border: round $primary; }
        #log, #out { border: round $surface; height: 1fr; margin: 1; }
        #comps { height: auto; max-height: 12; }
        #tbl { height: 8; margin-top: 1; }
        Input { margin-bottom: 1; }
        """

        def on_mount(self) -> None:
            self.push_screen(MenuScreen())

    rc = SocApp().run()
    return int(rc or 0)

# ───────────────────────────── entrypoint ───────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="TUI for deploy-soc-stack.sh")
    ap.add_argument("--plain", action="store_true", help="prompt-based mode (no Textual needed)")
    ap.add_argument("--force", action="store_true", help="re-run stages already completed")
    ap.add_argument("--deploy-script", help="path to deploy-soc-stack.sh")
    a = ap.parse_args()

    try:
        script = find_deploy_script(a.deploy_script)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if os.geteuid() != 0 and not os.environ.get("SOC_TUI_ALLOW_NONROOT"):
        print("ERROR: run as root (use ./soc-deploy, which handles sudo).", file=sys.stderr)
        return 2

    if a.plain or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return run_plain(script, a.force)
    try:
        import textual  # noqa: F401
    except ImportError:
        print("Textual is not installed - falling back to plain mode.", file=sys.stderr)
        return run_plain(script, a.force)
    return run_textual(script, a.force)


if __name__ == "__main__":
    sys.exit(main())
