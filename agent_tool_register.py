#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent-tool-register: a two-minute inventory for scripts that AI coding agents wrote.

Standard library only. Python 3.9 or later. One file.

You register the scripts people keep running. The tool reads each one (it never runs it) and
flags the five promotion triggers: the moment a personal script needs an owner who can read it.

  1. second_user         two or more people use it regularly        (you declare --user)
  2. sensitive_data      it names paths that match your sensitive globs
  3. acts_on_systems     it imports or calls network, e-mail, database or subprocess code
  4. stored_credentials  key-shaped strings or hard-coded passwords sit in the file
  5. quantitative        its numbers inform a decision              (you declare --quantitative)

Secret values are never printed or stored. Findings record the kind of secret and the line only.

Commands:
  add PATH      register a script (or update it) and scan it
  scan PATH     scan a file or a directory without changing what is registered
  list          one line per registered script
  report        a markdown report for whoever reviews the list

The registry is a JSON file: ./agent-tools.json by default, or --registry / $AGENT_TOOL_REGISTRY.
"""
import argparse
import ast
import datetime as _dt
import fnmatch
import json
import os
import re
import sys

__version__ = "0.1.0"

DEFAULT_REGISTRY = "agent-tools.json"
DEFAULT_SENSITIVE_GLOBS = [
    "*client*", "*customer*", "*payroll*", "*salary*", "*/hr/*",
    "*.pem", "*.key", "*id_rsa*", "*/.ssh/*", "*/.aws/*", "*.env",
]
TRIGGERS = ["second_user", "sensitive_data", "acts_on_systems", "stored_credentials", "quantitative"]
TRIGGER_TEXT = {
    "second_user": "a second regular user",
    "sensitive_data": "touches sensitive data paths",
    "acts_on_systems": "acts on other systems",
    "stored_credentials": "stored credentials",
    "quantitative": "produces quantitative estimates",
}

# Top-level modules whose import means "this script can reach another system".
SYSTEM_MODULES = {
    "socket": "network", "ssl": "network", "http": "network", "urllib": "network",
    "requests": "network", "httpx": "network", "aiohttp": "network", "urllib3": "network",
    "websocket": "network", "websockets": "network", "ftplib": "network", "paramiko": "network",
    "grpc": "network", "boto3": "cloud", "botocore": "cloud", "google": "cloud", "azure": "cloud",
    "openai": "cloud", "anthropic": "cloud", "slack_sdk": "network",
    "smtplib": "email", "imaplib": "email", "poplib": "email",
    "subprocess": "subprocess", "pty": "subprocess",
    "psycopg2": "database", "psycopg": "database", "pymysql": "database", "pyodbc": "database",
    "sqlalchemy": "database", "pymongo": "database", "redis": "database", "cx_Oracle": "database",
    "webbrowser": "browser",
}
# Calls that act outside the script even though their module looks harmless.
SYSTEM_CALLS = {
    "os.system": "subprocess", "os.popen": "subprocess", "os.spawnl": "subprocess",
    "os.spawnv": "subprocess", "os.execv": "subprocess", "os.execvp": "subprocess",
    "os.startfile": "subprocess", "urllib.request.urlopen": "network",
}
# Imports that suggest numbers are being estimated. A hint only, never a trigger on its own.
QUANT_HINT_MODULES = {"numpy", "pandas", "scipy", "statsmodels", "sklearn", "torch", "prophet"}

SECRET_PATTERNS = [
    ("openai-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("aws access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
SECRET_NAME = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)$", re.I)
TEXT_NETWORK = re.compile(r"\b(curl|wget|ssh|scp|rsync|sendmail|nc|fetch\(|axios|XMLHttpRequest|Invoke-WebRequest)\b")
SCRIPT_EXTS = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".ts", ".rb", ".ps1", ".pl"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox"}


# ---------------------------------------------------------------- scanning

def _dotted(node):
    """Return 'a.b.c' for Name/Attribute chains, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _secret_hits(text):
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, pat in SECRET_PATTERNS:
            if pat.search(line):
                hits.append({"kind": kind, "line": lineno})
    return hits


def _looks_like_path(s):
    """Paths and file names only, so log messages that mention 'client' do not count."""
    return "/" in s or "\\" in s or bool(re.match(r"^[~\w.-]+\.[A-Za-z0-9]{1,6}$", s))


def _path_hits(strings, globs):
    hits = []
    for lineno, s in strings:
        if not s or len(s) > 400 or "\n" in s or not _looks_like_path(s):
            continue
        low = s.replace("\\", "/").lower()
        for g in globs:
            if fnmatch.fnmatch(low, g.lower()) or fnmatch.fnmatch(os.path.basename(low), g.lower()):
                hits.append({"glob": g, "line": lineno, "value": s})
                break
    return hits


def scan_python(text, globs):
    """Static scan of Python source. Never executes it."""
    out = {"systems": [], "secrets": _secret_hits(text), "paths": [], "quant_hints": [], "notes": []}
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        out["notes"].append("could not parse as Python (line %s); used text checks only" % e.lineno)
        return _scan_text_fallback(text, globs, out)

    aliases = {}            # local name -> full dotted module path
    strings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                _note_module(a.name, node.lineno, out)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            _note_module(node.module, node.lineno, out)
            for a in node.names:
                aliases[a.asname or a.name] = node.module + "." + a.name
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append((getattr(node, "lineno", 0), node.value))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            _note_secret_assignment(node, out)
        elif isinstance(node, ast.keyword) and node.arg and SECRET_NAME.search(node.arg):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value:
                out["secrets"].append({"kind": "hard-coded %s argument" % node.arg, "line": node.value.lineno})

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if not name:
                continue
            head, _, rest = name.partition(".")
            full = aliases.get(head, head) + ("." + rest if rest else "")
            if full in SYSTEM_CALLS:
                out["systems"].append({"kind": SYSTEM_CALLS[full], "what": full + "()", "line": node.lineno})

    out["paths"] = _path_hits(strings, globs)
    out["systems"] = _dedupe(out["systems"], ("kind", "what"))
    out["secrets"] = _dedupe(out["secrets"], ("kind", "line"))
    return out


def _note_module(module, lineno, out):
    top = module.split(".")[0]
    if top in SYSTEM_MODULES:
        out["systems"].append({"kind": SYSTEM_MODULES[top], "what": "import " + module, "line": lineno})
    if top in QUANT_HINT_MODULES:
        out["quant_hints"].append({"what": "import " + module, "line": lineno})


def _note_secret_assignment(node, out):
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    value = node.value
    if not (isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 4):
        return
    for t in targets:
        name = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else None)
        if name and SECRET_NAME.search(name):
            out["secrets"].append({"kind": "hard-coded %s" % name, "line": node.lineno})


def _scan_text_fallback(text, globs, out):
    for lineno, line in enumerate(text.splitlines(), 1):
        m = TEXT_NETWORK.search(line)
        if m:
            out["systems"].append({"kind": "network", "what": m.group(1).rstrip("("), "line": lineno})
    strings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for q in re.findall(r"""["']([^"'\n]{1,400})["']""", line):
            strings.append((lineno, q))
        for tok in re.findall(r"""[^\s"'=@<>|;,()]+""", line):
            if "/" in tok or "\\" in tok or "." in tok:
                strings.append((lineno, tok))
    out["paths"] = _path_hits(strings, globs)
    out["systems"] = _dedupe(out["systems"], ("kind", "what"))
    return out


def _dedupe(items, keys):
    seen, res = set(), []
    for it in items:
        k = tuple(it.get(x) for x in keys)
        if k not in seen:
            seen.add(k)
            res.append(it)
    return res


def scan_file(path, globs):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return {"systems": [], "secrets": [], "paths": [], "quant_hints": [], "notes": ["unreadable: %s" % e.strerror]}
    if path.endswith(".py"):
        return scan_python(text, globs)
    out = {"systems": [], "secrets": _secret_hits(text), "paths": [], "quant_hints": [],
           "notes": ["not Python: text checks only"]}
    return _scan_text_fallback(text, globs, out)


def iter_scripts(path):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            if os.path.splitext(f)[1] in SCRIPT_EXTS:
                yield os.path.join(root, f)


def triggers_for(entry):
    f = entry.get("findings", {})
    hit = []
    if len(set(entry.get("users", []))) >= 2:
        hit.append("second_user")
    if f.get("paths"):
        hit.append("sensitive_data")
    if f.get("systems"):
        hit.append("acts_on_systems")
    if f.get("secrets"):
        hit.append("stored_credentials")
    if entry.get("quantitative"):
        hit.append("quantitative")
    return hit


def status_for(entry):
    hit = triggers_for(entry)
    if not hit:
        return "personal"
    review = entry.get("review")
    if review and set(hit) <= set(review.get("triggers", [])):
        return "reviewed"
    return "needs review"


# ---------------------------------------------------------------- registry

def load(path):
    if not os.path.exists(path):
        return {"version": 1, "settings": {"sensitive_globs": list(DEFAULT_SENSITIVE_GLOBS)}, "tools": {}}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.setdefault("settings", {}).setdefault("sensitive_globs", list(DEFAULT_SENSITIVE_GLOBS))
    data.setdefault("tools", {})
    return data


def save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def _today():
    return _dt.date.today().isoformat()


def _public_findings(f):
    """Findings as stored and printed: path matches keep the path, secrets keep kind and line only."""
    return {
        "systems": f["systems"], "secrets": [{"kind": s["kind"], "line": s["line"]} for s in f["secrets"]],
        "paths": f["paths"], "quant_hints": f["quant_hints"], "notes": f["notes"],
    }


# ---------------------------------------------------------------- commands

def cmd_add(args, reg):
    globs = reg["settings"]["sensitive_globs"]
    for g in args.sensitive_glob or []:
        if g not in globs:
            globs.append(g)
    path = os.path.abspath(args.path)
    if not os.path.isfile(path):
        raise SystemExit("error: %s is not a file" % args.path)
    name = args.name or os.path.splitext(os.path.basename(path))[0]
    entry = reg["tools"].get(name, {"added": _today(), "users": []})
    entry["path"] = path
    if args.owner:
        entry["owner"] = args.owner
    if args.purpose:
        entry["purpose"] = args.purpose
    users = list(entry.get("users", []))
    for u in ([args.owner] if args.owner else []) + (args.user or []):
        if u and u not in users:
            users.append(u)
    entry["users"] = users
    if args.quantitative:
        entry["quantitative"] = True
    if args.not_quantitative:
        entry["quantitative"] = False
    entry["findings"] = _public_findings(scan_file(path, globs))
    entry["last_scan"] = _today()
    if args.reviewed_by:
        entry["review"] = {"by": args.reviewed_by, "date": _today(), "triggers": triggers_for(entry)}
    reg["tools"][name] = entry
    hit = triggers_for(entry)
    print("%s: %s" % (name, status_for(entry)))
    for t in hit:
        print("  trigger: %s" % TRIGGER_TEXT[t])
    if entry["findings"]["quant_hints"] and not entry.get("quantitative"):
        print("  hint: imports numeric libraries; if people act on its numbers, re-run add with --quantitative")
    return 0


def cmd_scan(args, reg):
    globs = list(reg["settings"]["sensitive_globs"]) + list(args.sensitive_glob or [])
    by_path = {e["path"]: n for n, e in reg["tools"].items()}
    results, any_trigger = [], False
    for p in iter_scripts(args.path):
        ap = os.path.abspath(p)
        f = _public_findings(scan_file(ap, globs))
        name = by_path.get(ap)
        entry = dict(reg["tools"][name]) if name else {"users": []}
        entry["findings"] = f
        hit = triggers_for(entry)
        any_trigger = any_trigger or bool(hit)
        results.append({"file": p, "registered_as": name, "triggers": hit, "findings": f})
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            label = r["registered_as"] or "not registered"
            print("%s  [%s]" % (r["file"], label))
            if not r["triggers"]:
                print("  no triggers found")
            for t in r["triggers"]:
                print("  trigger: %s" % TRIGGER_TEXT[t])
            for s in r["findings"]["systems"]:
                print("    line %d: %s (%s)" % (s["line"], s["what"], s["kind"]))
            for s in r["findings"]["paths"]:
                print("    line %d: path matches %s" % (s["line"], s["glob"]))
            for s in r["findings"]["secrets"]:
                print("    line %d: %s (value not shown)" % (s["line"], s["kind"]))
            for n in r["findings"]["notes"]:
                print("    note: %s" % n)
            if r["findings"]["quant_hints"] and "quantitative" not in r["triggers"]:
                print("    hint: imports numeric libraries; declare with add --quantitative if people act on its numbers")
        print("%d file(s) scanned, %d with triggers" % (len(results), sum(1 for r in results if r["triggers"])))
    return 2 if (args.fail_on_trigger and any_trigger) else 0


def cmd_list(args, reg):
    if not reg["tools"]:
        print("registry is empty: add a script with  agent_tool_register.py add PATH --owner NAME")
        return 0
    w = max(len(n) for n in reg["tools"])
    for name in sorted(reg["tools"]):
        e = reg["tools"][name]
        hit = triggers_for(e)
        print("%-*s  %-12s  %-14s  %s" % (w, name, status_for(e), e.get("owner", "-"),
                                          ", ".join(hit) if hit else "-"))
    return 0


def render_report(reg):
    tools = reg["tools"]
    rows = sorted(tools.items(), key=lambda kv: ({"needs review": 0, "reviewed": 1, "personal": 2}[status_for(kv[1])], kv[0]))
    counts = {"needs review": 0, "reviewed": 0, "personal": 0}
    for _, e in rows:
        counts[status_for(e)] += 1
    out = ["# Agent-built tools: promotion report", "",
           "Generated %s by agent-tool-register %s. Static scan only: the scripts were read, not run." % (_today(), __version__), "",
           "%d registered · %d need review · %d reviewed · %d personal" % (len(rows), counts["needs review"], counts["reviewed"], counts["personal"]), "",
           "| Tool | Status | Owner | Users | Triggers |", "|---|---|---|---|---|"]
    for name, e in rows:
        hit = triggers_for(e)
        out.append("| %s | %s | %s | %d | %s |" % (name, status_for(e), e.get("owner", "-"), len(set(e.get("users", []))),
                                                   ", ".join(TRIGGER_TEXT[t] for t in hit) if hit else "-"))
    for name, e in rows:
        if status_for(e) == "personal":
            continue
        f = e.get("findings", {})
        out += ["", "## %s" % name, "",
                "- Path: `%s`" % e.get("path", "?"),
                "- Purpose: %s" % e.get("purpose", "(not given)"),
                "- Users: %s" % (", ".join(e.get("users", [])) or "(none declared)"),
                "- Last scan: %s" % e.get("last_scan", "?")]
        if e.get("review"):
            out.append("- Reviewed by %s on %s for: %s" % (e["review"]["by"], e["review"]["date"], ", ".join(e["review"]["triggers"]) or "-"))
        for s in f.get("systems", []):
            out.append("- Line %d: `%s` (%s)" % (s["line"], s["what"], s["kind"]))
        for s in f.get("paths", []):
            out.append("- Line %d: path matches `%s`" % (s["line"], s["glob"]))
        for s in f.get("secrets", []):
            out.append("- Line %d: %s (value not shown)" % (s["line"], s["kind"]))
        if e.get("quantitative"):
            out.append("- Declared: its numbers inform decisions")
        for n in f.get("notes", []):
            out.append("- Note: %s" % n)
    out += ["", "Sensitive globs in use: %s" % ", ".join("`%s`" % g for g in reg["settings"]["sensitive_globs"]), ""]
    return "\n".join(out)


def cmd_report(args, reg):
    text = render_report(reg)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("wrote %s" % args.out)
    else:
        print(text)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="agent_tool_register.py", description="Register agent-built scripts and flag promotion triggers.")
    p.add_argument("--registry", default=os.environ.get("AGENT_TOOL_REGISTRY", DEFAULT_REGISTRY), help="JSON registry file (default: %(default)s)")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    a = sub.add_parser("add", help="register or update a script, then scan it")
    a.add_argument("path")
    a.add_argument("--name", help="short name (default: file name without extension)")
    a.add_argument("--owner", help="the person who answers for it; also counted as a user")
    a.add_argument("--purpose", help="one line on what it does")
    a.add_argument("--user", action="append", help="someone who runs it regularly (repeatable)")
    a.add_argument("--quantitative", action="store_true", help="its numbers inform a decision")
    a.add_argument("--not-quantitative", action="store_true", help="clear the quantitative flag")
    a.add_argument("--sensitive-glob", action="append", help="add a sensitive path glob to the registry (repeatable)")
    a.add_argument("--reviewed-by", help="record a review covering the triggers present now")
    a.set_defaults(func=cmd_add, writes=True)

    s = sub.add_parser("scan", help="scan a file or directory; changes nothing")
    s.add_argument("path")
    s.add_argument("--sensitive-glob", action="append", help="extra glob for this scan only (repeatable)")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.add_argument("--fail-on-trigger", action="store_true", help="exit 2 if any file has a trigger (for CI)")
    s.set_defaults(func=cmd_scan, writes=False)

    l = sub.add_parser("list", help="one line per registered script")
    l.set_defaults(func=cmd_list, writes=False)

    r = sub.add_parser("report", help="markdown report for reviewers")
    r.add_argument("--out", help="write to a file instead of stdout")
    r.set_defaults(func=cmd_report, writes=False)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    reg = load(args.registry)
    code = args.func(args, reg)
    if args.writes:
        save(args.registry, reg)
    return code


if __name__ == "__main__":
    sys.exit(main())
