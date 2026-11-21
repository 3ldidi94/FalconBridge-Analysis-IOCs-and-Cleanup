#!/usr/bin/env python3
"""
run_frida.py - launches the sample under Frida and follows child processes.

Useful here because the loader may create/inject a child process (CreateProcess suspended +
SetThreadContext/ResumeThread). Child gating instruments the child BEFORE it runs and lets the
injected payload be dumped.

Requirements (inside the guest VM):
    pip install frida-tools
    (Frida must match the architecture: x64 here.)

Usage:
    python run_frida.py C:\\sandbox\\payload.exe
    python run_frida.py C:\\sandbox\\payload.exe --args foo bar

Output:
    .\frida.log            timestamped log of every hook
    .\dumps\*.bin          injected payloads and captured network traffic
"""
import frida, sys, os, argparse, datetime

ap = argparse.ArgumentParser()
ap.add_argument("target", help="path to the malicious executable (renamed to .exe)")
ap.add_argument("--args", nargs="*", default=[], help="arguments passed to the sample")
ap.add_argument("--script", default=os.path.join(os.path.dirname(__file__), "frida_hooks.js"))
ap.add_argument("--timeout", type=int, default=0, help="kill after N seconds (0 = unlimited)")
args = ap.parse_args()

os.makedirs("dumps", exist_ok=True)
logf = open("frida.log", "a", encoding="utf-8")
def emit(line):
    print(line)
    logf.write(line + "\n"); logf.flush()

with open(args.script, "r", encoding="utf-8") as f:
    SRC = f.read()

device = frida.get_local_device()
sessions = {}

def on_message(message, data):
    if message["type"] == "send":
        emit(message["payload"])
    elif message["type"] == "error":
        emit("[FRIDA-ERROR] " + message.get("stack", str(message)))

def on_console(level, text):
    emit(text)

def inject(pid, label):
    try:
        session = device.attach(pid)
    except Exception as e:
        emit(f"[DRIVER] attach {pid} failed: {e}"); return None
    try:
        session.enable_child_gating()
    except Exception:
        pass
    script = session.create_script(SRC)
    script.on("message", on_message)
    # redirect the script's console.log to our log
    try:
        script.set_log_handler(on_console)
    except Exception:
        pass
    script.load()
    sessions[pid] = (session, script)
    emit(f"[DRIVER] instrumented {label} pid={pid}")
    return session

def on_child_added(child):
    emit(f"[DRIVER] >>> child detected pid={child.pid} ppid={child.parent_pid} path={getattr(child,'path',None)}")
    inject(child.pid, "CHILD")
    try:
        device.resume(child.pid)
    except Exception as e:
        emit(f"[DRIVER] resume child {child.pid} failed: {e}")

device.on("child-added", on_child_added)

emit("=" * 70)
emit(f"[DRIVER] {datetime.datetime.now().isoformat()}  target={args.target}")
emit("=" * 70)

pid = device.spawn([args.target] + args.args)
inject(pid, "PARENT")
device.resume(pid)
emit(f"[DRIVER] PARENT pid={pid} launched. Press Ctrl+C to stop.")

import time
try:
    if args.timeout > 0:
        time.sleep(args.timeout)
        emit(f"[DRIVER] timeout {args.timeout}s reached, stopping.")
    else:
        sys.stdin.read()
except KeyboardInterrupt:
    pass
finally:
    for pid, (s, sc) in list(sessions.items()):
        try: device.kill(pid)
        except Exception: pass
    emit("[DRIVER] done.")
    logf.close()
