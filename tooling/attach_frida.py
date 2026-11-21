"""Attaches Frida to a PID, loads a script, writes all messages to a log file, sleeps.
Usage: python attach_frida.py <pid> <script.js> <log_path> [<seconds>]
"""
import sys, time, frida, os

pid = int(sys.argv[1])
script_path = sys.argv[2]
log_path = sys.argv[3]
duration = int(sys.argv[4]) if len(sys.argv) > 4 else 300

logf = open(log_path, "a", encoding="utf-8", buffering=1)

def on_message(msg, data):
    try:
        if msg.get("type") == "send":
            logf.write(str(msg.get("payload")) + "\n")
        elif msg.get("type") == "error":
            logf.write("[FRIDA-ERROR] " + str(msg.get("description")) + "\n")
            if msg.get("stack"):
                logf.write(msg["stack"] + "\n")
    except Exception as e:
        logf.write("[driver-error] " + repr(e) + "\n")

# Redirect console.log inside Frida to our logf via frida's own mechanism
def on_console(*args):
    # Frida calls handler(level, text); tolerate any arity.
    try:
        logf.write(str(args[-1]) + "\n")
    except Exception as e:
        logf.write("[driver-error] " + repr(e) + "\n")

print(f"[attach] pid={pid} script={script_path} log={log_path} duration={duration}", flush=True)
session = frida.attach(pid)
with open(script_path, "r", encoding="utf-8") as f:
    code = f.read()
script = session.create_script(code, runtime="qjs")
script.on("message", on_message)
# Attach console.log listener (Frida 16+)
try:
    script.set_log_handler(on_console)
except Exception:
    pass
script.load()
print(f"[attach] script loaded, sleeping {duration}s", flush=True)
try:
    time.sleep(duration)
finally:
    print("[attach] unloading", flush=True)
    try: script.unload()
    except Exception: pass
    try: session.detach()
    except Exception: pass
    logf.close()
