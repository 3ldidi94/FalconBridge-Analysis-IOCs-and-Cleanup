"""Spawns an executable suspended, loads a Frida script, resumes it, logs, and detaches cleanly.
Usage: python spawn_frida.py <exe> <script.js> <log_path> [<seconds>]
"""
import sys, time, frida

exe, script_path, log_path = sys.argv[1], sys.argv[2], sys.argv[3]
duration = int(sys.argv[4]) if len(sys.argv) > 4 else 40
logf = open(log_path, "a", encoding="utf-8", buffering=1)
alive = {"v": True}

def on_message(msg, data):
    logf.write("[msg] " + str(msg) + "\n")

def on_console(*args):
    try: logf.write(str(args[-1]) + "\n")
    except Exception as e: logf.write("[driver-error] " + repr(e) + "\n")

def on_detached(reason, *rest):
    logf.write("[driver] detached: " + str(reason) + "\n")
    alive["v"] = False

pid = frida.spawn([exe])
logf.write("[driver] spawned pid=%d\n" % pid)
session = frida.attach(pid)
session.on("detached", on_detached)
with open(script_path, "r", encoding="utf-8") as f:
    script = session.create_script(f.read(), runtime="qjs")
script.on("message", on_message)
try: script.set_log_handler(on_console)
except Exception: pass
script.load()
logf.write("[driver] script loaded, resuming at %s\n" % time.strftime("%H:%M:%S"))
frida.resume(pid)
end = time.time() + duration
while time.time() < end and alive["v"]:
    time.sleep(0.2)
logf.write("[driver] end at %s alive=%s\n" % (time.strftime("%H:%M:%S"), alive["v"]))
if alive["v"]:
    try: script.unload()
    except Exception: pass
    try: session.detach()
    except Exception: pass
logf.close()
