# Dynamic-analysis tooling

Frida hooks, drivers and lab helpers used to observe the FalconBridge chain in an isolated VM
(see the [report](../README.md), sections 3.9 and 4).

> **Run this only inside a disposable, snapshotted VM with a host-only network.** Several scripts execute or
> instrument live malware, and `frida_hooks.js` can actively change the sample's behaviour (anti-debug and
> anti-VM neutralisation, MessageBox auto-dismiss). **No malware sample is included in this repository.**

The files are cleaned-up, translated editions of the scripts used during the analysis; they are not byte-identical
to the versions that produced the logs in the report. Paths such as `C:\sandbox\dumps` are conventions of the lab
VM: change them to suit yours (the directory must exist and be writable by the instrumented process).

## Requirements

- Windows 10/11 x64 guest VM, Python 3, `pip install frida-tools` (tested with Frida 17.x; a compatibility shim in
  `frida_hooks.js` also covers Frida 16).
- Optional: Sysinternals (Procmon, Autoruns), Wireshark/npcap (`dumpcap`), FakeNet-NG.

## Files

| File | Purpose |
|---|---|
| `run_frida.py` | Spawns a target under Frida with `frida_hooks.js`, follows child processes (child gating), writes `frida.log` and `dumps\`. |
| `frida_hooks.js` | Broad instrumentation: dynamic API resolution, injection primitives, sockets/DNS/WinHTTP, registry and file writes, crypto, named pipes, certificate stores, windows, exits; optional anti-debug / anti-VM neutralisation. |
| `attach_frida.py` | Attaches to an existing PID (for example `explorer.exe`), loads one script, logs messages to a file. |
| `spawn_frida.py` | Spawns an executable suspended, loads one script, resumes it, logs, detaches cleanly. |
| `inj.js` | Light `ntdll`-only trace of cross-process actions (`NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, ...). Saves remote-written buffers. Used for run 6. |
| `bodycap.js` | Forces `WinHttpSendRequest` / `WinHttpWriteData` to succeed in a network-less VM so that the code writes its body, and saves the buffers. Used for run 7. |
| `comp.js` | Captures buffers before/after `RtlCompressBuffer` / `RtlDecompressBuffer`, lightly logs WinHTTP. Used for run 7. |
| `memdump.js` | Detects new private executable ranges in a process, waits, and dumps them. Used for run 8. |
| `tlscheck.js` | Logs the TLS-related options and certificate/signature calls (pinning check). Used for run 9. |
| `resolve.js` | Lists functions/DLLs resolved by code located outside any loaded module (injected code). Used for run 10. |
| `smbios_vm.js` | Experiment: puts a "VMware" string back into the SMBIOS table returned by `GetSystemFirmwareTable`. |
| `guest_prep.ps1` | `-Phase pre` / `post`: starts/stops Procmon and dumpcap, takes Autoruns snapshots and diffs them, lists non-Microsoft scheduled tasks. |
| `fakenet_FalconBridge.ini` | FakeNet-NG configuration for the isolated phase (DNS sinkhole, raw/HTTP/HTTPS listeners). |

## Typical workflow

```text
[host]  Verify: VM network is host-only, CLEAN snapshot taken.
[VM]    Copy the loader to C:\sandbox\payload.exe
[VM]    powershell -ExecutionPolicy Bypass -File guest_prep.ps1 -Phase pre
[VM]    fakenet.exe -c fakenet_FalconBridge.ini            (optional)
[VM]    python run_frida.py C:\sandbox\payload.exe          (Ctrl+C when activity settles)
[VM]    powershell -ExecutionPolicy Bypass -File guest_prep.ps1 -Phase post
[VM]    Collect C:\sandbox\capture\*, frida.log, dumps\*
[host]  Restore the CLEAN snapshot.
```

Lessons from the analysis that shaped these scripts:

- Heavy hook sets can crash the Go loader (a Go panic inside `syscall.Call`). Prefer the small single-purpose
  scripts, and attach them to `explorer.exe` rather than the loader when observing the injected code.
- The injected code only writes its HTTP body if the send appears to succeed, hence `bodycap.js`.
- The injection was captured by hooking `ntdll` only (`inj.js`) in `dexter.exe`, which avoids touching the loader.
- The WinHTTP `port` argument is a 16-bit value; the upper bits read by a 32-bit hook are garbage (we logged
  19,988,923 for port 443).

## Safety checklist

- [ ] Disposable VM, CLEAN snapshot taken **before** detonation.
- [ ] Host-only network (or a filtered, logged gateway if you must reach the Internet). Do not let the sample
      reach its real infrastructure unless you have decided to.
- [ ] No real data or credentials in the VM, no writable shared folder during detonation.
- [ ] Restore the snapshot after **every** run.
- [ ] Treat dumps as live malware (do not double-click).
