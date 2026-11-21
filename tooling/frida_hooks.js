/*
 * frida_hooks.js - general-purpose Frida instrumentation used during the FalconBridge analysis.
 * Targets: the Go loader (payload.exe), the native injector (dexter.exe) and, when attached,
 * the injected code running inside explorer.exe.
 *
 * Coverage: dynamic API resolution, process injection, sockets / DNS / WinHTTP, registry and
 * file writes, crypto, named pipes, certificate stores, window creation, process exit, and
 * optional anti-debug / anti-VM neutralisation.
 *
 * Buffers written to other processes and network payloads are dumped to DUMPDIR.
 * Usage: through run_frida.py (spawn + child gating), or attach_frida.py / spawn_frida.py.
 *
 * WARNING: this script actively modifies behaviour in a few places (see the "ANTI-DEBUG /
 * ANTI-VM" and "MESSAGEBOX" sections). Run it only inside an isolated, snapshotted VM.
 * Heavy hook sets can crash the Go loader (observed: panic inside syscall.Call); the smaller
 * single-purpose scripts in this folder (inj.js, comp.js, ...) exist for that reason.
 */

'use strict';

// ------------------------------------------------------------------ Frida 17 compat shim
// Frida >= 17 removed Module.findExportByName; rebuild it so the rest of the script runs
// unchanged on Frida 16 and 17+.
if (typeof Module.findExportByName !== 'function') {
  Module.findExportByName = function (mod, fn) {
    try {
      if (mod === null || mod === undefined) {
        if (typeof Module.getGlobalExportByName === 'function') {
          try { return Module.getGlobalExportByName(fn); } catch (e) {}
        }
        const mods = Process.enumerateModules();
        for (let i = 0; i < mods.length; i++) {
          try { const a = mods[i].findExportByName(fn); if (a) return a; } catch (e) {}
        }
        return null;
      }
      const m = Process.findModuleByName(mod);
      return m ? m.findExportByName(fn) : null;
    } catch (e) { return null; }
  };
}

// ------------------------------------------------------------------ utils
const PID = Process.id;
function ts() { return new Date().toISOString().substr(11, 12); }
function log(tag, msg) { console.log(`[${ts()}][pid:${PID}][${tag}] ${msg}`); }
function backtrace(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, 4)
      .map(DebugSymbol.fromAddress).map(s => s.toString()).join(' <- ');
  } catch (e) { return '(bt n/a)'; }
}

// Absolute path on purpose: explorer.exe has C:\Windows as its working directory (read-only).
let DUMPDIR = 'C:\\sandbox\\dumps';
function dumpBytes(name, ptr, len) {
  if (len <= 0 || len > 8 * 1024 * 1024) len = Math.min(Math.max(len, 0), 8 * 1024 * 1024);
  try {
    const bytes = ptr.readByteArray(len);
    const fn = `${DUMPDIR}/${PID}_${name}_${Date.now()}.bin`;
    const f = new File(fn, 'wb'); f.write(bytes); f.close();
    log('DUMP', `${len} bytes -> ${fn}`);
    log('DUMP', hexPreview(ptr, Math.min(len, 64)));
  } catch (e) { log('DUMP', 'failed: ' + e); }
}
function hexPreview(ptr, len) {
  try { return hexdump(ptr, { length: len, ansi: false, header: false }).split('\n')[0]; }
  catch (e) { return '(hex n/a)'; }
}

// sockaddr -> "ip:port"
function parseSockaddr(p) {
  try {
    const fam = p.readU16();
    if (fam === 2) { // AF_INET
      const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
      const ip = [0, 1, 2, 3].map(i => p.add(4 + i).readU8()).join('.');
      return `${ip}:${port} (IPv4)`;
    }
    if (fam === 23) { // AF_INET6
      const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
      let seg = [];
      for (let i = 0; i < 8; i++) seg.push(((p.add(8 + i * 2).readU8() << 8) | p.add(8 + i * 2 + 1).readU8()).toString(16));
      return `[${seg.join(':')}]:${port} (IPv6)`;
    }
    return `family=${fam}`;
  } catch (e) { return '(sockaddr n/a)'; }
}

// ------------------------------------------------------------------ hook registry (lazy)
// Hooks on exports of DLLs that are not loaded yet are queued and retried after each LdrLoadDll.
const pending = [];   // {mod, fn, on}
const installed = {};
function hook(mod, fn, on) { pending.push({ mod, fn, on }); flush(); }
function flush() {
  for (let i = pending.length - 1; i >= 0; i--) {
    const h = pending[i];
    const key = `${h.mod}!${h.fn}`;
    if (installed[key]) { pending.splice(i, 1); continue; }
    let addr = null;
    try { addr = Module.findExportByName(h.mod, h.fn); } catch (e) {}
    if (!addr) { try { addr = Module.findExportByName(null, h.fn); } catch (e) {} }
    if (addr) {
      try { Interceptor.attach(addr, h.on); installed[key] = true; pending.splice(i, 1); log('HOOK', `+ ${key} @${addr}`); }
      catch (e) { log('HOOK', `failed ${key}: ${e}`); pending.splice(i, 1); }
    }
  }
}
['LdrLoadDll'].forEach(fn => {
  const a = Module.findExportByName('ntdll.dll', fn);
  if (a) Interceptor.attach(a, { onLeave: function () { flush(); } });
});

// ================================================================== GetProcAddress
hook('kernel32.dll', 'GetProcAddress', {
  onEnter(args) { this.mod = args[0]; this.name = args[1]; },
  onLeave(ret) {
    try {
      let n = '';
      if (!this.name.isNull() && this.name.compare(ptr(0x10000)) > 0) n = this.name.readUtf8String();
      else n = 'ord#' + this.name.toInt32();
      if (n && !ret.isNull()) log('RESOLVE', `GetProcAddress(${n}) -> ${ret}`);
    } catch (e) {}
  }
});

// ================================================================== INJECTION
hook('kernel32.dll', 'CreateProcessW', {
  onEnter(a) {
    this.app = a[0].isNull() ? '' : a[0].readUtf16String();
    this.cmd = a[1].isNull() ? '' : a[1].readUtf16String();
    this.flags = a[5].toInt32();
    const SUSPENDED = 0x4;
    log('INJECT', `CreateProcessW app="${this.app}" cmd="${this.cmd}" flags=0x${this.flags.toString(16)}${(this.flags & SUSPENDED) ? ' [SUSPENDED]' : ''}`);
  }
});
hook('kernel32.dll', 'CreateProcessAsUserW', {
  onEnter(a) { log('INJECT', `CreateProcessAsUserW cmd="${a[2].isNull() ? '' : a[2].readUtf16String()}"`); }
});
hook('kernel32.dll', 'VirtualAllocEx', {
  onEnter(a) { this.sz = a[2].toInt32(); this.prot = a[3].toInt32(); },
  onLeave(r) { log('INJECT', `VirtualAllocEx size=${this.sz} prot=0x${this.prot.toString(16)} -> ${r}`); }
});
hook('kernel32.dll', 'WriteProcessMemory', {
  onEnter(a) {
    const buf = a[2], len = a[3].toInt32();
    log('INJECT', `WriteProcessMemory hProc=${a[0]} dst=${a[1]} len=${len}  ${hexPreview(buf, Math.min(len, 32))}`);
    dumpBytes('injected', buf, len);   // injected payload
  }
});
['SetThreadContext', 'ResumeThread', 'NtResumeThread', 'NtWriteVirtualMemory',
 'NtMapViewOfSection', 'NtUnmapViewOfSection', 'NtCreateThreadEx', 'QueueUserAPC'].forEach(fn => {
  const mod = fn.startsWith('Nt') ? 'ntdll.dll' : 'kernel32.dll';
  hook(mod, fn, { onEnter(a) { log('INJECT', `${fn}(${a[0]}, ${a[1]})`); } });
});
hook('kernel32.dll', 'VirtualProtect', {
  onEnter(a) { log('EVADE', `VirtualProtect addr=${a[0]} size=${a[1].toInt32()} newProt=0x${a[2].toInt32().toString(16)} ${backtrace(this.context)}`); }
});

// ================================================================== NETWORK
hook('ws2_32.dll', 'connect', { onEnter(a) { log('NET', `connect() -> ${parseSockaddr(a[1])}  ${backtrace(this.context)}`); } });
hook('ws2_32.dll', 'WSAConnect', { onEnter(a) { log('NET', `WSAConnect() -> ${parseSockaddr(a[1])}`); } });
hook('ws2_32.dll', 'sendto', { onEnter(a) { log('NET', `sendto ${a[2].toInt32()}B -> ${parseSockaddr(a[4])}`); dumpBytes('net_out', a[1], a[2].toInt32()); } });
hook('ws2_32.dll', 'send', { onEnter(a) { const l = a[2].toInt32(); log('NET', `send ${l}B`); dumpBytes('net_out', a[1], l); } });
hook('ws2_32.dll', 'WSASend', { onEnter(a) { log('NET', `WSASend sock=${a[0]}`); } });
hook('ws2_32.dll', 'recv', { onEnter(a) { this.buf = a[1]; }, onLeave(r) { const n = r.toInt32(); if (n > 0) { log('NET', `recv ${n}B`); dumpBytes('net_in', this.buf, n); } } });
hook('ws2_32.dll', 'recvfrom', { onEnter(a) { this.buf = a[1]; this.from = a[4]; }, onLeave(r) { const n = r.toInt32(); if (n > 0) { log('NET', `recvfrom ${n}B <- ${this.from.isNull() ? '?' : parseSockaddr(this.from)}`); dumpBytes('net_in', this.buf, n); } } });
hook('ws2_32.dll', 'WSASocketW', { onEnter(a) { log('NET', `WSASocketW af=${a[0].toInt32()} type=${a[1].toInt32()} proto=${a[2].toInt32()}`); } });
// name resolution
hook('ws2_32.dll', 'getaddrinfo', { onEnter(a) { log('DNS', `getaddrinfo("${a[0].isNull() ? '' : a[0].readAnsiString()}", "${a[1].isNull() ? '' : a[1].readAnsiString()}")`); } });
hook('ws2_32.dll', 'GetAddrInfoW', { onEnter(a) { log('DNS', `GetAddrInfoW("${a[0].isNull() ? '' : a[0].readUtf16String()}", "${a[1].isNull() ? '' : a[1].readUtf16String()}")`); } });
hook('dnsapi.dll', 'DnsQuery_W', { onEnter(a) { log('DNS', `DnsQuery_W("${a[0].isNull() ? '' : a[0].readUtf16String()}")`); } });

// ================================================================== REGISTRY / FILES / EXECUTION
hook('advapi32.dll', 'RegSetValueExW', {
  onEnter(a) {
    const name = a[1].isNull() ? '' : a[1].readUtf16String();
    let data = '';
    try { if (!a[4].isNull()) data = a[4].readUtf16String(); } catch (e) {}
    log('REG', `RegSetValueExW value="${name}" data="${data}"`);
  }
});
hook('advapi32.dll', 'RegCreateKeyExW', { onEnter(a) { log('REG', `RegCreateKeyExW subkey="${a[1].isNull() ? '' : a[1].readUtf16String()}"`); } });
hook('kernel32.dll', 'CreateFileW', {
  onEnter(a) { const p = a[0].isNull() ? '' : a[0].readUtf16String(); if (p && !/\\(Device|PIPE|KnownDlls)/i.test(p)) log('FILE', `CreateFileW "${p}"`); }
});
hook('kernel32.dll', 'CopyFileW', { onEnter(a) { log('FILE', `CopyFileW "${a[0].readUtf16String()}" -> "${a[1].readUtf16String()}"`); } });
hook('kernel32.dll', 'MoveFileExW', { onEnter(a) { log('FILE', `MoveFileExW "${a[0].readUtf16String()}" -> "${a[1].isNull() ? '' : a[1].readUtf16String()}"`); } });
['ShellExecuteW', 'ShellExecuteExW'].forEach(fn => hook('shell32.dll', fn, { onEnter(a) { try { log('EXEC', `${fn} ...`); } catch (e) {} } }));
hook('kernel32.dll', 'WinExec', { onEnter(a) { log('EXEC', `WinExec("${a[0].readAnsiString()}")`); } });
// .inf execution through advpack
['LaunchINFSectionW', 'LaunchINFSectionExW', 'RunSetupCommandW'].forEach(fn => hook('advpack.dll', fn, { onEnter(a) { log('EXEC', `advpack!${fn}`); } }));

// ================================================================== CRYPTO
['CryptStringToBinaryW', 'CryptStringToBinaryA'].forEach(fn => hook('crypt32.dll', fn, { onEnter(a) { log('CRYPTO', `${fn}`); } }));
['BCryptDecrypt', 'BCryptEncrypt'].forEach(fn => hook('bcrypt.dll', fn, { onEnter(a) { log('CRYPTO', `${fn} in=${a[2]} len=${a[3].toInt32()}`); } }));
// DPAPI
['CryptUnprotectData', 'CryptProtectData'].forEach(fn => hook('crypt32.dll', fn, {
  onEnter(a) { try { this.inLen = a[0].isNull() ? 0 : a[0].readU32(); } catch (e) { this.inLen = -1; } },
  onLeave(r) { log('CRYPTO', `DPAPI ${fn} inLen=${this.inLen} ret=${r.toInt32()}`); }
}));
['CryptUnprotectMemory', 'CryptProtectMemory'].forEach(fn => hook('crypt32.dll', fn, {
  onEnter(a) { log('CRYPTO', `DPAPI ${fn} flags=0x${a[2].toInt32().toString(16)}`); }
}));

// ================================================================== WINHTTP
// The injected component talks through WinHTTP rather than raw ws2_32: capture the whole session.
hook('winhttp.dll', 'WinHttpOpen', {
  onEnter(a) { try { this.ua = a[0].isNull() ? '' : a[0].readUtf16String(); } catch (e) {} },
  onLeave(r) { log('HTTP', `WinHttpOpen UA="${this.ua || ''}" session=${r}`); }
});
hook('winhttp.dll', 'WinHttpConnect', {
  onEnter(a) {
    try { this.host = a[1].isNull() ? '' : a[1].readUtf16String(); this.port = a[2].toInt32(); }
    catch (e) {}
  },
  // NOTE: the port argument is an INTERNET_PORT (16 bits); the upper bits read here are garbage.
  onLeave(r) { log('HTTP', `WinHttpConnect host="${this.host || ''}" port=${(this.port & 0xffff) || '?'} conn=${r}`); }
});
hook('winhttp.dll', 'WinHttpOpenRequest', {
  onEnter(a) {
    try {
      this.verb = a[1].isNull() ? '' : a[1].readUtf16String();
      this.path = a[2].isNull() ? '' : a[2].readUtf16String();
    } catch (e) {}
  },
  onLeave(r) { log('HTTP', `WinHttpOpenRequest ${this.verb || ''} path="${this.path || ''}" req=${r}`); }
});
hook('winhttp.dll', 'WinHttpSendRequest', {
  onEnter(a) {
    try {
      this.hdrs = a[1].isNull() ? '' : (a[2].toInt32() > 0 ? a[1].readUtf16String() : '');
      this.bodyLen = a[5].toInt32();
      this.body = a[3];
    } catch (e) {}
  },
  onLeave(r) {
    log('HTTP', `WinHttpSendRequest hdrs="${(this.hdrs||'').substr(0,120)}" bodyLen=${this.bodyLen}`);
    if (this.bodyLen > 0 && this.body && !this.body.isNull()) {
      dumpBytes('http_send', this.body, Math.min(this.bodyLen, 4 * 1024 * 1024));
    }
  }
});
hook('winhttp.dll', 'WinHttpWriteData', {
  onEnter(a) { this.buf = a[1]; this.len = a[2].toInt32(); },
  onLeave(r) {
    log('HTTP', `WinHttpWriteData len=${this.len}`);
    if (this.len > 0 && this.buf && !this.buf.isNull()) {
      dumpBytes('http_write', this.buf, Math.min(this.len, 4 * 1024 * 1024));
    }
  }
});
hook('winhttp.dll', 'WinHttpReadData', {
  onEnter(a) { this.buf = a[1]; this.capacity = a[2].toInt32(); this.outLen = a[3]; },
  onLeave(r) {
    try {
      const n = this.outLen && !this.outLen.isNull() ? this.outLen.readU32() : 0;
      if (n > 0) { log('HTTP', `WinHttpReadData ${n}B`); dumpBytes('http_read', this.buf, n); }
    } catch (e) {}
  }
});
hook('winhttp.dll', 'WinHttpQueryHeaders', { onEnter(a) { log('HTTP', `WinHttpQueryHeaders info=0x${a[1].toInt32().toString(16)}`); } });
hook('winhttp.dll', 'WinHttpReceiveResponse', {
  onLeave(r) { log('HTTP', `WinHttpReceiveResponse ret=${r.toInt32()}`); }
});
hook('winhttp.dll', 'WinHttpQueryDataAvailable', {
  onEnter(a) { this.outLen = a[1]; },
  onLeave(r) {
    try {
      const n = (this.outLen && !this.outLen.isNull()) ? this.outLen.readU32() : 0;
      log('HTTP', `WinHttpQueryDataAvailable bytesAvailable=${n} ret=${r.toInt32()}`);
    } catch (e) {}
  }
});
// Other HTTP stacks, in case
['InternetOpenW', 'InternetConnectW', 'HttpOpenRequestW', 'HttpSendRequestW', 'InternetReadFile', 'InternetWriteFile']
  .forEach(fn => hook('wininet.dll', fn, { onEnter(a) { log('HTTP', `wininet!${fn}`); } }));

// ================================================================== NAMED PIPES
hook('kernel32.dll', 'CreateNamedPipeW', {
  onEnter(a) { try { this.name = a[0].isNull() ? '' : a[0].readUtf16String(); } catch (e) {} },
  onLeave(r) { log('PIPE', `CreateNamedPipeW "${this.name || ''}" -> handle=${r}`); }
});
hook('ntdll.dll', 'NtCreateNamedPipeFile', {
  onEnter(a) {
    try {
      // a[2] = OBJECT_ATTRIBUTES*; the name sits inside ObjectName (UNICODE_STRING*)
      const oa = a[2];
      if (!oa.isNull()) {
        const pUniStr = oa.add(Process.pointerSize * 2).readPointer();  // offset of ObjectName
        if (pUniStr && !pUniStr.isNull()) {
          const nameLen = pUniStr.readU16();
          const buf = pUniStr.add(Process.pointerSize).readPointer();
          if (buf && !buf.isNull()) { this.name = buf.readUtf16String(nameLen / 2); }
        }
      }
    } catch (e) {}
  },
  onLeave(r) { if (this.name) log('PIPE', `NtCreateNamedPipeFile "${this.name}"`); }
});
hook('kernel32.dll', 'ConnectNamedPipe', { onEnter(a) { log('PIPE', `ConnectNamedPipe handle=${a[0]}`); } });

// ================================================================== CERTIFICATE STORES
['CertAddCertificateContextToStore', 'CertAddEncodedCertificateToStore', 'CertAddCertificateLinkToStore']
  .forEach(fn => hook('crypt32.dll', fn, { onEnter(a) { log('CERT', `crypt32!${fn} store=${a[0]}`); } }));
['CertOpenStore', 'CertOpenSystemStoreW', 'CertOpenSystemStoreA']
  .forEach(fn => hook('crypt32.dll', fn, {
    onEnter(a) {
      try {
        if (fn === 'CertOpenSystemStoreW' && !a[1].isNull()) this.store = a[1].readUtf16String();
        else if (fn === 'CertOpenSystemStoreA' && !a[1].isNull()) this.store = a[1].readAnsiString();
        else if (fn === 'CertOpenStore' && !a[3].isNull()) { try { this.store = a[3].readUtf16String(); } catch (e) { try { this.store = a[3].readAnsiString(); } catch (e2) {} } }
      } catch (e) {}
    },
    onLeave(r) { if (this.store) log('CERT', `crypt32!${fn} store="${this.store}"`); }
  }));

// ================================================================== PROCESS SUSPEND / APC
hook('ntdll.dll', 'NtSuspendProcess', { onEnter(a) { log('PROC', `NtSuspendProcess hProc=${a[0]}`); } });
hook('ntdll.dll', 'NtResumeProcess',  { onEnter(a) { log('PROC', `NtResumeProcess hProc=${a[0]}`); } });
hook('ntdll.dll', 'NtQueueApcThread', {
  onEnter(a) { log('INJECT', `NtQueueApcThread hThread=${a[0]} apc=${a[1]} ctx=${a[2]}`); }
});
hook('ntdll.dll', 'NtQueueApcThreadEx', {
  onEnter(a) { log('INJECT', `NtQueueApcThreadEx hThread=${a[0]} apc=${a[2]}`); }
});

// ================================================================== ENVIRONMENT VARIABLES
// Flags variables commonly associated with TLS interception (reported by a public sandbox, not
// reproduced in our runs).
hook('kernel32.dll', 'SetEnvironmentVariableW', {
  onEnter(a) {
    try {
      const name = a[0].isNull() ? '' : a[0].readUtf16String();
      const val  = a[1].isNull() ? '' : a[1].readUtf16String();
      if (/SSLKEYLOGFILE|CURL_CA_BUNDLE|mitmproxy/i.test(name + ' ' + val)) {
        log('ENV', `SetEnv ${name}="${val}"  <<< TLS-interception related`);
      } else {
        log('EXEC', `SetEnv ${name}="${val || ''}"`);
      }
    } catch (e) {}
  }
});
hook('kernel32.dll', 'SetEnvironmentVariableA', {
  onEnter(a) {
    try {
      const name = a[0].isNull() ? '' : a[0].readAnsiString();
      const val  = a[1].isNull() ? '' : a[1].readAnsiString();
      if (/SSLKEYLOGFILE|CURL_CA_BUNDLE|mitmproxy/i.test(name + ' ' + val)) {
        log('ENV', `SetEnv ${name}="${val}"  <<< TLS-interception related`);
      }
    } catch (e) {}
  }
});

// ================================================================== REGISTRY WRITE HIGHLIGHTER
// The generic RegSetValueExW hook above logs everything. This second hook tags values that look like
// certificate / COM-hijack candidates. (A 16-hex-digit value-name heuristic was dropped: such names also
// exist on clean Windows installations under ...\Notifications\Data.)
Interceptor.attach(Module.findExportByName('advapi32.dll', 'RegSetValueExW'), {
  onEnter(a) {
    try {
      const name = a[1].isNull() ? '' : a[1].readUtf16String();
      if (!name) return;
      if (/certblob|cert|disallowed|root|treatas|inprocserver32/i.test(name)) {
        log('REG', `RegSetValueExW value="${name}" (certificate / COM-hijack candidate)`);
      }
    } catch (e) {}
  }
});

// ================================================================== FIRMWARE TABLE (anti-VM observation)
hook('kernel32.dll', 'GetSystemFirmwareTable', {
  onEnter(a) { this.provider = a[0].toInt32(); this.id = a[1].toInt32(); this.buf = a[2]; this.sz = a[3].toInt32(); },
  onLeave(r) {
    const n = r.toInt32();
    log('ANTI-VM', `GetSystemFirmwareTable provider=0x${this.provider.toString(16)} id=0x${this.id.toString(16)} wrote=${n}B (SMBIOS)`);
    // The buffer is not edited here: the VM is expected to be hardened (.vmx SMBIOS.reflectHost = FALSE).
    // See smbios_vm.js for the opposite experiment (re-inserting a "VMware" string).
  }
});
// GetCursorPos is deliberately not hooked: 800+ calls in explorer.exe over 10 minutes (normal polling).

// ================================================================== CROSS-PROCESS ACCESS
// Watch for a process opening explorer.exe: OpenProcess/NtOpenProcess with write-capable access.
hook('kernel32.dll', 'OpenProcess', {
  onEnter(a) { this.access = a[0].toInt32(); this.pid = a[2].toInt32(); },
  onLeave(r) {
    if (r.isNull()) return;
    // PROCESS_VM_WRITE=0x20, PROCESS_VM_OPERATION=0x08, PROCESS_CREATE_THREAD=0x02
    const interesting = (this.access & 0x2A) !== 0 || this.access === 0x1FFFFF; // PROCESS_ALL_ACCESS
    log('INJECT', `OpenProcess pid=${this.pid} access=0x${this.access.toString(16)} -> h=${r}${interesting ? ' [WRITE/CREATE_THREAD/ALL]' : ''}`);
  }
});
// NtOpenProcess: a[3] (CLIENT_ID*) can be NULL, which crashed the Go runtime in an earlier version,
// so every dereference is guarded.
hook('ntdll.dll', 'NtOpenProcess', {
  onEnter(a) {
    try {
      this.access = a[1].toInt32();
      if (a[3] && !a[3].isNull()) {
        const cid = a[3].readPointer();
        if (cid && !cid.isNull()) this.pid = cid.toInt32();
      }
    } catch (e) { this.pid = -1; }
  },
  onLeave(r) {
    if (this.pid && this.pid > 0) {
      log('INJECT', `NtOpenProcess pid=${this.pid} access=0x${(this.access||0).toString(16)} ret=${r.toInt32()}`);
    }
  }
});

// NtMapViewOfSection - minimal version, to avoid dereferencing unchecked pointers (the Go runtime calls
// it a lot at start-up). Only logged when hProc is not NtCurrentProcess(-1): a cross-process mapping.
hook('ntdll.dll', 'NtMapViewOfSection', {
  onEnter(a) { this.hProc = a[1]; },
  onLeave(r) {
    try {
      const hp = this.hProc;
      if (hp && !hp.isNull() && hp.toInt32() !== -1 && hp.toInt32() !== 0xffffffff) {
        log('INJECT', `NtMapViewOfSection CROSS-PROCESS hProc=${hp} ret=${r.toInt32()}`);
      }
    } catch (e) {}
  }
});
hook('ntdll.dll', 'NtUnmapViewOfSection', {
  onEnter(a) { log('INJECT', `NtUnmapViewOfSection hProc=${a[0]} base=${a[1]}`); }
});
// Injectors that bypass CreateRemoteThread
hook('ntdll.dll', 'RtlCreateUserThread', {
  onEnter(a) { log('INJECT', `RtlCreateUserThread hProc=${a[0]} startAddr=${a[4]} startArg=${a[5]}`); }
});
// DLL injection through window hooks
hook('user32.dll', 'SetWindowsHookExW', {
  onEnter(a) { log('INJECT', `SetWindowsHookExW type=${a[0].toInt32()} hMod=${a[2]} tid=${a[3].toInt32()}`); }
});
hook('user32.dll', 'SetWindowsHookExA', {
  onEnter(a) { log('INJECT', `SetWindowsHookExA type=${a[0].toInt32()} hMod=${a[2]} tid=${a[3].toInt32()}`); }
});
// WM_COPYDATA via SendMessage is deliberately not hooked: thousands of calls per second in explorer.exe.

// Window lookup (e.g. locating the shell window before injecting)
['FindWindowW','FindWindowA','FindWindowExW','FindWindowExA'].forEach(fn => hook('user32.dll', fn, {
  onEnter(a) {
    try {
      const isW = fn.endsWith('W');
      const i = fn.includes('Ex') ? 2 : 0;
      const clsArg = a[i], nameArg = a[i+1];
      let cls = '', name = '';
      if (!clsArg.isNull()) {
        // can be an atom (low bits) or a string pointer
        const v = clsArg.toInt32() >>> 0;
        if (v > 0xFFFF) cls = isW ? clsArg.readUtf16String() : clsArg.readAnsiString();
        else cls = `#atom:${v}`;
      }
      if (nameArg && !nameArg.isNull()) name = isW ? nameArg.readUtf16String() : nameArg.readAnsiString();
      if (cls || name) log('WINDOW', `${fn} class="${cls}" name="${name}"`);
    } catch (e) {}
  }
}));

// ================================================================== DIALOG VARIANTS (log only)
['SoftModalMessageBox', 'MessageBoxIndirectW', 'MessageBoxIndirectA']
  .forEach(fn => hook('user32.dll', fn, {
    onEnter(a) { log('MSGBOX', `${fn} called`); }
  }));
['TaskDialog', 'TaskDialogIndirect']
  .forEach(fn => hook('comctl32.dll', fn, {
    onEnter(a) { log('MSGBOX', `comctl32!${fn} called`); }
  }));
['SHMessageBoxCheckW', 'SHMessageBoxCheckA']
  .forEach(fn => hook('shlwapi.dll', fn, {
    onEnter(a) {
      try {
        const txt = a[1].isNull() ? '' : (fn.endsWith('W') ? a[1].readUtf16String() : a[1].readAnsiString());
        log('MSGBOX', `shlwapi!${fn} text="${txt.substr(0,100)}"`);
      } catch (e) { log('MSGBOX', `shlwapi!${fn}`); }
    }
  }));
// All windows go through NtUserCreateWindowEx on Windows 10+
hook('win32u.dll', 'NtUserCreateWindowEx', {
  onEnter(a) { log('MSGBOX', 'NtUserCreateWindowEx (window creation at syscall level)'); }
});
hook('user32.dll', 'ShowWindow', {
  onEnter(a) {
    const cmd = a[1].toInt32();
    // SW_SHOW=5, SW_SHOWNORMAL=1
    if (cmd === 5 || cmd === 1) log('MSGBOX', `ShowWindow hwnd=${a[0]} cmd=${cmd}`);
  }
});

// Process creation at syscall level (catches the loader launching its child)
hook('ntdll.dll', 'NtCreateUserProcess', {
  onEnter(a) { log('INJECT', 'NtCreateUserProcess (process launch at syscall level)'); }
});

// ================================================================== ANTI-DEBUG / ANTI-VM NEUTRALISATION
// MODIFIES BEHAVIOUR. Masks the debugger / VM so the sample keeps its normal flow.
// Covered: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess
// (DebugPort / DebugObjectHandle / DebugFlags), opening of VMware / VirtualBox / QEMU registry keys.
// Not covered: the CPUID hypervisor bit (needs instruction-level Stalker), MAC address checks
// through GetAdaptersInfo (logged below, not spoofed).
hook('kernel32.dll', 'IsDebuggerPresent', {
  onLeave(r) { r.replace(ptr(0)); log('ANTI-VM', 'IsDebuggerPresent -> 0'); }
});
hook('kernel32.dll', 'CheckRemoteDebuggerPresent', {
  onEnter(a) { this.pbuf = a[1]; },
  onLeave(r) {
    try { if (!this.pbuf.isNull()) this.pbuf.writeU32(0); } catch (e) {}
    log('ANTI-VM', 'CheckRemoteDebuggerPresent -> 0');
  }
});
// NtQueryInformationProcess: DebugPort(7)/DebugObjectHandle(0x1e) = 0 ; DebugFlags(0x1f) = 1
hook('ntdll.dll', 'NtQueryInformationProcess', {
  onEnter(a) { this.cls = a[1].toInt32(); this.buf = a[2]; this.len = a[3].toInt32(); },
  onLeave(r) {
    try {
      if ((this.cls === 7 || this.cls === 0x1e) && this.len >= Process.pointerSize) {
        this.buf.writePointer(ptr(0));
        log('ANTI-VM', `NtQueryInfoProc cls=0x${this.cls.toString(16)} forced 0`);
      } else if (this.cls === 0x1f && this.len >= 4) {
        this.buf.writeU32(1);
        log('ANTI-VM', 'NtQueryInfoProc DebugFlags = 1');
      }
    } catch (e) {}
  }
});
// Registry: hide VMware / VBox / QEMU / Parallels / Xen / Wine keys
['RegOpenKeyExW', 'RegOpenKeyExA'].forEach(fn => hook('advapi32.dll', fn, {
  onEnter(a) {
    try {
      const sub = (fn.endsWith('W') ? (a[1].isNull() ? '' : a[1].readUtf16String())
                                    : (a[1].isNull() ? '' : a[1].readAnsiString())) || '';
      this.subname = sub;
      this.vmKey = /VMware|VBox|VirtualBox|QEMU|Xen|Parallels|Wine|vmhgfs|vmmouse|vmusbmouse|VMTools/i.test(sub);
    } catch (e) {}
  },
  onLeave(r) {
    if (this.vmKey) {
      r.replace(ptr(2));  // ERROR_FILE_NOT_FOUND
      log('ANTI-VM', `RegOpen "${this.subname}" -> ERROR_FILE_NOT_FOUND`);
    }
  }
}));

// ================================================================== MESSAGEBOX AUTO-DISMISS (lazy)
// MODIFIES BEHAVIOUR. Replaces MessageBox* so the sample is never blocked by a dialog (returns IDOK).
// Installed lazily: retried after every LdrLoadDll, in case user32 is loaded late.
const _msgboxDone = {};
function _installMsgboxReplacement(fn, mod, isW, nargs) {
  const key = mod + '!' + fn;
  if (_msgboxDone[key]) return;
  const addr = Module.findExportByName(mod, fn);
  if (!addr) return;
  try {
    Interceptor.replace(addr, new NativeCallback(function () {
      try {
        const lpText = arguments[1];
        const lpCaption = arguments[2];
        let text = '', caption = '';
        if (lpText && !lpText.isNull())    text    = isW ? lpText.readUtf16String() : lpText.readAnsiString();
        if (lpCaption && !lpCaption.isNull()) caption = isW ? lpCaption.readUtf16String() : lpCaption.readAnsiString();
        log('MSGBOX', `${fn} intercepted title="${caption}" text="${(text || '').substr(0, 200)}" -> IDOK`);
      } catch (e) { log('MSGBOX', `${fn} intercepted (read error: ${e}) -> IDOK`); }
      return 1;  // IDOK
    }, 'int', new Array(nargs).fill('pointer')));
    _msgboxDone[key] = true;
    log('HOOK', `+ replaced ${key}`);
  } catch (e) { log('HOOK', `failed to replace ${key}: ${e}`); }
}
function _installAllMsgbox() {
  ['MessageBoxW','MessageBoxA'].forEach(fn => _installMsgboxReplacement(fn, 'user32.dll', fn.endsWith('W'), 4));
  ['MessageBoxExW','MessageBoxExA'].forEach(fn => _installMsgboxReplacement(fn, 'user32.dll', fn.endsWith('W'), 5));
  // Undocumented MessageBoxTimeoutW/A (6 args)
  ['MessageBoxTimeoutW','MessageBoxTimeoutA'].forEach(fn => _installMsgboxReplacement(fn, 'user32.dll', fn.endsWith('W'), 6));
  // TaskDialog / TaskDialogIndirect (comctl32) are only logged above: their signature is more complex.
}
_installAllMsgbox();

// Log every window created (a sample may display a custom window instead of a MessageBox)
hook('user32.dll', 'CreateWindowExW', {
  onEnter(a) {
    try {
      const cls  = a[1].isNull() ? '' : a[1].readUtf16String();
      const name = a[2].isNull() ? '' : a[2].readUtf16String();
      if (cls || name) log('MSGBOX', `CreateWindowExW class="${cls}" name="${name}"`);
    } catch (e) {}
  }
});
hook('user32.dll', 'CreateWindowExA', {
  onEnter(a) {
    try {
      const cls  = a[1].isNull() ? '' : a[1].readAnsiString();
      const name = a[2].isNull() ? '' : a[2].readAnsiString();
      if (cls || name) log('MSGBOX', `CreateWindowExA class="${cls}" name="${name}"`);
    } catch (e) {}
  }
});
// Catches a title set after creation
hook('user32.dll', 'SetWindowTextW', { onEnter(a) { try { if (!a[1].isNull()) log('MSGBOX', `SetWindowTextW "${a[1].readUtf16String()}"`); } catch (e) {} } });
// Common DialogBox* / CreateDialog* variants
['DialogBoxParamW','DialogBoxParamA','DialogBoxIndirectParamW','DialogBoxIndirectParamA',
 'CreateDialogParamW','CreateDialogParamA','CreateDialogIndirectParamW','CreateDialogIndirectParamA']
  .forEach(fn => hook('user32.dll', fn, { onEnter() { log('MSGBOX', `${fn} called`); } }));

// Re-install the MessageBox replacements after each DLL load
['LdrLoadDll'].forEach(fn => {
  const a = Module.findExportByName('ntdll.dll', fn);
  if (a) Interceptor.attach(a, { onLeave: function () { try { _installAllMsgbox(); } catch (e) {} } });
});

// ================================================================== EXIT TRACING
// Where and why does the sample exit (silent anti-VM exit? normal exit?)
hook('kernel32.dll', 'ExitProcess', { onEnter(a) { log('EXIT', `ExitProcess code=${a[0].toInt32()} ${backtrace(this.context)}`); } });
hook('ntdll.dll',    'NtTerminateProcess', { onEnter(a) { log('EXIT', `NtTerminateProcess hProc=${a[0]} code=${a[1].toInt32()} ${backtrace(this.context)}`); } });
hook('ntdll.dll',    'RtlExitUserProcess', { onEnter(a) { log('EXIT', `RtlExitUserProcess code=${a[0].toInt32()}`); } });
['exit','_exit','abort','_cexit','_c_exit','quick_exit'].forEach(fn => {
  ['ucrtbase.dll','msvcrt.dll','vcruntime140.dll'].forEach(mod => hook(mod, fn, { onEnter(a) { try { log('EXIT', `${mod}!${fn} code=${a[0].toInt32()} ${backtrace(this.context)}`); } catch (e) {} } }));
});
hook('kernel32.dll', 'TerminateProcess', { onEnter(a) { log('EXIT', `TerminateProcess hProc=${a[0]} code=${a[1].toInt32()}`); } });

// ================================================================== MAC / COMPUTER NAME (log only, no spoofing)
hook('iphlpapi.dll', 'GetAdaptersInfo',      { onEnter() { log('ANTI-VM', 'GetAdaptersInfo called (possible MAC check)'); } });
hook('iphlpapi.dll', 'GetAdaptersAddresses', { onEnter() { log('ANTI-VM', 'GetAdaptersAddresses called (possible MAC check)'); } });
hook('kernel32.dll', 'GetComputerNameExW',   { onEnter() { log('ANTI-VM', 'GetComputerNameExW called'); } });

log('INIT', `Instrumentation loaded. dumps -> ${DUMPDIR}`);
