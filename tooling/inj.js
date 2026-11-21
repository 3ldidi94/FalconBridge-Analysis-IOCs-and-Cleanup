// inj.js - inside the injector (dexter.exe): traces native (ntdll) calls used to act on ANOTHER process.
// Deliberately light: ntdll only, no function replacement.
(function () {
  const nt = Process.getModuleByName('ntdll.dll');
  const P = Process.id;
  const SELF = '0xffffffffffffffff';
  let q = 0;
  function save(tag, p, len) {
    try {
      if (p.isNull() || len <= 0 || len > 16 * 1024 * 1024) return;
      const fn = 'C:\\sandbox\\dumps\\' + P + '_' + tag + '_' + (q++) + '_' + Date.now() + '.bin';
      const f = new File(fn, 'wb'); f.write(p.readByteArray(len)); f.close();
      console.log('[INJ] saved ' + len + ' bytes -> ' + fn);
    } catch (e) { console.log('[INJ] save error ' + e); }
  }
  function h(name, cb) {
    try { Interceptor.attach(nt.getExportByName(name), cb); }
    catch (e) { console.log('[INJ] cannot hook ' + name + ': ' + e); }
  }
  function st(r) { return '0x' + r.toUInt32().toString(16); }

  h('NtOpenProcess', {
    onEnter(a) { this.ph = a[0]; this.acc = a[1].toUInt32(); try { this.pid = a[3].readPointer().toUInt32(); } catch (e) { this.pid = -1; } },
    onLeave(r) { let hv = '?'; try { hv = this.ph.readPointer(); } catch (e) {}
      console.log('[INJ] NtOpenProcess pid=' + this.pid + ' access=0x' + this.acc.toString(16) + ' -> handle=' + hv + ' status=' + st(r)); }
  });
  h('NtOpenThread', {
    onEnter(a) { this.acc = a[1].toUInt32(); try { this.pid = a[3].readPointer().toUInt32(); this.tid = a[3].add(Process.pointerSize).readPointer().toUInt32(); } catch (e) {} },
    onLeave(r) { console.log('[INJ] NtOpenThread pid=' + this.pid + ' tid=' + this.tid + ' access=0x' + this.acc.toString(16) + ' status=' + st(r)); }
  });
  h('NtAllocateVirtualMemory', {
    onEnter(a) { this.hp = a[0]; this.pb = a[1]; this.ps = a[3]; this.prot = a[5].toUInt32(); },
    onLeave(r) { if (this.hp.toString() === SELF) return; let b = '?', s = '?'; try { b = this.pb.readPointer(); s = this.ps.readPointer(); } catch (e) {}
      console.log('[INJ] NtAllocateVirtualMemory REMOTE h=' + this.hp + ' base=' + b + ' size=' + s + ' prot=0x' + this.prot.toString(16) + ' status=' + st(r)); }
  });
  h('NtWriteVirtualMemory', {
    onEnter(a) { const n = a[3].toUInt32(); console.log('[INJ] NtWriteVirtualMemory h=' + a[0] + ' base=' + a[1] + ' len=' + n);
      if (a[0].toString() !== SELF) save('remote_write', a[2], n); }
  });
  h('NtProtectVirtualMemory', {
    onEnter(a) { if (a[0].toString() !== SELF) { let b = '?'; try { b = a[1].readPointer(); } catch (e) {}
      console.log('[INJ] NtProtectVirtualMemory REMOTE h=' + a[0] + ' base=' + b + ' newProt=0x' + a[3].toUInt32().toString(16)); } }
  });
  h('NtCreateSection', {
    onEnter(a) { this.ph = a[0]; this.prot = a[4].toUInt32(); this.attr = a[5].toUInt32(); try { this.size = a[3].isNull() ? 0 : a[3].readU64(); } catch (e) { this.size = '?'; } },
    onLeave(r) { let hv = '?'; try { hv = this.ph.readPointer(); } catch (e) {}
      console.log('[INJ] NtCreateSection size=' + this.size + ' prot=0x' + this.prot.toString(16) + ' attr=0x' + this.attr.toString(16) + ' -> ' + hv); }
  });
  h('NtMapViewOfSection', {
    onEnter(a) { this.sec = a[0]; this.hp = a[1]; this.pb = a[2]; this.prot = a[9].toUInt32(); },
    onLeave(r) { let b = '?'; try { b = this.pb.readPointer(); } catch (e) {}
      if (this.hp.toString() !== SELF) console.log('[INJ] NtMapViewOfSection REMOTE section=' + this.sec + ' hProc=' + this.hp + ' base=' + b + ' prot=0x' + this.prot.toString(16) + ' status=' + st(r)); }
  });
  h('NtCreateThreadEx', {
    onEnter(a) { console.log('[INJ] NtCreateThreadEx hProc=' + a[3] + ' start=' + a[4] + ' arg=' + a[5] + (a[3].toString() === SELF ? ' (local)' : ' (REMOTE)')); }
  });
  h('NtQueueApcThread',   { onEnter(a) { console.log('[INJ] NtQueueApcThread hThread=' + a[0] + ' routine=' + a[1] + ' arg1=' + a[2]); } });
  h('NtQueueApcThreadEx', { onEnter(a) { console.log('[INJ] NtQueueApcThreadEx hThread=' + a[0] + ' routine=' + a[2] + ' arg1=' + a[3]); } });
  h('NtSetContextThread', { onEnter(a) { console.log('[INJ] NtSetContextThread hThread=' + a[0]); } });
  h('NtGetContextThread', { onEnter(a) { console.log('[INJ] NtGetContextThread hThread=' + a[0]); } });
  h('NtSuspendThread',    { onEnter(a) { console.log('[INJ] NtSuspendThread hThread=' + a[0]); } });
  h('NtResumeThread',     { onEnter(a) { console.log('[INJ] NtResumeThread hThread=' + a[0]); } });
  h('NtSuspendProcess',   { onEnter(a) { console.log('[INJ] NtSuspendProcess h=' + a[0]); } });
  h('NtCreateUserProcess',{ onEnter(a) { console.log('[INJ] NtCreateUserProcess'); } });
  h('NtOpenSection',      { onEnter(a) { try { const us = a[2].add(Process.pointerSize * 2).readPointer(); const s = us.add(Process.pointerSize).readPointer().readUtf16String(us.readU16() / 2); console.log('[INJ] NtOpenSection "' + s + '"'); } catch (e) {} } });
  h('NtTerminateProcess', { onEnter(a) { console.log('[INJ] NtTerminateProcess h=' + a[0] + ' code=' + a[1].toInt32()); } });
  h('NtRaiseHardError',   { onEnter(a) { console.log('[INJ] NtRaiseHardError status=0x' + a[0].toUInt32().toString(16)); } });
  h('NtQuerySystemInformation', { onEnter(a) { const c = a[0].toUInt32(); if (c === 5 || c === 16 || c === 64) console.log('[INJ] NtQuerySystemInformation class=' + c); } });
  console.log('[INJ] inj loaded in pid ' + P);
})();
