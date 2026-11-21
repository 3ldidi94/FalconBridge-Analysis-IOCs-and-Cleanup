// resolve.js - inside explorer.exe: lists the functions and DLLs requested by code located OUTSIDE any
// loaded module (i.e. the injected code), through GetProcAddress / LoadLibrary*.
(function () {
  const k = Process.getModuleByName('kernel32.dll');
  const seen = {};
  function fromInjected(ret) { try { return Process.findModuleByAddress(ret) === null; } catch (e) { return false; } }
  Interceptor.attach(k.getExportByName('GetProcAddress'), {
    onEnter(a) {
      try {
        if (!fromInjected(this.returnAddress)) return;
        const n = a[1];
        const s = n.compare(ptr(0x10000)) > 0 ? n.readAnsiString() : '#' + n.toUInt32();
        const mod = Process.findModuleByAddress(a[0]);
        const key = (mod ? mod.name : a[0].toString()) + '!' + s;
        if (!seen[key]) { seen[key] = 1; console.log('[RES] ' + key); }
      } catch (e) {}
    }
  });
  [['LoadLibraryA', false], ['LoadLibraryW', true], ['LoadLibraryExA', false], ['LoadLibraryExW', true]].forEach(function (p) {
    try {
      Interceptor.attach(k.getExportByName(p[0]), {
        onEnter(a) {
          try {
            if (!fromInjected(this.returnAddress)) return;
            const s = p[1] ? a[0].readUtf16String() : a[0].readAnsiString();
            const key = 'LOAD ' + s;
            if (!seen[key]) { seen[key] = 1; console.log('[RES] ' + key); }
          } catch (e) {}
        }
      });
    } catch (e) {}
  });
  console.log('[RES] resolve armed in pid ' + Process.id);
})();
