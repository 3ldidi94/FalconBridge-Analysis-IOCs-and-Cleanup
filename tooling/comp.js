// comp.js - inside explorer.exe: captures the buffers before/after compression (RtlCompressBuffer /
// RtlDecompressBuffer) and lightly logs the WinHTTP session.
(function () {
  const nt = Process.getModuleByName('ntdll.dll');
  const P = Process.id;
  let q = 0;
  function save(tag, p, len) {
    try {
      if (p.isNull() || len <= 0 || len > 16 * 1024 * 1024) return;
      const fn = 'C:\\sandbox\\dumps\\' + P + '_' + tag + '_' + (q++) + '_' + Date.now() + '.bin';
      const f = new File(fn, 'wb'); f.write(p.readByteArray(len)); f.close();
      console.log('[COMP] saved ' + len + ' bytes -> ' + fn);
    } catch (e) { console.log('[COMP] save error ' + e); }
  }
  function bt(ctx) {
    try { return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, 3).map(x => x.toString()).join(' < '); }
    catch (e) { return '?'; }
  }
  Interceptor.attach(nt.getExportByName('RtlCompressBuffer'), {
    onEnter(a) {
      this.out = a[3]; this.fin = a[6];
      const n = a[2].toUInt32();
      console.log('[COMP] RtlCompressBuffer fmt=0x' + (a[0].toUInt32() & 0xffff).toString(16) + ' inLen=' + n + ' from ' + bt(this.context));
      save('compress_in', a[1], n);
    },
    onLeave(r) {
      try {
        const n = this.fin.readU32();
        console.log('[COMP] RtlCompressBuffer -> outLen=' + n + ' status=0x' + r.toUInt32().toString(16));
        save('compress_out', this.out, n);
      } catch (e) {}
    }
  });
  Interceptor.attach(nt.getExportByName('RtlDecompressBuffer'), {
    onEnter(a) {
      this.out = a[1]; this.fin = a[5];
      const n = a[4].toUInt32();
      console.log('[COMP] RtlDecompressBuffer inLen=' + n + ' from ' + bt(this.context));
      save('decompress_in', a[3], n);
    },
    onLeave(r) {
      try { const n = this.fin.readU32(); console.log('[COMP] RtlDecompressBuffer -> outLen=' + n); save('decompress_out', this.out, n); } catch (e) {}
    }
  });
  try {
    const wh = Process.getModuleByName('winhttp.dll');
    Interceptor.attach(wh.getExportByName('WinHttpOpen'), {
      onEnter(a) { try { console.log('[HTTP] WinHttpOpen UA="' + (a[0].isNull() ? '' : a[0].readUtf16String()) + '" from ' + bt(this.context)); } catch (e) {} }
    });
    Interceptor.attach(wh.getExportByName('WinHttpConnect'), {
      onEnter(a) { try { console.log('[HTTP] WinHttpConnect host="' + a[1].readUtf16String() + '" port=' + (a[2].toUInt32() & 0xffff)); } catch (e) {} }
    });
  } catch (e) { console.log('[HTTP] winhttp not loaded yet'); }
  console.log('[COMP] comp loaded in pid ' + P);
})();
