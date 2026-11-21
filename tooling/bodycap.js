// bodycap.js - "request body" experiment, to be attached to explorer.exe.
// WinHTTP sending fails (VM with no network): force success so that the code actually writes its
// body, and save every buffer to C:\sandbox\dumps.
(function () {
  const wh = Process.getModuleByName('winhttp.dll');
  const P = Process.id;
  let seq = 0;
  function save(tag, p, len) {
    try {
      if (p.isNull() || len <= 0) return;
      const fn = 'C:\\sandbox\\dumps\\' + P + '_' + tag + '_' + (seq++) + '_' + Date.now() + '.bin';
      const f = new File(fn, 'wb'); f.write(p.readByteArray(len)); f.close();
      console.log('[BODY] saved ' + len + ' bytes -> ' + fn);
    } catch (e) { console.log('[BODY] save error ' + e); }
  }
  Interceptor.attach(wh.getExportByName('WinHttpSendRequest'), {
    onEnter(a) {
      this.t = Date.now();
      this.opt = a[3]; this.optLen = a[4].toInt32(); this.tot = a[5].toInt32();
      console.log('[BODY] SendRequest enter lpOptional=' + this.opt + ' optLen=' + this.optLen + ' total=' + this.tot);
      save('send_optional', this.opt, this.optLen);
    },
    onLeave(r) {
      console.log('[BODY] SendRequest ret=' + r.toInt32() + ' after ' + (Date.now() - this.t) + ' ms');
      if (r.toInt32() === 0) { r.replace(ptr(1)); console.log('[BODY] SendRequest forced TRUE'); }
    }
  });
  Interceptor.attach(wh.getExportByName('WinHttpWriteData'), {
    onEnter(a) {
      this.len = a[2].toInt32(); this.out = a[3];
      console.log('[BODY] WriteData len=' + this.len);
      save('write', a[1], this.len);
    },
    onLeave(r) {
      if (r.toInt32() === 0) {
        try { if (!this.out.isNull()) this.out.writeU32(this.len); } catch (e) {}
        r.replace(ptr(1)); console.log('[BODY] WriteData forced TRUE');
      }
    }
  });
  Interceptor.attach(wh.getExportByName('WinHttpReceiveResponse'), {
    onLeave(r) { console.log('[BODY] ReceiveResponse ret=' + r.toInt32()); }
  });
  console.log('[BODY] bodycap loaded in pid ' + P);
})();
