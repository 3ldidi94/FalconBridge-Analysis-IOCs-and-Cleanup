// smbios_vm.js - "yolo window" experiment.
// Puts the "VMware" string back into the SMBIOS table returned by GetSystemFirmwareTable('RSMB'),
// to see whether the injected code changes behaviour (message box? no network call?).
(function () {
  const addr = Process.getModuleByName('kernel32.dll').getExportByName('GetSystemFirmwareTable');
  Interceptor.attach(addr, {
    onEnter(a) { this.prov = a[0].toUInt32(); this.buf = a[2]; this.cap = a[3].toUInt32(); },
    onLeave(r) {
      try {
        const n = r.toUInt32();
        if (this.prov !== 0x52534d42 || this.buf.isNull() || n === 0 || n > this.cap) return;
        const u8 = new Uint8Array(this.buf.readByteArray(n));
        // first run of 14 consecutive printable characters = an SMBIOS string
        let start = -1, run = 0;
        for (let i = 8; i < n; i++) {
          if (u8[i] >= 0x20 && u8[i] < 0x7f) { run++; if (run === 14) { start = i - 13; break; } }
          else run = 0;
        }
        if (start < 0) { console.log('[SMBIOS] no string found'); return; }
        const fake = 'VMware, Inc.  ';
        for (let j = 0; j < fake.length; j++) this.buf.add(start + j).writeU8(fake.charCodeAt(j));
        console.log('[SMBIOS] patched "VMware, Inc." at offset ' + start + ' of ' + n);
      } catch (e) { console.log('[SMBIOS] error ' + e); }
    }
  });
  console.log('[SMBIOS] smbios_vm loaded in pid ' + Process.id);
})();
