// memdump.js - inside explorer.exe: spots any new private executable range (no backing file) that appears
// after the script is loaded, waits about 4 s (time for the code to decrypt itself there), then saves it
// to C:\sandbox\dumps.
(function () {
  const P = Process.id;
  const base0 = {};
  function privExec() {
    return Process.enumerateRanges('r-x').filter(r => !r.file && r.size >= 0x10000 && r.size <= 0x400000);
  }
  privExec().forEach(r => { base0[r.base.toString()] = true; });
  const pending = {};   // base -> ticks seen
  let dumped = 0;
  const t = setInterval(function () {
    try {
      privExec().forEach(r => {
        const k = r.base.toString();
        if (base0[k]) return;
        pending[k] = (pending[k] || 0) + 1;
        if (pending[k] === 1) console.log('[MEM] new private exec range ' + k + ' size=0x' + r.size.toString(16) + ' prot=' + r.protection);
        if (pending[k] === 5 && dumped < 6) {
          const fn = 'C:\\sandbox\\dumps\\' + P + '_region_' + k + '_' + r.size.toString(16) + '.bin';
          const f = new File(fn, 'wb'); f.write(r.base.readByteArray(r.size)); f.close();
          dumped++;
          console.log('[MEM] dumped 0x' + r.size.toString(16) + ' bytes from ' + k + ' (' + r.protection + ') -> ' + fn);
        }
      });
    } catch (e) { console.log('[MEM] error ' + e); }
  }, 1000);
  console.log('[MEM] memdump armed in pid ' + P + ', baseline ranges=' + Object.keys(base0).length);
})();
