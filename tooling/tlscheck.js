// tlscheck.js - what the injected code asks WinHTTP and crypt32 to do regarding TLS:
// - WinHttpSetOption / WinHttpQueryOption: which security flags, which option
// - WinHttpQueryOption(SERVER_CERT_CONTEXT=78): a sign the code inspects the server certificate
// - CertGetCertificateChain / CertVerifyChainPolicy: standard validation
// - BCryptVerifySignature: signature check on the response (looks for public-key pinning)
// No modification, logging only.
(function () {
  const P = Process.id;
  const WHOPT = {
    0: 'CALLBACK', 2: 'RESOLVE_TIMEOUT', 3: 'CONNECT_TIMEOUT', 7: 'CONTEXT_VALUE',
    31: 'SECURITY_FLAGS', 32: 'SECURITY_CERTIFICATE_STRUCT', 36: 'ENABLE_FEATURE',
    43: 'DISABLE_FEATURE', 45: 'HTTP_VERSION', 47: 'CLIENT_CERT_CONTEXT',
    52: 'SECURE_PROTOCOLS', 56: 'TCP_KEEPALIVE', 77: 'REJECT_USERPWD_IN_URL',
    78: 'SERVER_CERT_CONTEXT', 84: 'DECOMPRESSION', 85: 'WEB_SOCKET_KEEPALIVE_INTERVAL',
    99: 'TLS_FALSE_START', 123: 'TLS_PROTOCOL_INSECURE_FALLBACK', 131: 'CONNECTION_FILTER'
  };
  const SECFLAGS = {
    0x100: 'IGNORE_UNKNOWN_CA', 0x200: 'IGNORE_CERT_DATE_INVALID',
    0x1000: 'IGNORE_CERT_CN_INVALID', 0x2000: 'IGNORE_CERT_WRONG_USAGE',
    0x4000: 'IGNORE_WEAK_SIGNATURE', 0x8000: 'STRONG_CRYPTO'
  };
  function decFlags(v) {
    const out = []; for (const k in SECFLAGS) if (v & parseInt(k)) out.push(SECFLAGS[k]);
    return out.length ? out.join('|') : '0x' + v.toString(16);
  }
  function u32(p, off) { try { return p.add(off).readU32(); } catch (e) { return 0; } }

  function h(mod, name, cb) {
    try { Interceptor.attach(Process.getModuleByName(mod).getExportByName(name), cb); }
    catch (e) { console.log('[TLS] skip ' + mod + '!' + name + ': ' + e); }
  }

  h('winhttp.dll', 'WinHttpSetOption', {
    onEnter(a) {
      const opt = a[1].toUInt32();
      const name = WHOPT[opt] || ('0x' + opt.toString(16));
      const len = a[3].toUInt32();
      let extra = '';
      try {
        if (opt === 31 && len >= 4) extra = ' value=' + decFlags(a[2].readU32());
        else if (len >= 1 && len <= 16) extra = ' bytes=' + a[2].readByteArray(len);
      } catch (e) {}
      console.log('[TLS] WinHttpSetOption ' + name + ' (opt=' + opt + ') len=' + len + extra);
    }
  });
  h('winhttp.dll', 'WinHttpQueryOption', {
    onEnter(a) { this.opt = a[1].toUInt32(); this.buf = a[2]; this.pLen = a[3]; this.hReq = a[0]; },
    onLeave(r) {
      try {
        const name = WHOPT[this.opt] || ('0x' + this.opt.toString(16));
        const out = this.pLen.isNull() ? 0 : this.pLen.readU32();
        let extra = '';
        if (this.opt === 31 && out >= 4) extra = ' value=' + decFlags(this.buf.readU32());
        if (this.opt === 78) extra = ' CERT_CONTEXT=' + this.buf.readPointer() + '  <<< server cert fetched (pinning candidate)';
        if (this.opt === 32) extra = '  <<< certificate struct read (pinning candidate)';
        console.log('[TLS] WinHttpQueryOption ' + name + ' (opt=' + this.opt + ') out=' + out + ' ret=' + r.toUInt32() + extra);
      } catch (e) {}
    }
  });

  h('crypt32.dll', 'CertGetCertificateChain', {
    onEnter(a) { console.log('[TLS] CertGetCertificateChain enter'); }
  });
  h('crypt32.dll', 'CertVerifyChainPolicy', {
    onEnter(a) {
      let oid = '?';
      try { if (!a[0].isNull() && a[0].toUInt32() < 0x10000) oid = '#' + a[0].toUInt32(); else oid = a[0].readAnsiString(); } catch (e) {}
      console.log('[TLS] CertVerifyChainPolicy oid=' + oid);
    }
  });
  h('crypt32.dll', 'CertCreateCertificateContext', { onEnter(a) { console.log('[TLS] CertCreateCertificateContext len=' + a[2].toUInt32()); } });
  h('crypt32.dll', 'CertCompareCertificate',         { onEnter(a) { console.log('[TLS] CertCompareCertificate'); } });

  h('bcrypt.dll', 'BCryptVerifySignature',           { onEnter(a) { console.log('[TLS] BCryptVerifySignature hLen=' + a[3].toUInt32() + ' sigLen=' + a[5].toUInt32()); } });
  h('bcrypt.dll', 'BCryptImportKeyPair',             { onEnter(a) { try { console.log('[TLS] BCryptImportKeyPair blobType="' + a[2].readUtf16String() + '" len=' + a[5].toUInt32()); } catch (e) {} } });

  console.log('[TLS] tlscheck armed in pid ' + P);
})();
