(() => {
  window.App = window.App || {};
  const AppNS = window.App;

  // Logging utility
  AppNS.log = function log(...args) {
    try {
      const { log: $log } = AppNS.dom || {};
      const line = args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ');
      if ($log) {
        $log.textContent += line + "\n";
        $log.scrollTop = $log.scrollHeight;
      }
      // eslint-disable-next-line no-console
      console.log(...args);
    } catch (_) {}
  };

  // Safe conversions
  AppNS.bigIntToStringSafe = function bigIntToStringSafe(v) {
    try { return typeof v === 'bigint' ? v.toString() : String(v); } catch { return String(v); }
  };

  AppNS.toBigIntSafe = function toBigIntSafe(v) {
    try {
      if (typeof v === 'bigint') return v;
      if (typeof v === 'string') return BigInt(v);
      if (typeof v === 'number') return BigInt(v);
      if (v && typeof v === 'object' && typeof v.toString === 'function') return BigInt(v.toString());
    } catch {}
    return null;
  };

  AppNS.generateRandomBigInt64 = function generateRandomBigInt64() {
    const buf = new Uint8Array(8);
    (self.crypto || window.crypto).getRandomValues(buf);
    let out = 0n;
    for (let i = 0; i < 8; i++) {
      out |= BigInt(buf[i]) << (8n * BigInt(i));
    }
    return out;
  };

  AppNS.formatDate = function formatDate(ts) {
    try { return new Date((ts || 0) * 1000).toLocaleString(); } catch { return String(ts); }
  };
})();


