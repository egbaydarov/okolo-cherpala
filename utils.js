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

  // Date helpers (UTC-oriented)
  AppNS.pad2 = function pad2(n) { return String(n).padStart(2, '0'); };

  AppNS.formatUtcForInput = function formatUtcForInput(d) {
    try {
      const y = d.getUTCFullYear();
      const m = AppNS.pad2(d.getUTCMonth() + 1);
      const day = AppNS.pad2(d.getUTCDate());
      const hh = AppNS.pad2(d.getUTCHours());
      const mm = AppNS.pad2(d.getUTCMinutes());
      return `${y}-${m}-${day} ${hh}:${mm}`;
    } catch (_) { return ''; }
  };

  AppNS.parseDateInputToUnix = function parseDateInputToUnix(input, opts) {
    try {
      if (!input) return null;
      const s = String(input).trim();
      if (!s) return null;
      if (/^\d{10}$/.test(s)) { return Number(s); }
      if (/^\d{13}$/.test(s)) { return Math.floor(Number(s) / 1000); }
      // If ISO-like without timezone, assume UTC by appending Z
      if (/^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?$/.test(s) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(s)) {
        const ms = Date.parse(s.replace(' ', 'T') + 'Z');
        if (!Number.isNaN(ms)) return Math.floor(ms / 1000);
      }
      const ms = Date.parse(s);
      if (!Number.isNaN(ms)) return Math.floor(ms / 1000);
    } catch (_) {}
    return null;
  };

  AppNS.getLastRangeUnix = function getLastRangeUnix(kind) {
    const now = new Date();
    const to = Math.floor(now.getTime() / 1000);
    const fromDate = new Date(now.getTime());
    if (kind === 'day') fromDate.setUTCDate(fromDate.getUTCDate() - 1);
    else if (kind === 'week') fromDate.setUTCDate(fromDate.getUTCDate() - 7);
    else if (kind === 'month') fromDate.setUTCMonth(fromDate.getUTCMonth() - 1);
    const from = Math.floor(fromDate.getTime() / 1000);
    return { from, to };
  };
})();


