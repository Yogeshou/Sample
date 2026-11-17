// SSRF guard for webhook targets.
const dns = require('dns').promises;
const net = require('net');

const BLOCKED_HOSTNAMES = new Set(['localhost', 'metadata.google.internal', 'metadata']);

function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) || // CGNAT
      (a === 169 && b === 254) ||            // link-local / cloud metadata
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224                                // multicast / reserved
    );
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v.startsWith('::ffff:')) return isPrivateAddress(v.slice(7));
    return v === '::' || v === '::1' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
  }
  return true; // unknown format -> deny
}

// Static checks at registration time.
function validateWebhookUrl(raw, { allowInsecure }) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return 'url must be a valid absolute URL';
  }
  const allowed = allowInsecure ? ['https:', 'http:'] : ['https:'];
  if (!allowed.includes(u.protocol)) return 'url must use https';
  if (u.username || u.password) return 'url must not contain credentials';
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith('.internal') || host.endsWith('.local')) {
    return 'url host is not allowed';
  }
  if (net.isIP(host) && isPrivateAddress(host)) return 'url host is not allowed';
  return null;
}

// Dynamic check right before dispatch: every resolved address must be public.
// NOTE: residual DNS-rebinding TOCTOU remains; egress NetworkPolicy is the backstop.
async function assertPublicDestination(raw) {
  const host = new URL(raw).hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (addrs.length === 0 || addrs.some(a => isPrivateAddress(a.address))) {
    throw new Error('destination resolves to a non-public address');
  }
}

module.exports = { validateWebhookUrl, assertPublicDestination, isPrivateAddress };
