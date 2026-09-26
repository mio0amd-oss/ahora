/**
 * Single-IP admin lock for the Ahura admin area.
 *
 * IMPORTANT: this middleware must run on the server, never in browser-only code.
 * It allows one client IP to hold the admin lock at a time. A different IP is
 * rejected until the lock expires or the current IP releases it.
 */
export function createAdminIpLock({ ttlMs = 30 * 60 * 1000, paths = ['/admin.html', '/ar/admin.html'] } = {}) {
  let activeIp = null;
  let expiresAt = 0;

  const normalizeIp = (value) => String(value || '').trim().replace(/^::ffff:/, '');
  const isProtected = (path) => paths.includes(path);

  return function adminIpLock(req, res, next) {
    if (!isProtected(req.path)) return next();

    const now = Date.now();
    const ip = normalizeIp(req.ip);

    if (!ip) return res.status(403).send('Admin access denied.');

    if (!activeIp || now >= expiresAt) {
      activeIp = ip;
      expiresAt = now + ttlMs;
      res.setHeader('X-Ahura-Admin-Lock', 'claimed');
      return next();
    }

    if (activeIp !== ip) {
      res.status(423).type('text/plain').send('Admin is currently locked to another IP address.');
      return;
    }

    // Refresh the lease while the current IP is using the admin page.
    expiresAt = now + ttlMs;
    res.setHeader('X-Ahura-Admin-Lock', 'active');
    return next();
  };
}
