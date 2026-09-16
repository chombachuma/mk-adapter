/**
 * MediKredit Adapter v3 — mTLS SOAP proxy (test + PRODUCTION identities) + SFTP ERA collector.
 * Deploy to Railway (service: mk-adapter-production).
 *
 * v3.1 (15 Sep 2026): Basic-Auth may be supplied by the CALLER (Authorization header) — production username/password
 *   live in the Base44 app's secrets, not here. The adapter only needs the client certificate for an identity to be usable.
 * v3 (15 Sep 2026): production identity, chosen by target host. v2 (15 Sep): SFTP ERA.
 * The request/response contract of POST / is unchanged since v1 — every Base44 function keeps working.
 *
 * ┌──────────┐   HTTPS + X-Adapter-Secret   ┌──────────────┐   mTLS + BasicAuth   ┌────────────────────────────┐
 * │  Base44  │ ───────────────────────────► │  Railway     │ ───────────────────► │ test-services-ccert  (TEST) │
 * │ Function │  { target_url, body, ... }   │  Adapter     │  identity chosen by  │ prod-services-ccert  (PROD) │
 * │          │                              │  (static IP) │  target hostname     └────────────────────────────┘
 * │          │                              │              │   SFTP :22           ┌────────────────────────────┐
 * └──────────┘                              └──────────────┘ ───────────────────► │ sftp.medikredit.co.za  ERA │
 *                                                                                 └────────────────────────────┘
 *
 * ── Environment variables (Railway → Variables). Secrets live HERE and nowhere else. ──
 *
 *   ADAPTER_SECRET                      shared secret; Base44 sends it as X-Adapter-Secret
 *
 *   TEST identity (unchanged names from v1):
 *   MEDIKREDIT_USERNAME / MEDIKREDIT_PASSWORD           Basic Auth for test-services-ccert
 *   MEDIKREDIT_CLIENT_PFX_B64 / MEDIKREDIT_CLIENT_PASSPHRASE   test client certificate (PFX)
 *
 *   PRODUCTION identity (new in v3) — EITHER the PEM pair OR the PFX; PEM pair preferred
 *   because MediKredit's .key is an unencrypted PKCS#8 key, so no passphrase is needed:
 *   MEDIKREDIT_PROD_USERNAME / MEDIKREDIT_PROD_PASSWORD  Basic Auth for prod-services-ccert
 *   MEDIKREDIT_PROD_CLIENT_CERT_B64                      ccert.medikredit.co.za.pem  (base64 of the file, or the raw PEM)
 *   MEDIKREDIT_PROD_CLIENT_KEY_B64                       ccert.medikredit.co.za.key  (base64 of the file, or the raw PEM)
 *   MEDIKREDIT_PROD_CA_B64                               origin_ca_rsa_root.pem (optional; used when MK_TLS_STRICT=1)
 *     — or —
 *   MEDIKREDIT_PROD_CLIENT_PFX_B64 / MEDIKREDIT_PROD_CLIENT_PASSPHRASE
 *
 *   MK_TLS_STRICT                       "1" to verify MediKredit's server certificate (default: off, as v1)
 *
 *   SFTP (v2):
 *   MK_SFTP_HOST=sftp.medikredit.co.za  MK_SFTP_PORT=22  MK_SFTP_USER=LIGHTHOUSE_ISCRIPT
 *   MK_SFTP_PASSWORD                    MK_SFTP_ERA_PATH=outgoing/era   MK_SFTP_HOST_KEY (pin after first /sftp/health)
 *
 * ── API (all need X-Adapter-Secret except GET /health) ──
 *   GET  /health                 versions, which identities are loaded (never the values), cert expiry dates
 *   POST /                       SOAP proxy. Body { target_url, method, headers, body }. Identity = by target host.
 *   GET  /mtls/probe?env=production|test   certificate + whitelisting probe. Creates NO MediKredit transaction.
 *   GET  /sftp/health            SFTP connect + auth only
 *   POST /sftp/era/list          listing (operator use only — may count as a "touch")
 *   POST /sftp/era/collect       list once → download everything listed → return bytes
 *
 * ── Identity selection ──
 *   hostname contains "prod-services"  → PRODUCTION identity. If it is not fully configured the call is
 *                                        REFUSED (status 0, error PRODUCTION_IDENTITY_NOT_CONFIGURED).
 *                                        It never falls back to the test certificate.
 *   anything else                      → TEST identity.
 */

const http = require('http');
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const SftpClient = require('ssh2-sftp-client');

const ADAPTER_SECRET = process.env.ADAPTER_SECRET || '';
const PORT = process.env.PORT || 3000;
const TLS_STRICT = process.env.MK_TLS_STRICT === '1';

if (!ADAPTER_SECRET) {
  console.error('FATAL: ADAPTER_SECRET environment variable is required');
  process.exit(1);
}

// ── helpers ──────────────────────────────────────────────────────────────────
function json(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}
async function readBody(req) {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  if (!raw) return {};
  return JSON.parse(raw);
}
function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

/** Accept a PEM either raw or base64-encoded; return a Buffer or null. */
function pemFromEnv(value) {
  if (!value) return null;
  const v = String(value).trim();
  if (v.includes('-----BEGIN')) return Buffer.from(v.replace(/\\n/g, '\n'), 'utf8');
  try {
    const decoded = Buffer.from(v, 'base64');
    if (decoded.toString('utf8').includes('-----BEGIN')) return decoded;
  } catch { /* not base64 */ }
  return null;
}
function bufFromB64(value) {
  if (!value) return null;
  try { const b = Buffer.from(String(value).trim(), 'base64'); return b.length ? b : null; } catch { return null; }
}
function certInfo(pemBuf) {
  try {
    const c = new crypto.X509Certificate(pemBuf);
    return { subject: c.subject.replace(/\n/g, ', '), issuer: c.issuer.replace(/\n/g, ', '), valid_from: c.validFrom, valid_to: c.validTo,
      days_to_expiry: Math.floor((new Date(c.validTo) - Date.now()) / 86400000), fingerprint256: c.fingerprint256 };
  } catch (e) { return { error: 'could not parse certificate: ' + e.message }; }
}

// ── identities ───────────────────────────────────────────────────────────────
function loadIdentity(name, env) {
  const id = { name, username: env.username || '', password: env.password || '', pfx: null, passphrase: env.passphrase || '', cert: null, key: null, ca: null, source: null, complete: false, problems: [] };
  id.cert = pemFromEnv(env.certPem);
  id.key = pemFromEnv(env.keyPem);
  id.ca = pemFromEnv(env.caPem);
  if (id.cert && id.key) id.source = 'pem';
  else {
    id.pfx = bufFromB64(env.pfxB64);
    if (id.pfx) id.source = 'pfx';
  }
  if (!id.source) id.problems.push('no client certificate (need CERT+KEY PEM, or PFX)');
  id.has_credentials = !!(id.username && id.password);
  if (!id.has_credentials) id.notes = ['no Basic-Auth username/password on the adapter — the caller must send an Authorization header'];
  // v3.1: "complete" = the certificate is usable. Credentials may come from the caller per request.
  id.complete = id.problems.length === 0;
  return id;
}
const IDENTITIES = {
  test: loadIdentity('test', {
    username: process.env.MEDIKREDIT_USERNAME, password: process.env.MEDIKREDIT_PASSWORD,
    pfxB64: process.env.MEDIKREDIT_CLIENT_PFX_B64, passphrase: process.env.MEDIKREDIT_CLIENT_PASSPHRASE || 'testpass123',
    certPem: process.env.MEDIKREDIT_CLIENT_CERT_B64, keyPem: process.env.MEDIKREDIT_CLIENT_KEY_B64,
  }),
  production: loadIdentity('production', {
    username: process.env.MEDIKREDIT_PROD_USERNAME, password: process.env.MEDIKREDIT_PROD_PASSWORD,
    pfxB64: process.env.MEDIKREDIT_PROD_CLIENT_PFX_B64, passphrase: process.env.MEDIKREDIT_PROD_CLIENT_PASSPHRASE || '',
    certPem: process.env.MEDIKREDIT_PROD_CLIENT_CERT_B64, keyPem: process.env.MEDIKREDIT_PROD_CLIENT_KEY_B64,
    caPem: process.env.MEDIKREDIT_PROD_CA_B64,
  }),
};
function identityForHost(hostname) {
  return /prod-services/i.test(String(hostname || '')) ? IDENTITIES.production : IDENTITIES.test;
}
function tlsOptionsFor(id) {
  const o = { rejectUnauthorized: TLS_STRICT };
  if (id.source === 'pem') { o.cert = id.cert; o.key = id.key; }
  else if (id.source === 'pfx') { o.pfx = id.pfx; o.passphrase = id.passphrase; }
  if (TLS_STRICT && id.ca) o.ca = [id.ca];
  return o;
}
function identitySummary(id) {
  return {
    configured: id.complete, source: id.source, problems: id.problems, notes: id.notes || [],
    username_set: !!id.username, credentials_mode: id.has_credentials ? 'adapter' : 'caller-supplied',
    certificate: id.source === 'pem' ? certInfo(id.cert) : (id.source === 'pfx' ? { note: 'PFX loaded (' + id.pfx.length + ' bytes); dates not parsed' } : null),
  };
}
for (const k of Object.keys(IDENTITIES)) {
  const id = IDENTITIES[k];
  console.log(`[adapter] identity ${k}: ${id.complete ? 'OK (' + id.source + ', credentials: ' + (id.has_credentials ? 'adapter' : 'caller-supplied') + ')' : 'INCOMPLETE — ' + id.problems.join('; ')}`);
}

// ── SFTP ─────────────────────────────────────────────────────────────────────
const SFTP = {
  host: process.env.MK_SFTP_HOST || '', port: Number(process.env.MK_SFTP_PORT || 22),
  username: process.env.MK_SFTP_USER || '', password: process.env.MK_SFTP_PASSWORD || '',
  eraPath: (process.env.MK_SFTP_ERA_PATH || 'outgoing/era').replace(/^\/+|\/+$/g, ''),
  hostKey: process.env.MK_SFTP_HOST_KEY || '',
};
const SFTP_CONFIGURED = !!(SFTP.host && SFTP.username && SFTP.password);
if (!SFTP_CONFIGURED) console.warn('[adapter] SFTP not configured — ERA collection disabled');

async function sftpConnect(captureHostKey) {
  if (!SFTP_CONFIGURED) { const e = new Error('SFTP is not configured (MK_SFTP_HOST / MK_SFTP_USER / MK_SFTP_PASSWORD).'); e.code = 'SFTP_NOT_CONFIGURED'; throw e; }
  const client = new SftpClient('mk-era');
  await client.connect({
    host: SFTP.host, port: SFTP.port, username: SFTP.username, password: SFTP.password,
    readyTimeout: 20000, retries: 1, tryKeyboard: false,
    hostVerifier: (keyHash) => {
      if (captureHostKey) captureHostKey(String(keyHash));
      if (!SFTP.hostKey) return true;
      const ok = String(keyHash).trim() === SFTP.hostKey.trim();
      if (!ok) console.error(`[sftp] HOST KEY MISMATCH: got ${keyHash}, expected ${SFTP.hostKey}`);
      return ok;
    },
  });
  return client;
}
async function resolveEraDir(client) {
  const candidates = [SFTP.eraPath, '/' + SFTP.eraPath, `/${SFTP.username}/${SFTP.eraPath}`, `${SFTP.username}/${SFTP.eraPath}`];
  for (const c of candidates) { try { if ((await client.exists(c)) === 'd') return c; } catch { /* next */ } }
  const e = new Error(`ERA directory not found. Tried: ${candidates.join(', ')}`); e.code = 'ERA_DIR_NOT_FOUND'; throw e;
}

// ── mTLS probe (no transaction is created) ───────────────────────────────────
function httpsRequest(id, urlStr, method, headers, body, timeoutMs = 20000) {
  return new Promise((resolve) => {
    const u = new URL(urlStr);
    const agent = new https.Agent(tlsOptionsFor(id));
    const bodyBytes = Buffer.from(body || '', 'utf8');
    const h = { ...headers };
    if (method === 'POST') h['Content-Length'] = bodyBytes.length;
    const t0 = Date.now();
    const req = https.request({ hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method, agent, headers: h }, (r) => {
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        const peer = r.socket && r.socket.getPeerCertificate ? r.socket.getPeerCertificate() : null;
        resolve({ ok: true, status: r.statusCode, headers: { server: r.headers.server, 'cf-ray': r.headers['cf-ray'], 'www-authenticate': r.headers['www-authenticate'] },
          body_head: text.slice(0, 400), latency_ms: Date.now() - t0, tls_authorized: r.socket ? r.socket.authorized : undefined,
          server_cert_subject: peer && peer.subject ? peer.subject.CN : undefined });
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve({ ok: false, error: 'timeout after ' + timeoutMs + 'ms', latency_ms: Date.now() - t0 }); });
    req.on('error', (e) => resolve({ ok: false, error: e.message, code: e.code, latency_ms: Date.now() - t0 }));
    if (method === 'POST') req.write(bodyBytes);
    req.end();
  });
}
function interpretProbe(steps) {
  const notes = [];
  const hs = steps.tls_handshake;
  if (hs && !hs.ok) {
    if (/certificate|handshake|alert|ECONNRESET/i.test(hs.error || '')) notes.push('TLS handshake failed — the client certificate/key was not accepted, or the server closed the connection during the handshake. Check the certificate files and passphrase.');
    else notes.push('TLS connection failed: ' + hs.error);
    return { verdict: 'CERTIFICATE_OR_NETWORK_PROBLEM', notes };
  }
  const g = steps.https_get_no_auth;
  if (g && g.ok && g.status === 403 && /cloudflare|error code: 10|access denied/i.test(g.body_head + ' ' + (g.headers.server || ''))) {
    notes.push('HTTP 403 from Cloudflare on a plain GET — our egress IP appears to be BLOCKED. IP whitelisting IS required for this host.');
    return { verdict: 'IP_WHITELISTING_REQUIRED', notes };
  }
  const p = steps.https_post_with_auth;
  if (p && p.ok) {
    if (p.status === 401) { notes.push('Certificate accepted (we got past TLS) but Basic-Auth was refused (401). Check username/password for this environment.'); return { verdict: 'BASIC_AUTH_REJECTED', notes }; }
    if (p.status === 403) { notes.push('403 after authentication — likely IP whitelisting or an access rule on the ccert path.'); return { verdict: 'FORBIDDEN_CHECK_WHITELISTING', notes }; }
    if (p.status >= 200 && p.status < 600) { notes.push(`Reached the S2PI endpoint with certificate and credentials (HTTP ${p.status} on an intentionally empty SOAP body — a fault here is expected and harmless). No IP whitelisting problem, certificate accepted, credentials accepted.`); return { verdict: 'ENDPOINT_REACHABLE_READY', notes }; }
  }
  notes.push('Inconclusive — see steps.');
  return { verdict: 'INCONCLUSIVE', notes };
}

// ── HTTP server ──────────────────────────────────────────────────────────────

// ── Egress IP self-check (v3.1.2) ─────────────────────────────────────────────
// MediKredit's Cloudflare allowlists by source IP. Railway Static Outbound IPs are enabled on
// this service; these are the three addresses handed to MediKredit on 16 Sep 2026.
const EGRESS_ALLOWLIST = (process.env.EGRESS_ALLOWLIST || '162.220.232.250,152.55.177.181,152.55.177.192').split(',').map(s => s.trim()).filter(Boolean);
let _egressCache = { ip: null, ok: null, checked_at: null, at: 0 };
function getEgressInfo() {
  if (Date.now() - _egressCache.at < 5 * 60 * 1000) return Promise.resolve(_egressCache);
  return new Promise((resolve) => {
    const req = https.get('https://api.ipify.org?format=json', { timeout: 5000 }, (r) => {
      let b = ''; r.on('data', c => b += c); r.on('end', () => {
        let ip = null; try { ip = JSON.parse(b).ip || null; } catch (_) {}
        _egressCache = { ip, ok: ip ? EGRESS_ALLOWLIST.includes(ip) : null, checked_at: new Date().toISOString(), at: Date.now() };
        if (ip && !EGRESS_ALLOWLIST.includes(ip)) console.error(`[adapter] EGRESS DRIFT: outbound IP ${ip} is not in the MediKredit allowlist ${EGRESS_ALLOWLIST.join(',')}`);
        resolve(_egressCache);
      });
    });
    req.on('error', () => resolve({ ..._egressCache, checked_at: new Date().toISOString() }));
    req.on('timeout', () => { req.destroy(); resolve({ ..._egressCache, checked_at: new Date().toISOString() }); });
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Adapter-Secret, X-MK-Authorization, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname.replace(/\/+$/, '') || '/';

  if (req.method === 'GET' && path === '/health') {
    // v3.1.2: report the live egress IP against the IPs whitelisted at MediKredit (Railway static egress).
    const egress = await getEgressInfo();
    return json(res, 200, {
      ok: true, version: 3, adapter_version: '3.1.2', tls_strict: TLS_STRICT,
      egress_ip: egress.ip, egress_allowlist: EGRESS_ALLOWLIST, egress_allowlist_ok: egress.ok, egress_checked_at: egress.checked_at,
      identities: { test: identitySummary(IDENTITIES.test), production: identitySummary(IDENTITIES.production) },
      // v1/v2 fields kept for existing health checks
      pfx_loaded: !!IDENTITIES.test.source, has_credentials: !!IDENTITIES.test.username,
      sftp_configured: SFTP_CONFIGURED, sftp_host: SFTP_CONFIGURED ? SFTP.host : null, sftp_era_path: SFTP_CONFIGURED ? SFTP.eraPath : null,
    });
  }

  // v3.1.1: accept the primary secret or the engine's alternate secret (ADAPTER_SECRET_ALT).
  // The previous adapter (v3.3.1) only LOGGED mismatches, so the engine has been sending a
  // different value than Railway's ADAPTER_SECRET since July. Until the two are consolidated,
  // both are accepted. Mismatch logging is fingerprint-only (sha256 prefix), never the value.
  const incomingSecret = String(req.headers['x-adapter-secret'] || '').trim().replace(/^<|>$/g, '');
  const ACCEPTED = [ADAPTER_SECRET, process.env.ADAPTER_SECRET_ALT || ''].filter(Boolean);
  if (!ACCEPTED.includes(incomingSecret)) {
    const fp = incomingSecret ? crypto.createHash('sha256').update(incomingSecret).digest('hex').slice(0, 12) : 'NONE';
    console.warn(`[adapter] Unauthorized ${req.method} ${path} secret_fp=${fp} len=${incomingSecret.length} prefix=${incomingSecret.slice(0, 6)}`);
    if (process.env.ADAPTER_SECRET_DEBUG === '1') console.warn(`[adapter] TEMP-DEBUG incoming secret: ${incomingSecret}`);
    return json(res, 401, { error: 'Unauthorized — invalid adapter secret' });
  }

  // ═══════════ mTLS probe ═══════════
  if (req.method === 'GET' && path === '/mtls/probe') {
    const envName = url.searchParams.get('env') === 'production' ? 'production' : 'test';
    const id = IDENTITIES[envName];
    const base = envName === 'production' ? 'https://prod-services-ccert.medikredit.co.za/live/ws2pint/' : 'https://test-services-ccert.medikredit.co.za/ws2pint/';
    const target = url.searchParams.get('target_url') || base;
    const u = new URL(target);
    const steps = { identity: identitySummary(id) };
    if (!id.complete) return json(res, 200, { env: envName, target, steps, verdict: 'IDENTITY_NOT_CONFIGURED', notes: id.problems });

    // 1. Raw TLS handshake with the client certificate
    steps.tls_handshake = await new Promise((resolve) => {
      const t0 = Date.now();
      const s = tls.connect({ host: u.hostname, port: Number(u.port || 443), servername: u.hostname, ...tlsOptionsFor(id) }, () => {
        const peer = s.getPeerCertificate();
        resolve({ ok: true, authorized: s.authorized, authorization_error: s.authorizationError ? String(s.authorizationError) : undefined,
          protocol: s.getProtocol(), server_cert_subject: peer && peer.subject ? peer.subject.CN : undefined, server_cert_issuer: peer && peer.issuer ? peer.issuer.O : undefined,
          server_cert_valid_to: peer ? peer.valid_to : undefined, latency_ms: Date.now() - t0 });
        s.end();
      });
      s.setTimeout(15000, () => { s.destroy(); resolve({ ok: false, error: 'TLS handshake timeout', latency_ms: Date.now() - t0 }); });
      s.on('error', (e) => resolve({ ok: false, error: e.message, code: e.code, latency_ms: Date.now() - t0 }));
    });
    // 2. Plain GET, no Basic-Auth — a Cloudflare IP block shows here as 403
    steps.https_get_no_auth = await httpsRequest(id, target, 'GET', {}, '');
    // 3. POST with Basic-Auth and an EMPTY SOAP body — proves auth + routing; MediKredit returns a fault, creates nothing
    // v3.1: the caller may forward its own Basic-Auth (X-MK-Authorization or Authorization); adapter creds are the fallback
    const callerAuth = req.headers['x-mk-authorization'] || (req.headers['authorization'] && /^Basic /i.test(req.headers['authorization']) ? req.headers['authorization'] : null);
    const auth = callerAuth || (id.has_credentials ? 'Basic ' + Buffer.from(`${id.username}:${id.password}`).toString('base64') : null);
    steps.credentials_source = callerAuth ? 'caller' : (auth ? 'adapter' : 'none');
    if (!auth) {
      steps.https_post_with_auth = { skipped: true, reason: 'no Basic-Auth available (adapter has none and caller sent none)' };
      const partial = interpretProbe({ ...steps, https_post_with_auth: { ok: true, status: 401 } });
      const verdictNoAuth = partial.verdict === 'BASIC_AUTH_REJECTED' ? { verdict: 'BASIC_AUTH_MISSING', notes: ['Certificate and network are fine, but no Basic-Auth was available. Set MEDIKREDIT_PROD_USERNAME/PASSWORD in the Base44 app secrets so the caller forwards them (X-MK-Authorization).'] } : partial;
      return json(res, 200, { env: envName, target, egress_note: 'Requests leave from this Railway service\'s static egress IP.', ...verdictNoAuth, steps });
    }
    steps.https_post_with_auth = await httpsRequest(id, target, 'POST', { Authorization: auth, 'Content-Type': 'text/xml; charset=utf-8', SOAPAction: '""' }, '');
    const verdict = interpretProbe(steps);
    return json(res, 200, { env: envName, target, egress_note: 'Requests leave from this Railway service\'s static egress IP.', ...verdict, steps });
  }

  // ═══════════ SFTP ═══════════
  if (req.method === 'GET' && path === '/sftp/health') {
    const t0 = Date.now(); let client; let seen = null;
    try {
      client = await sftpConnect((k) => { seen = k; });
      const cwd = await client.cwd(); await client.end();
      return json(res, 200, { ok: true, host: SFTP.host, port: SFTP.port, username: SFTP.username, login_directory: cwd, server_host_key: seen, host_key_pinned: !!SFTP.hostKey, latency_ms: Date.now() - t0,
        note: 'Connected and authenticated. No directory listed, no file touched. Pin server_host_key as MK_SFTP_HOST_KEY.' });
    } catch (e) {
      if (client) client.end().catch(() => {});
      return json(res, 200, { ok: false, error: e.code || 'SFTP_CONNECT_FAILED', message: e.message, host: SFTP.host, port: SFTP.port, username: SFTP.username || null, latency_ms: Date.now() - t0 });
    }
  }
  if (req.method === 'POST' && path === '/sftp/era/list') {
    let client;
    try {
      client = await sftpConnect(); const dir = await resolveEraDir(client); const entries = await client.list(dir); await client.end();
      return json(res, 200, { ok: true, directory: dir,
        file_count: entries.filter((e) => e.type === '-').length,
        files: entries.filter((e) => e.type === '-').map((e) => ({ name: e.name, size: e.size, modified: new Date(e.modifyTime).toISOString() })),
        subdirectories: entries.filter((e) => e.type === 'd').map((e) => e.name),
        warning: 'MediKredit has not confirmed whether a listing counts as "touching" a file. Use /sftp/era/collect for anything other than a look.' });
    } catch (e) { if (client) client.end().catch(() => {}); return json(res, 200, { ok: false, error: e.code || 'SFTP_LIST_FAILED', message: e.message }); }
  }
  if (req.method === 'POST' && path === '/sftp/era/collect') {
    let body = {}; try { body = await readBody(req); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }
    const maxFiles = Math.min(Math.max(Number(body.max_files || 50), 1), 200);
    const namePattern = body.name_pattern ? new RegExp(body.name_pattern, 'i') : null;
    const t0 = Date.now(); let client; const collected = []; const failed = []; let dir = null; let listed = [];
    try {
      client = await sftpConnect(); dir = await resolveEraDir(client);
      const entries = await client.list(dir);                       // ONE listing
      listed = entries.filter((e) => e.type === '-').map((e) => ({ name: e.name, size: e.size, modified: new Date(e.modifyTime).toISOString() }));
      console.log(`[sftp] ${dir}: ${listed.length} file(s) listed`);
      const targets = listed.filter((f) => !namePattern || namePattern.test(f.name)).slice(0, maxFiles);
      for (const f of targets) {                                    // then EVERY file, sequentially, same session
        try {
          const buf = await client.get(`${dir}/${f.name}`); const bytes = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
          collected.push({ name: f.name, size: bytes.length, modified: f.modified, sha256: sha256(bytes), content_b64: bytes.toString('base64'),
            looks_like_xml: /^\s*<\?xml|^\s*<MkEra/i.test(bytes.slice(0, 200).toString('utf8')) });
          console.log(`[sftp] downloaded ${f.name} (${bytes.length} bytes)`);
        } catch (e) { console.error(`[sftp] download FAILED ${f.name}: ${e.message}`); failed.push({ name: f.name, size: f.size, error: e.message }); }
      }
      await client.end();
    } catch (e) {
      if (client) client.end().catch(() => {});
      return json(res, 200, { ok: false, error: e.code || 'SFTP_COLLECT_FAILED', message: e.message, directory: dir, listed, collected, failed,
        warning: collected.length ? `${collected.length} file(s) WERE downloaded before the failure and are returned above. PERSIST THEM.` : undefined, latency_ms: Date.now() - t0 });
    }
    return json(res, 200, { ok: failed.length === 0, directory: dir, listed_count: listed.length, collected_count: collected.length, failed_count: failed.length,
      skipped_by_limit: Math.max(0, listed.filter((f) => !namePattern || namePattern.test(f.name)).length - maxFiles), listed, files: collected, failed, latency_ms: Date.now() - t0,
      order_of_operations: 'one listing → every listed file downloaded in the same session → returned to caller, who persists raw bytes BEFORE parsing. Nothing on the server is moved, renamed or deleted.' });
  }

  // ═══════════ SOAP proxy (contract unchanged since v1) ═══════════
  if (req.method !== 'POST' || path !== '/') {
    return json(res, 404, { error: 'Not found', routes: ['GET /health', 'POST /', 'GET /mtls/probe?env=production|test', 'GET /sftp/health', 'POST /sftp/era/list', 'POST /sftp/era/collect'] });
  }
  let payload; try { payload = await readBody(req); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }

  const targetUrl = payload.target_url || 'https://test-services-ccert.medikredit.co.za/ws2pint/';
  const method = payload.method || 'POST';
  const soapBody = payload.body || '';
  const urlObj = new URL(targetUrl);
  const id = identityForHost(urlObj.hostname);

  // Production is refused unless its identity is complete — never fall back to the test certificate.
  if (id.name === 'production' && !id.complete) {
    console.error(`[adapter] REFUSED production call to ${urlObj.hostname}: identity incomplete (${id.problems.join('; ')})`);
    return json(res, 200, { status: 0, body: '', error: 'PRODUCTION_IDENTITY_NOT_CONFIGURED: ' + id.problems.join('; '), target_url: targetUrl, identity: 'production' });
  }

  const headers = { ...(payload.headers || {}) };
  // Normalise header casing so a caller-supplied 'authorization' is recognised
  for (const k of Object.keys(headers)) if (k.toLowerCase() === 'authorization' && k !== 'Authorization') { headers['Authorization'] = headers[k]; delete headers[k]; }
  if (!headers['Authorization'] && id.has_credentials) headers['Authorization'] = 'Basic ' + Buffer.from(`${id.username}:${id.password}`).toString('base64');
  if (!headers['Authorization']) {
    console.error(`[adapter] REFUSED ${id.name} call to ${urlObj.hostname}: no Basic-Auth (adapter has none, caller sent none)`);
    return json(res, 200, { status: 0, body: '', error: (id.name === 'production' ? 'PRODUCTION_BASIC_AUTH_MISSING' : 'BASIC_AUTH_MISSING') + ': the adapter holds no username/password for this identity and the caller did not send an Authorization header', target_url: targetUrl, identity: id.name });
  }
  if (!headers['Content-Type']) headers['Content-Type'] = 'text/xml; charset=utf-8';
  const bodyBytes = Buffer.from(soapBody, 'utf8');
  headers['Content-Length'] = bodyBytes.length;

  console.log(`[adapter] ${id.name.toUpperCase()} ${method} → ${targetUrl} (${bodyBytes.length} bytes)`);
  const agent = new https.Agent(tlsOptionsFor(id));
  const startTime = Date.now();
  const mkRequest = https.request({ hostname: urlObj.hostname, port: urlObj.port || 443, path: urlObj.pathname + urlObj.search, method, agent, headers }, (mkResponse) => {
    const chunks = [];
    mkResponse.on('data', (c) => chunks.push(c));
    mkResponse.on('end', () => {
      const responseBody = Buffer.concat(chunks).toString('utf8');
      const latency = Date.now() - startTime;
      console.log(`[adapter] ${id.name.toUpperCase()} MediKredit responded: HTTP ${mkResponse.statusCode} in ${latency}ms`);
      json(res, 200, { status: mkResponse.statusCode, body: responseBody, latency_ms: latency, target_url: targetUrl, identity: id.name });
    });
  });
  mkRequest.setTimeout(30000, () => { mkRequest.destroy(); console.error('[adapter] MediKredit request timed out'); json(res, 200, { status: 0, body: '', error: 'MediKredit request timed out (30s)', identity: id.name }); });
  mkRequest.on('error', (e) => { console.error('[adapter] MediKredit request error:', e.message); json(res, 200, { status: 0, body: '', error: e.message, identity: id.name }); });
  mkRequest.write(bodyBytes);
  mkRequest.end();
});

server.listen(PORT, () => {
  console.log(`[adapter] MediKredit adapter v3.1 listening on port ${PORT}`);
  console.log(`[adapter] TEST identity: ${IDENTITIES.test.complete ? 'ready' : 'INCOMPLETE'} | PRODUCTION identity: ${IDENTITIES.production.complete ? 'ready' : 'INCOMPLETE'} | TLS strict: ${TLS_STRICT}`);
  console.log(`[adapter] SFTP: ${SFTP_CONFIGURED ? `${SFTP.username}@${SFTP.host}:${SFTP.port}/${SFTP.eraPath}` : 'NOT CONFIGURED'}`);
});
