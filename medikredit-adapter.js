/**
 * MediKredit mTLS Proxy Adapter — Deploy this to Railway.
 *
 * This service acts as a middleman between Base44 (which can't do mTLS
 * and is IP-blocked by Cloudflare) and MediKredit's SOAP endpoint.
 *
 * ┌──────────┐     HTTPS      ┌──────────────┐    mTLS + BasicAuth    ┌────────────┐
 * │  Base44  │ ──────────────► │  Railway     │ ─────────────────────► │ MediKredit │
 * │ Function │  X-Adapter-     │  Adapter     │  PFX cert + creds      │ (ccert)    │
 * │          │  Secret auth    │  (static IP)  │ ◄───────────────────── │            │
 * └──────────┘                 └──────────────┘    SOAP response       └────────────┘
 *
 * ── Deploy to Railway ──
 * 1. Create a new Railway project from this repo (or copy this file)
 * 2. Set these environment variables on Railway:
 *    - ADAPTER_SECRET       : a random string (same as MK_ADAPTER_SECRET in Base44)
 *    - MEDIKREDIT_USERNAME  : eYVUqtNKSu
 *    - MEDIKREDIT_PASSWORD  : fGRp2mtGH86RrpdqwTBx
 *    - MEDIKREDIT_CLIENT_PFX_B64 : the base64-encoded PFX cert
 *    - MEDIKREDIT_CLIENT_PASSPHRASE : testpass123
 *    - PORT                 : 3000 (Railway sets this automatically)
 * 3. Deploy → Railway gives you a URL like https://iscript-mk-proxy.up.railway.app
 * 4. Set that URL as MEDIKREDIT_FORCE_IP_ENDPOINT in Base44 secrets
 *
 * ── API ──
 * POST /
 * Headers: X-Adapter-Secret: <ADAPTER_SECRET>
 * Body (JSON): { target_url, method, headers, body }
 * Response: { status, body, headers }
 */

const http = require('http');
const https = require('https');

const ADAPTER_SECRET = process.env.ADAPTER_SECRET || '';
const MK_USERNAME = process.env.MEDIKREDIT_USERNAME || '';
const MK_PASSWORD = process.env.MEDIKREDIT_PASSWORD || '';
const PFX_B64 = process.env.MEDIKREDIT_CLIENT_PFX_B64 || '';
const PFX_PASS = process.env.MEDIKREDIT_CLIENT_PASSPHRASE || 'testpass123';
const PORT = process.env.PORT || 3000;

if (!ADAPTER_SECRET) {
  console.error('FATAL: ADAPTER_SECRET environment variable is required');
  process.exit(1);
}

// Decode PFX from base64
let pfxBuffer = null;
if (PFX_B64) {
  try {
    pfxBuffer = Buffer.from(PFX_B64, 'base64');
    console.log(`[adapter] PFX cert loaded: ${pfxBuffer.length} bytes`);
  } catch (e) {
    console.error('[adapter] Failed to decode PFX:', e.message);
  }
} else {
  console.warn('[adapter] WARNING: MEDIKREDIT_CLIENT_PFX_B64 not set — mTLS will fail');
}

// ── HTTP server ──
const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Adapter-Secret');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Health check
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, pfx_loaded: !!pfxBuffer, has_credentials: !!MK_USERNAME }));
    return;
  }

  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  // Authenticate
  const adapterSecret = req.headers['x-adapter-secret'];
  if (adapterSecret !== ADAPTER_SECRET) {
    console.warn('[adapter] Unauthorized request — secret mismatch');
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized — invalid adapter secret' }));
    return;
  }

  // Read request body
  let rawBody = '';
  for await (const chunk of req) rawBody += chunk;

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (e) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    return;
  }

  const targetUrl = payload.target_url || 'https://test-services-ccert.medikredit.co.za/ws2pint/';
  const method = payload.method || 'POST';
  const soapBody = payload.body || '';

  // Merge provided headers with mandatory auth
  const headers = { ...(payload.headers || {}) };
  if (!headers['Authorization'] && MK_USERNAME) {
    headers['Authorization'] = 'Basic ' + Buffer.from(`${MK_USERNAME}:${MK_PASSWORD}`).toString('base64');
  }
  if (!headers['Content-Type']) {
    headers['Content-Type'] = 'text/xml; charset=utf-8';
  }
  const bodyBytes = Buffer.from(soapBody, 'utf8');
  headers['Content-Length'] = bodyBytes.length;

  console.log(`[adapter] Forwarding ${method} → ${targetUrl} (${bodyBytes.length} bytes)`);

  // Parse target URL
  const urlObj = new URL(targetUrl);

  // Create mTLS agent
  const agentOpts = { rejectUnauthorized: false };
  if (pfxBuffer) {
    agentOpts.pfx = pfxBuffer;
    agentOpts.passphrase = PFX_PASS;
  }
  const agent = new https.Agent(agentOpts);

  // Forward request to MediKredit
  const startTime = Date.now();
  const mkRequest = https.request({
    hostname: urlObj.hostname,
    port: urlObj.port || 443,
    path: urlObj.pathname + urlObj.search,
    method: method,
    agent: agent,
    headers: headers,
  }, (mkResponse) => {
    const chunks = [];
    mkResponse.on('data', (c) => chunks.push(c));
    mkResponse.on('end', () => {
      const responseBody = Buffer.concat(chunks).toString('utf8');
      const latency = Date.now() - startTime;

      console.log(`[adapter] MediKredit responded: HTTP ${mkResponse.statusCode} in ${latency}ms`);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: mkResponse.statusCode,
        body: responseBody,
        latency_ms: latency,
        target_url: targetUrl,
      }));
    });
  });

  mkRequest.setTimeout(30000, () => {
    mkRequest.destroy();
    console.error('[adapter] MediKredit request timed out');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 0, body: '', error: 'MediKredit request timed out (30s)' }));
  });

  mkRequest.on('error', (e) => {
    console.error('[adapter] MediKredit request error:', e.message);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 0, body: '', error: e.message }));
  });

  mkRequest.write(bodyBytes);
  mkRequest.end();
});

server.listen(PORT, () => {
  console.log(`[adapter] MediKredit mTLS proxy listening on port ${PORT}`);
  console.log(`[adapter] PFX cert: ${pfxBuffer ? 'loaded' : 'MISSING'}`);
  console.log(`[adapter] Credentials: ${MK_USERNAME ? 'set' : 'MISSING'}`);
});