//Force Rebuild
/**
 * MediKredit mTLS Proxy Adapter v2.0 — Railway Deployment
 * 17.07.26 — v2 with error handling and custom domain support
 * Domain: mk.iscript.co.za (CNAME -> i2wiycg2.up.railway.app)
 */

const http = require('http');
const https = require('https');

const ADAPTER_SECRET = process.env.ADAPTER_SECRET || '';
const MK_USERNAME = process.env.MEDIKREDIT_USERNAME || process.env.MK_USERNAME || '';
const MK_PASSWORD = process.env.MEDIKREDIT_PASSWORD || process.env.MK_PASSWORD || '';
const PFX_B64 = process.env.MEDIKREDIT_CLIENT_PFX_B64 || process.env.MK_PFX_B64 || '';
const PFX_PASS = process.env.MEDIKREDIT_CLIENT_PASSPHRASE || process.env.MK_PFX_PASS || 'testpass123';
const PORT = process.env.PORT || 3000;

if (!ADAPTER_SECRET) {
  console.error('FATAL: ADAPTER_SECRET environment variable is required');
  process.exit(1);
}

let cachedAgent = null;
let agentInitError = null;

function getHttpsAgent() {
  if (cachedAgent) return cachedAgent;
  if (agentInitError) return null;
  if (!PFX_B64) {
    agentInitError = 'No PFX certificate configured';
    return null;
  }
  try {
    const pfxBuffer = Buffer.from(PFX_B64, 'base64');
    console.log('[adapter] PFX cert loaded: ' + pfxBuffer.length + ' bytes');
    cachedAgent = new https.Agent({
      pfx: pfxBuffer,
      passphrase: PFX_PASS,
      rejectUnauthorized: false
    });
    return cachedAgent;
  } catch (e) {
    console.error('[adapter] Failed to create mTLS agent: ' + e.message);
    agentInitError = e.message;
    return null;
  }
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Adapter-Secret');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (req.method === 'GET' && req.url === '/health') {
    const pfxBuf = PFX_B64 ? Buffer.from(PFX_B64, 'base64') : null;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, pfx_loaded: !!pfxBuf, has_credentials: !!MK_USERNAME, adapter_version: '2.0' }));
    return;
  }

  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  const adapterSecret = req.headers['x-adapter-secret'];
  if (adapterSecret !== ADAPTER_SECRET) {
    console.warn('[adapter] Unauthorized request — secret mismatch');
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized — invalid adapter secret' }));
    return;
  }

  let rawBody = '';
  req.on('data', (chunk) => { rawBody += chunk; });
  req.on('end', () => {
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

    const headers = Object.assign({}, payload.headers || {});
    if (!headers['Authorization'] && MK_USERNAME) {
      headers['Authorization'] = 'Basic ' + Buffer.from(MK_USERNAME + ':' + MK_PASSWORD).toString('base64');
    }
    if (!headers['Content-Type']) { headers['Content-Type'] = 'text/xml; charset=utf-8'; }
    const bodyBytes = Buffer.from(soapBody, 'utf8');
    headers['Content-Length'] = bodyBytes.length;

    console.log('[adapter] Forwarding ' + method + ' -> ' + targetUrl + ' (' + bodyBytes.length + ' bytes)');

    let urlObj;
    try { urlObj = new URL(targetUrl); } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 0, body: '', error: 'Invalid target_url: ' + e.message }));
      return;
    }

    const agent = getHttpsAgent();
    if (!agent && PFX_B64) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 0, body: '', error: 'mTLS agent creation failed: ' + agentInitError }));
      return;
    }

    const startTime = Date.now();
    try {
      const mkRequest = https.request({
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: urlObj.pathname + urlObj.search,
        method: method,
        agent: agent || undefined,
        headers: headers,
        timeout: 30000
      }, (mkResponse) => {
        const chunks = [];
        mkResponse.on('data', (c) => chunks.push(c));
        mkResponse.on('end', () => {
          const responseBody = Buffer.concat(chunks).toString('utf8');
          const latency = Date.now() - startTime;
          console.log('[adapter] MediKredit responded: HTTP ' + mkResponse.statusCode + ' in ' + latency + 'ms');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: mkResponse.statusCode, body: responseBody, latency_ms: latency, target_url: targetUrl }));
        });
        mkResponse.on('error', (e) => {
          const latency = Date.now() - startTime;
          console.error('[adapter] Response stream error: ' + e.message);
          if (!res.headersSent) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 0, body: '', error: 'Response error: ' + e.message, latency_ms: latency }));
          }
        });
      });

      mkRequest.on('timeout', () => {
        mkRequest.destroy();
        const latency = Date.now() - startTime;
        console.error('[adapter] Request timed out after ' + latency + 'ms');
        if (!res.headersSent) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 0, body: '', error: 'Request timed out (30s)', latency_ms: latency }));
        }
      });

      mkRequest.on('error', (e) => {
        const latency = Date.now() - startTime;
        console.error('[adapter] Request error: ' + e.message);
        if (!res.headersSent) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 0, body: '', error: e.message, latency_ms: latency }));
        }
      });

      mkRequest.write(bodyBytes);
      mkRequest.end();
    } catch (e) {
      const latency = Date.now() - startTime;
      console.error('[adapter] Exception: ' + e.message);
      if (!res.headersSent) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 0, body: '', error: 'Exception: ' + e.message, latency_ms: latency }));
      }
    }
  });

  req.on('error', (e) => {
    console.error('[adapter] Request stream error: ' + e.message);
    if (!res.headersSent) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Request stream error: ' + e.message }));
    }
  });
});

server.listen(PORT, () => {
  const pfxStatus = PFX_B64 ? 'loaded (' + Buffer.from(PFX_B64, 'base64').length + ' bytes)' : 'MISSING';
  console.log('[adapter] MediKredit mTLS proxy v2.0 listening on port ' + PORT);
  console.log('[adapter] PFX cert: ' + pfxStatus);
  console.log('[adapter] Credentials: ' + (MK_USERNAME ? 'set' : 'MISSING'));
  console.log('[adapter] Passphrase: ' + (PFX_PASS ? 'set' : 'MISSING'));
});
