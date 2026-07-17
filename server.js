//Force Rebuild
/**
 * MediKredit mTLS Proxy Adapter v3.0 — Railway Deployment
 * 17.07.26 — v3 supports PEM cert+key (primary) and PFX (fallback)
 * Domain: mk.iscript.co.za (CNAME -> i2wiycg2.up.railway.app)
 */

const http = require('http');
const https = require('https');

const ADAPTER_SECRET = process.env.ADAPTER_SECRET || '';
const MK_USERNAME = process.env.MEDIKREDIT_USERNAME || process.env.MK_USERNAME || '';
const MK_PASSWORD = process.env.MEDIKREDIT_PASSWORD || process.env.MK_PASSWORD || '';

// PEM cert + key (primary)
const CERT_PEM = process.env.MEDIKREDIT_CLIENT_CERT_PEM || '';
const KEY_PEM = process.env.MEDIKREDIT_CLIENT_KEY_PEM || '';

// PFX (fallback)
const PFX_B64 = process.env.MEDIKREDIT_CLIENT_PFX_B64 || process.env.MK_PFX_B64 || '';
const PFX_PASS = process.env.MEDIKREDIT_CLIENT_PASSPHRASE || process.env.MK_PFX_PASS || 'GH86RrpdqwTBx';

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

  var agentOpts = { rejectUnauthorized: false };

  if (CERT_PEM && KEY_PEM) {
    // PEM mode
    agentOpts.cert = CERT_PEM;
    agentOpts.key = KEY_PEM;
    console.log('[adapter] Using PEM cert+key for mTLS');
    console.log('[adapter] Cert length: ' + CERT_PEM.length + ' chars, Key length: ' + KEY_PEM.length + ' chars');
  } else if (PFX_B64) {
    // PFX mode
    try {
      var pfxBuffer = Buffer.from(PFX_B64, 'base64');
      if (pfxBuffer.length < 100) {
        throw new Error('PFX data too short (' + pfxBuffer.length + ' bytes) — likely truncated');
      }
      agentOpts.pfx = pfxBuffer;
      agentOpts.passphrase = PFX_PASS;
      console.log('[adapter] Using PFX cert for mTLS: ' + pfxBuffer.length + ' bytes');
    } catch (e) {
      console.error('[adapter] PFX failed: ' + e.message);
      agentInitError = e.message;
      return null;
    }
  } else {
    agentInitError = 'No mTLS certificate configured (need CERT_PEM+KEY_PEM or PFX_B64)';
    console.error('[adapter] ' + agentInitError);
    return null;
  }

  try {
    cachedAgent = new https.Agent(agentOpts);
    console.log('[adapter] HTTPS agent created successfully');
    return cachedAgent;
  } catch (e) {
    console.error('[adapter] Agent creation failed: ' + e.message);
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
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      cert_mode: CERT_PEM && KEY_PEM ? 'PEM' : (PFX_B64 ? 'PFX' : 'none'),
      has_credentials: !!MK_USERNAME,
      adapter_version: '3.0'
    }));
    return;
  }

  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  var adapterSecret = req.headers['x-adapter-secret'];
  if (adapterSecret !== ADAPTER_SECRET) {
    console.warn('[adapter] Unauthorized request');
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  var rawBody = '';
  req.on('data', function(chunk) { rawBody += chunk; });
  req.on('end', function() {
    var payload;
    try {
      payload = JSON.parse(rawBody);
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
      return;
    }

    var targetUrl = payload.target_url || 'https://test-services-ccert.medikredit.co.za/ws2pint/';
    var method = payload.method || 'POST';
    var soapBody = payload.body || '';

    var headers = Object.assign({}, payload.headers || {});
    if (!headers['Authorization'] && MK_USERNAME) {
      headers['Authorization'] = 'Basic ' + Buffer.from(MK_USERNAME + ':' + MK_PASSWORD).toString('base64');
    }
    if (!headers['Content-Type']) { headers['Content-Type'] = 'text/xml; charset=utf-8'; }
    var bodyBytes = Buffer.from(soapBody, 'utf8');
    headers['Content-Length'] = bodyBytes.length;

    console.log('[adapter] -> ' + method + ' ' + targetUrl + ' (' + bodyBytes.length + ' bytes)');

    var urlObj;
    try { urlObj = new URL(targetUrl); } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 0, body: '', error: 'Invalid target_url: ' + e.message }));
      return;
    }

    var agent = getHttpsAgent();
    if (!agent) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 0, body: '', error: 'mTLS agent failed: ' + agentInitError }));
      return;
    }

    var startTime = Date.now();
    try {
      var mkRequest = https.request({
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: urlObj.pathname + urlObj.search,
        method: method,
        agent: agent,
        headers: headers,
        timeout: 30000
      }, function(mkResponse) {
        var chunks = [];
        mkResponse.on('data', function(c) { chunks.push(c); });
        mkResponse.on('end', function() {
          var responseBody = Buffer.concat(chunks).toString('utf8');
          var latency = Date.now() - startTime;
          console.log('[adapter] <- HTTP ' + mkResponse.statusCode + ' in ' + latency + 'ms');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: mkResponse.statusCode, body: responseBody, latency_ms: latency, target_url: targetUrl }));
        });
        mkResponse.on('error', function(e) {
          var latency = Date.now() - startTime;
          console.error('[adapter] Response error: ' + e.message);
          if (!res.headersSent) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 0, body: '', error: 'Response error: ' + e.message, latency_ms: latency }));
          }
        });
      });

      mkRequest.on('timeout', function() {
        mkRequest.destroy();
        var latency = Date.now() - startTime;
        console.error('[adapter] Timeout after ' + latency + 'ms');
        if (!res.headersSent) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 0, body: '', error: 'Request timed out (30s)', latency_ms: latency }));
        }
      });

      mkRequest.on('error', function(e) {
        var latency = Date.now() - startTime;
        console.error('[adapter] Request error: ' + e.message);
        if (!res.headersSent) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 0, body: '', error: e.message, latency_ms: latency }));
        }
      });

      mkRequest.write(bodyBytes);
      mkRequest.end();
    } catch (e) {
      var latency = Date.now() - startTime;
      console.error('[adapter] Exception: ' + e.message);
      if (!res.headersSent) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 0, body: '', error: 'Exception: ' + e.message, latency_ms: latency }));
      }
    }
  });

  req.on('error', function(e) {
    console.error('[adapter] Stream error: ' + e.message);
    if (!res.headersSent) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Stream error: ' + e.message }));
    }
  });
});

server.listen(PORT, function() {
  var certMode = (CERT_PEM && KEY_PEM) ? 'PEM' : (PFX_B64 ? 'PFX' : 'NONE');
  console.log('[adapter] MediKredit mTLS proxy v3.0 on port ' + PORT);
  console.log('[adapter] Cert mode: ' + certMode);
  console.log('[adapter] Credentials: ' + (MK_USERNAME ? 'set' : 'MISSING'));
});
