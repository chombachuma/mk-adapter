//Force Rebuild
const http = require('http');
const https = require('https');

const ADAPTER_SECRET = process.env.ADAPTER_SECRET || '';
// MediKredit test credentials — hardcoded for test env
// From MediKredit integration kit: Username eYVUqtNKSu, Password fGRp2mtGH86RrpdqwTBx
// NOTE: When switching to prod, change these to prod credentials or use env vars
const MK_USERNAME = 'eYVUqtNKSu';
const MK_PASSWORD = 'fGRp2mtGH86RrpdqwTBx';
const PORT = process.env.PORT || 3000;

// mTLS certs — Cloudflare test certs from MediKredit S2PI spec (base64-encoded PEM)
const CERT_PEM = Buffer.from('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVGVENDQXYyZ0F3SUJBZ0lVWkl0YmViVG1KMkcwRUNacE5TQTh2TEhQdm44d0RRWUpLb1pJaHZjTkFRRUwKQlFBd2dhZ3hDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJRXdwRFlXeHBabTl5Ym1saE1SWXdGQVlEVlFRSApFdzFUWVc0Z1JuSmhibU5wYzJOdk1Sa3dGd1lEVlFRS0V4QkRiRzkxWkdac1lYSmxMQ0JKYm1NdU1Sc3dHUVlEClZRUUxFeEozZDNjdVkyeHZkV1JtYkdGeVpTNWpiMjB4TkRBeUJnTlZCQU1USzAxaGJtRm5aV1FnUTBFZ01qY3oKWVRGaE9UWTFPVE01TTJGak1XTXdPRGN4WTJKa01EUmxORGN4WW1Fd0hoY05NakV4TURBMk1ETXpPVEF3V2hjTgpNekV4TURBME1ETXpPVEF3V2pBaU1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVBeE1LUTJ4dmRXUm1iR0Z5ClpUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQUxTQTIwZ3JEY0pONjk5ck80YkkKdm5WSkZyZ1NFTko2clJQYVpEekdDVSsvaDRYZGUxOW93eGJ4N21ROHdLeW9zazFhdHJQNXMrMHNWZFJwTGlrOQpPRnoveXh1YVZ6WmR5OTlWR0lwRVEvQlFObEhYc3NIaGxUNGVLSEpteVI3TUlnNSs1MGVPRlFBdTFweXNxZ1lTCkpCdzR6MytPWXF1eHNlN2JtdzNUMjRnMlFvZm5PN3BsYWpLTG9Ldk1XVEpRbllNWGxxbE14ZW9KUXFuMlRLdXUKWWVoWGlIbU9TSUNxNDBoZWpSZWE0czBHMEVJZUJhZGxvMC9VNXZCM0lTK2xNUk1ZcGg0eHBUOWZ6RWtpVjdtdQpyRDgzNDlpTnhUTk1YUHhybUlrZHNFOE5vdTNEN1FXTCtyQXJPbDlEMis3RGNsekthcVRCNVk5NEJpQzNVemhwClZWOENBd0VBQWFPQnV6Q0J1REFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQWpBTUJnTlZIUk1CQWY4RUFqQUEKTUIwR0ExVWREZ1FXQkJRVzlUVVI3dFkrb0lFMUQrMVRYSll1YjZxbk9EQWZCZ05WSFNNRUdEQVdnQlMrWWRCMAozTU5YQy9xZ0NKSnBoQ2kzT3BCdXdEQlRCZ05WSFI4RVREQktNRWlnUnFCRWhrSm9kSFJ3T2k4dlkzSnNMbU5zCmIzVmtabXhoY21VdVkyOXRMelV6WkRNMk5EVTNMV1U1WVRRdE5ERTVNUzA1TWpSa0xUZzBaakU1WTJZMlkyUXgKTnk1amNtd3dEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRitxcnJyTDVWRjZiSVg0aHMwYzV6NVFrUjB4YzlDRQpZU0QrYkwvc0gvZE54aVBJRGxhc1Z4dktQVGdOckFPTGR2cGhOS3FxZk9xSFlVQU83SWp2cHJuRHVCNnRtT0NmCk9LenhqMjl6S0xialFSV2ZTQU8rMW5sakdEeXA4Ti9PbS9qRlNSZEhRcW9aUU1zN0xSTUY0L3g5QmJjYkV5SWcKUEo4T2ZBUVI3QVUzZVh6WGlRWFNzN3VwWXZaRkY2UW8yU3pITDZub0h0WUVxTithZmpvbm50VDlUcWszTWxvRwpRelpCcTNGME8zZWFwY2JRNzZ4WS9vVkt3aDArMHhhQ3VYRHBmZmxzTUFUTEdNUFg2cXpCZEVUMDV5RUp1c0NlClhBZnRkR2hFcXd4RXNoSUsvendlbXlwUTBBeGVTZHI2c0FMUnBuc1pGV2hOSmc5TWthbkc5RU09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K', 'base64').toString('utf8');
const KEY_PEM = Buffer.from('LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRQzBnTnRJS3czQ1RldmYKYXp1R3lMNTFTUmE0RWhEU2VxMFQybVE4eGdsUHY0ZUYzWHRmYU1NVzhlNWtQTUNzcUxKTldyYXorYlB0TEZYVQphUzRwUFRoYy84c2JtbGMyWGN2ZlZSaUtSRVB3VURaUjE3TEI0WlUrSGloeVpza2V6Q0lPZnVkSGpoVUFMdGFjCnJLb0dFaVFjT005L2ptS3JzYkh1MjVzTjA5dUlOa0tINXp1NlpXb3lpNkNyekZreVVKMkRGNWFwVE1YcUNVS3AKOWt5cnJtSG9WNGg1amtpQXF1TklYbzBYbXVMTkJ0QkNIZ1duWmFOUDFPYndkeUV2cFRFVEdLWWVNYVUvWDh4SgpJbGU1cnF3L04rUFlqY1V6VEZ6OGE1aUpIYkJQRGFMdHcrMEZpL3F3S3pwZlE5dnV3M0pjeW1xa3dlV1BlQVlnCnQxTTRhVlZmQWdNQkFBRUNnZ0VBRHZBQTlacDJnNGR1UnlsNUhpRGJ2aG9EMHN6UDdwTXZZbzYycjk3Vm8yOWUKdUVISmRXNVdncjRYczl6aE53aW81TVRtak1OVDFBTlF3UWpKUktsbjBpNXE4UWhYUWswRjA2QVhyVTJUNzcyNwptUTlJSUVwYVR1OHcrckt0M3lvV2dXdVlHVEJWWlpQNnQ3R0VTb2RTekxFWTN0MzZKV3BKcHRJdXBUak1tSnQ5ClUxRUlNcnpUZksrMzNyS05WUXVXTHBiSTZheHBYVGtIVENwUlNGczJ0WWZDSXorQkJvWVNhMHVCT0NHeVowd1YKM2UzWEJOUGRIUnlqRU5LbXIrVWlPRFJkU3hnS0d4YTVYU2lyYld6VnVBMVFKeGMwQWYwT0Y2Z3JqUHU4Q1NXbwoxSHBIbzIwb002WCtFN3U0U2RLdFp1OFlKYk5uMXFlc0Y1UXBmbzkxdVFLQmdRRGMvNWMxWVROSUNuR1hhWXFyCkpIM29UT25jdmtzRit3N0hGYUZnV3VHb05SZmZmNE93bTNCME5sNmppVzdnR1VIL3FHZlk2djVxbDN6NGVDd0cKeDdNVmNpSWRmZjZ2VDZUZDN2STVndk5UR3V5SWdHY3NUdXdUWnpxUkZKNXU3VWM4SVVKNlp0YkJxVWVoZ3piSAo3NDJEbWFRQndnOFY2azl1UCtkaEd4am5XUUtCZ1FEUkYyTjRxSzdPajdOTVlrOTJJMzRjZFN2V2pFZmQxR0tiCi8zK1lua2d0Mms5U3ZRYXZyeFU5ekRjUk10Y0xtWjZTei9YbVg1d1JKSEtqdEM2MTd6WWs2VjN1QklMZFBtWjkKT3QzTExsZFNCUVdEQmF3T1pIU3N4SXZjQzZ2dVlnQjJDZUw4TkRyWWRmaEN6TGhUYnpMeXhPdVhtZ0ZDUzhIcQowdVk0dmVYRGR3S0JnR3FmZWRHTU10U29EVVBTN005RFRPZTk2L3JQYUp6YkVyY2tqWFpTZ3BySCt0dWV4dWQzCkp4czZmQkNFcHhUQnV1RGczREdBdHZ5d1Y5LzlBcWpHd25VdldweEdCSkdLYUcyUE9laGJjSkFBNW11NUg0MzIKQ2RvV3JPQUFSYXdaR0l3L003YWdWUzZjUUc0QlEzWFU4cjZ5YXJsYWFqTFZtRHNGNDlrcTNLb0pBb0dCQUxNdgpLdlNGQWtGTWpxZ2YrOTdQTGN6dmNPRU5HSzEyekFiSjN5d0lRT3ppa0dYa1RlMlN5azVLU3NxM1dlaTcvbFBzCldkdlNCYW4vSlNzN1IyaHNsbWJ0Z3F4dU8wT2tyU29XbjJuMnphZ2hXNGJiL29YYStzM3dKYmN1WFdvTm5EMkwKM1hTcXdkOHN3ZE5sSTNXRTd4RnpSajZHSVJ3U1ZoMktIUGQxYllpakFvR0JBTFh0VWF0bEN2ZGt5NDl6ZnEyaApFejMxN3VyZ1I4ZFdOa29FemtBNExmbEtLYVR0Q3pVc3ZZRHpkR0JpYXhDeWhhV0FRaEM5SS9PTkNLRWo4bVlxCisraUhGampVSmUzclZiVlhtUjFTcDJrYnRwYUJ4aTdqZXVzYnZDLytnUzdTcUo3Z3llMDZ4VE5scDIxN3lVWVEKRHdBUlUybkh3RTlRTVpvdHZITDZ2Q2JSCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K', 'base64').toString('utf8');

if (!ADAPTER_SECRET) { console.error('FATAL: ADAPTER_SECRET required'); process.exit(1); }

let cachedAgent = null;
let agentInitError = null;

function getHttpsAgent() {
  if (cachedAgent) return cachedAgent;
  if (agentInitError) return null;
  try {
    cachedAgent = new https.Agent({ cert: CERT_PEM, key: KEY_PEM, rejectUnauthorized: false });
    console.log('[adapter] mTLS agent created OK');
    return cachedAgent;
  } catch (e) {
    agentInitError = e.message;
    console.error('[adapter] Agent failed: ' + e.message);
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
    res.end(JSON.stringify({ ok: true, cert_mode: 'PEM-embedded', has_credentials: !!MK_USERNAME, adapter_version: '3.2' }));
    return;
  }
  if (req.method !== 'POST') { res.writeHead(405); res.end('{"error":"Method not allowed"}'); return; }
  if (req.headers['x-adapter-secret'] !== ADAPTER_SECRET) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end('{"error":"Unauthorized"}');
    return;
  }
  var rawBody = '';
  req.on('data', function(c) { rawBody += c; });
  req.on('end', function() {
    var payload;
    try { payload = JSON.parse(rawBody); } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end('{"error":"Invalid JSON"}');
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
      res.end('{"status":0,"error":"Invalid URL"}');
      return;
    }
    var agent = getHttpsAgent();
    if (!agent) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 0, error: 'mTLS failed: ' + agentInitError }));
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
          console.log('[adapter] <- HTTP ' + mkResponse.statusCode + ' ' + latency + 'ms');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: mkResponse.statusCode, body: responseBody, latency_ms: latency }));
        });
        mkResponse.on('error', function(e) {
          var latency = Date.now() - startTime;
          if (!res.headersSent) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 0, error: 'Response error: ' + e.message, latency_ms: latency }));
          }
        });
      });
      mkRequest.on('timeout', function() {
        mkRequest.destroy();
        var latency = Date.now() - startTime;
        if (!res.headersSent) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 0, error: 'Timeout (30s)', latency_ms: latency }));
        }
      });
      mkRequest.on('error', function(e) {
        var latency = Date.now() - startTime;
        console.error('[adapter] Error: ' + e.message);
        if (!res.headersSent) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 0, error: e.message, latency_ms: latency }));
        }
      });
      mkRequest.write(bodyBytes);
      mkRequest.end();
    } catch (e) {
      var latency = Date.now() - startTime;
      if (!res.headersSent) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 0, error: 'Exception: ' + e.message, latency_ms: latency }));
      }
    }
  });
  req.on('error', function(e) {
    if (!res.headersSent) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Stream error: ' + e.message }));
    }
  });
});

server.listen(PORT, function() {
  console.log('[adapter] MediKredit mTLS proxy v3.2 on port ' + PORT);
  console.log('[adapter] Cert: embedded PEM');
  console.log('[adapter] Creds: ' + (MK_USERNAME ? 'set' : 'MISSING'));
});
