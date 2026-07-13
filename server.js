const express = require('express');
const axios = require('axios');
const https = require('https');
const xml2js = require('xml2js');

const app = express();
app.use(express.json());

// Environment configurations
const PORT = process.env.PORT || 3000;
const ADAPTER_SECRET = process.env.ADAPTER_SECRET;
const MK_ENV = process.env.MK_ENV || 'test';
const MK_USERNAME = process.env.MK_USERNAME;
const MK_PASSWORD = process.env.MK_PASSWORD;
const MK_PFX_B64 = process.env.MK_PFX_B64;
const MK_PFX_PASS = process.env.MK_PFX_PASS;

// MediKredit Endpoint URIs
const MEDIKREDIT_TEST_URL = 'https://test-services-ccert.medikredit.co.za/ws2pint/';
const MEDIKREDIT_PROD_URL = 'https://prod-services.medikredit.co.za/live/ws2pint/';

// Request Logging Middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const latency = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - Status: ${res.statusCode} - ${latency}ms`);
  });
  next();
});

// Memoized HTTPS Agent Creation helper
let cachedAgent = null;
let agentLoadError = null;

function getHttpsAgent() {
  if (cachedAgent) return cachedAgent;
  if (!MK_PFX_B64) {
    throw new Error('MK_PFX_B64 environment variable is missing.');
  }

  try {
    const pfxBuffer = Buffer.from(MK_PFX_B64, 'base64');
    cachedAgent = new https.Agent({
      pfx: pfxBuffer,
      passphrase: MK_PFX_PASS || undefined,
      rejectUnauthorized: true // Ensure server cert is validated too
    });
    agentLoadError = null;
    return cachedAgent;
  } catch (err) {
    agentLoadError = err.message;
    console.error('Error creating HTTPS agent with PFX certificate:', err);
    throw new Error(`Failed to initialize HTTPS mTLS Agent: ${err.message}`);
  }
}

// HTML encoding utility
function escapeXml(unsafe) {
  if (unsafe === undefined || unsafe === null) return '';
  return String(unsafe).replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
      default: return c;
    }
  });
}

// SOAP envelope builder helper
function buildSoapEnvelope(innerXml) {
  // Per S2PI spec: inner XML is wrapped in CDATA, NOT HTML-entity-encoded
  return `<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:s2pi="http://www.medikredit.co.za/S2PI">
   <soapenv:Header/>
   <soapenv:Body>
      <s2pi:submit-claim>
         <request><![CDATA[${innerXml}]]></request>
      </s2pi:submit-claim>
   </soapenv:Body>
</soapenv:Envelope>`;
}

// Generate unique transaction number if not provided
function generateTxNbr() {
  return 'TX' + Date.now() + Math.floor(Math.random() * 1000);
}

// Helper to get today's date formatted (YYYY-MM-DD or simple YYYYMMDD based on standard, here YYYYMMDD is usually used in SA healthcare but we will keep standard YYYY-MM-DD or let them pass. Typically ISO 10-char "YYYY-MM-DD" is safest. We default to YYYY-MM-DD)
function getTodayDate() {
  // MediKredit requires CCYYMMDD format (e.g. 20260713)
  const d = new Date();
  const y = d.getFullYear().toString().padStart(4,'0');
  const m = (d.getMonth()+1).toString().padStart(2,'0');
  const day = d.getDate().toString().padStart(2,'0');
  return y + m + day;
}

// POST /health endpoint
app.post('/health', (req, res) => {
  let pfxLoaded = false;
  try {
    getHttpsAgent();
    pfxLoaded = true;
  } catch (e) {
    pfxLoaded = false;
  }

  return res.json({
    status: 'ok',
    env: MK_ENV,
    pfx_loaded: pfxLoaded,
    error: pfxLoaded ? null : agentLoadError
  });
});

// GET /health support as well for easy health checks
app.get('/health', (req, res) => {
  let pfxLoaded = false;
  try {
    getHttpsAgent();
    pfxLoaded = true;
  } catch (e) {
    pfxLoaded = false;
  }

  return res.json({
    status: 'ok',
    env: MK_ENV,
    pfx_loaded: pfxLoaded,
    error: pfxLoaded ? null : agentLoadError
  });
});

// Main SOAP request dispatcher to MediKredit
async function sendToMediKredit(soapXml) {
  const agent = getHttpsAgent();
  const endpoint = MK_ENV === 'prod' ? MEDIKREDIT_PROD_URL : MEDIKREDIT_TEST_URL;

  // Setup Basic Auth Headers
  const headers = {
    'Content-Type': 'text/xml; charset=utf-8',
    'SOAPAction': '""'
  };

  const config = {
    httpsAgent: agent,
    headers: headers,
    timeout: 30000 // 30 second timeout
  };

  if (MK_USERNAME && MK_PASSWORD) {
    config.auth = {
      username: MK_USERNAME,
      password: MK_PASSWORD
    };
  }

  const response = await axios.post(endpoint, soapXml, config);
  return response.data;
}

// Parse SOAP XML Response to extract required properties
async function parseMediKreditResponse(soapResponseXml) {
  const parser = new xml2js.Parser({ explicitArray: false, tagNameProcessors: [xml2js.processors.stripPrefix] });
  const result = await parser.parseStringPromise(soapResponseXml);

  let responseBody = null;
  try {
    // Navigate standard SOAP Body envelope
    const envelope = result.Envelope;
    const body = envelope.Body;
    // S2PI submit-claim response — element is <reply> per MediKredit spec
    const submitClaimResponse = body['submit-claimResponse'] || body['ns:submit-claimResponse'] || body.submitClaimResponse;
    responseBody = submitClaimResponse.reply || submitClaimResponse.return || submitClaimResponse.submitClaimReturn;
  } catch (err) {
    throw new Error('Failed to parse SOAP response structure: ' + err.message);
  }

  if (!responseBody) {
    throw new Error('NO_RETURN_BODY: ' + JSON.stringify(result).substring(0, 500));
  }

  // The reply content is HTML-entity-encoded XML — unescape before parsing
  const unescaped = responseBody
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .trim();
  const innerParser = new xml2js.Parser({ explicitArray: false });
  const innerResult = await innerParser.parseStringPromise(unescaped);

  const doc = innerResult.DOCUMENT;
  if (!doc) {
    return {
      success: false,
      res_code: 'ERROR',
      gv_number: null,
      raw_xml: responseBody,
      parsed: innerResult
    };
  }

  // TX attributes contain res (result code) and other metadata
  const tx = doc.TX;
  const txAttrs = tx && tx.$ ? tx.$ : {};
  const resCode = txAttrs.res || null;
  
  // GV number (hnet) is in AUTHS element
  const auths = tx && tx.AUTHS ? tx.AUTHS : (doc.AUTHS || null);
  const authAttrs = auths && auths.$ ? auths.$ : (auths || {});
  const hnet = authAttrs.hnet || txAttrs.hnet || null;

  // Rejection codes
  const rjElem = tx && tx.RJ ? tx.RJ : null;
  const rjCode = rjElem && rjElem.$ ? rjElem.$.cd : null;
  const rjDesc = rjElem && rjElem.$ ? rjElem.$.desc : null;

  // MediKredit uses res="A" for approved
  const approved = resCode === 'A';

  return {
    success: approved,
    res_code: resCode,
    gv_number: hnet,
    rejection_code: rjCode,
    rejection_desc: rjDesc,
    raw_xml: unescaped,
    parsed: doc
  };
}

// Route mapping and XML builders
app.post('/mk', async (req, res) => {
  const incomingSecret = req.headers['x-adapter-secret'];

  // Security authorization check
  if (!ADAPTER_SECRET) {
    return res.status(500).json({ error: 'ADAPTER_SECRET is not configured on the adapter server.' });
  }

  if (incomingSecret !== ADAPTER_SECRET) {
    return res.status(401).json({ error: 'Unauthorized: Invalid X-Adapter-Secret header' });
  }

  const { action, payload = {} } = req.body;

  if (!action) {
    return res.status(400).json({ error: 'Missing action in request body.' });
  }

  // Populate dynamic default values
  const dateStr = payload.date || getTodayDate();
  const txNbr = payload.tx_nbr || generateTxNbr();
  const spBhf = payload.sp_bhf || (action === 'smoketest' ? '0469939' : '');
  const spHpc = payload.sp_hpc || (action === 'smoketest' ? 'MP0672858' : '');
  const plan = payload.plan || (action === 'smoketest' ? '612346' : '');
  const chId = payload.ch_id || (action === 'smoketest' ? 'MK1990533' : '');
  const depCd = payload.dep_cd || '00';
  const sname = payload.sname || 'TEST';
  const fname = payload.fname || 'TEST';
  const inits = payload.inits || 'T';
  const dob = (payload.dob || '19900101').replace(/-/g, ''); // CCYYMMDD format
  const idNbr = payload.id_nbr || '';

  let innerXml = '';

  try {
    switch (action) {
      case 'smoketest':
      case 'claim':
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}" grp_prac="${escapeXml(spBhf)}"
      tx_nbr="${escapeXml(txNbr)}" plan="${escapeXml(plan)}"
      dt_cr="${escapeXml(dateStr)}" dt_os="${escapeXml(dateStr)}"
      tx_cd="20" nbr_items="1" pay_adv="P" clm_orig="E"
      msg_fmt="13" orig="4" bin="2" cntry_cd="ZA" sect_cd="PR">
    <VEND vend_id="2085" pc_nbr="01" wks_nbr="001" vend_ver="1.0.0"/>
    <MEM ch_id="${escapeXml(chId)}" sname="${escapeXml(sname)}" inits="${escapeXml(inits)}"/>
    <PAT dep_cd="${escapeXml(depCd)}" dob="${escapeXml(dob)}" id_nbr="${escapeXml(idNbr)}"
         sname="${escapeXml(sname)}" fname="${escapeXml(fname)}" inits="${escapeXml(inits)}"
         gend="1" rlnship="0" status="O"/>
  </TX>
</DOCUMENT>`;
        break;

      case 'famcheck':
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}" grp_prac="${escapeXml(spBhf)}"
      tx_nbr="${escapeXml(txNbr)}" ch_id="${escapeXml(chId)}" plan="${escapeXml(plan)}"
      tx_cd="30" orig="4" bin="2" cntry_cd="ZA">
    <VEND vend_id="2085" pc_nbr="01" wks_nbr="001" vend_ver="1.0.0"/>
  </TX>
</DOCUMENT>`;
        break;

      case 'eligibility':
        // Eligibility check: tx_cd=10 with specific dep_cd per S2PI spec
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}" grp_prac="${escapeXml(spBhf)}"
      tx_nbr="${escapeXml(txNbr)}" ch_id="${escapeXml(chId)}" dep_cd="${escapeXml(depCd)}" plan="${escapeXml(plan)}"
      tx_cd="30" orig="4" bin="2" cntry_cd="ZA">
    <VEND vend_id="2085" pc_nbr="01" wks_nbr="001" vend_ver="1.0.0"/>
  </TX>
</DOCUMENT>`;
        break;

      case 'claim_reversal':
        // Reversals generally use tx_cd="25" with original tx_nbr to be reversed, or can vary.
        // We build a robust template containing standard parameters for reversal.
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}" grp_prac="${escapeXml(spBhf)}"
      tx_nbr="${escapeXml(txNbr)}" plan="${escapeXml(plan)}"
      dt_cr="${escapeXml(dateStr)}" dt_os="${escapeXml(dateStr)}"
      tx_cd="25" nbr_items="1" pay_adv="P" clm_orig="E"
      msg_fmt="13" orig="4" bin="2" cntry_cd="ZA" sect_cd="PR">
    <VEND vend_id="2085" pc_nbr="01" wks_nbr="001" vend_ver="1.0.0"/>
    <MEM ch_id="${escapeXml(chId)}" sname="${escapeXml(sname)}" inits="${escapeXml(inits)}"/>
  </TX>
</DOCUMENT>`;
        break;

      case 'resubmission':
        // Resubmission behaves similarly to claims but with specific flag or tracking adjustments (tx_cd=20 with clm_orig code updates or similar)
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}" grp_prac="${escapeXml(spBhf)}"
      tx_nbr="${escapeXml(txNbr)}" plan="${escapeXml(plan)}"
      dt_cr="${escapeXml(dateStr)}" dt_os="${escapeXml(dateStr)}"
      tx_cd="20" nbr_items="1" pay_adv="P" clm_orig="R"
      msg_fmt="13" orig="4" bin="2" cntry_cd="ZA" sect_cd="PR">
    <VEND vend_id="2085" pc_nbr="01" wks_nbr="001" vend_ver="1.0.0"/>
    <MEM ch_id="${escapeXml(chId)}" sname="${escapeXml(sname)}" inits="${escapeXml(inits)}"/>
    <PAT dep_cd="${escapeXml(depCd)}" dob="${escapeXml(dob)}" id_nbr="${escapeXml(idNbr)}"
         sname="${escapeXml(sname)}" fname="${escapeXml(fname)}" inits="${escapeXml(inits)}"
         gend="1" rlnship="0" status="O"/>
  </TX>
</DOCUMENT>`;
        break;

      default:
        return res.status(400).json({ error: `Unsupported action: ${action}` });
    }

    const soapEnvelope = buildSoapEnvelope(innerXml);
    const rawSoapResponse = await sendToMediKredit(soapEnvelope);
    let parsedResponse;
    try {
      parsedResponse = await parseMediKreditResponse(rawSoapResponse);
    } catch (parseErr) {
      // Return raw SOAP for debugging
      return res.status(200).json({
        success: false,
        error: parseErr.message,
        raw_soap: rawSoapResponse.substring(0, 3000)
      });
    }

    return res.json(parsedResponse);

  } catch (error) {
    console.error(`Error processing action ${action}:`, error);
    const axiosData = error.response ? error.response.data : null;
    return res.status(error.response ? error.response.status : 500).json({
      success: false,
      error: error.message,
      details: typeof axiosData === 'string' ? axiosData.substring(0, 2000) : axiosData
    });
  }
});

app.listen(PORT, () => {
  console.log(`MediKredit Express Adapter listening on port ${PORT} in ${MK_ENV} mode.`);
});
