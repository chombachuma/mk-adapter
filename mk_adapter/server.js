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
      rejectUnauthorized: true
    });
    agentLoadError = null;
    return cachedAgent;
  } catch (err) {
    agentLoadError = err.message;
    console.error('Error creating HTTPS agent with PFX certificate:', err);
    throw new Error(`Failed to initialize HTTPS mTLS Agent: ${err.message}`);
  }
}

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

function buildSoapEnvelope(innerXml) {
  const encodedXml = innerXml
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
  return `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:s2pi="http://www.medikredit.co.za/S2PI">
  <soapenv:Header/>
  <soapenv:Body>
    <s2pi:submit-claim>
      <request>${encodedXml}</request>
    </s2pi:submit-claim>
  </soapenv:Body>
</soapenv:Envelope>`;
}

async function sendToMediKredit(soapEnvelope) {
  const targetUrl = MK_ENV === 'prod' ? MEDIKREDIT_PROD_URL : MEDIKREDIT_TEST_URL;
  const agent = getHttpsAgent();
  const authHeader = 'Basic ' + Buffer.from(`${MK_USERNAME}:${MK_PASSWORD}`).toString('base64');
  const response = await axios.post(targetUrl, soapEnvelope, {
    httpsAgent: agent,
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      'SOAPAction': '""',
      'Authorization': authHeader,
      'Accept': 'text/xml, application/soap+xml',
    },
    timeout: 30000,
  });
  return response.data;
}

async function parseMediKreditResponse(rawSoapResponse) {
  const parser = new xml2js.Parser({ explicitArray: false });
  let parsedSoap;
  try {
    parsedSoap = await parser.parseStringPromise(rawSoapResponse);
  } catch (e) {
    throw new Error(`Failed to parse outer SOAP: ${e.message}`);
  }
  const body = parsedSoap?.['soapenv:Envelope']?.['soapenv:Body']
    || parsedSoap?.['SOAP-ENV:Envelope']?.['SOAP-ENV:Body']
    || parsedSoap?.Envelope?.Body;
  if (!body) throw new Error('No SOAP Body found');

  const replyWrapper = body?.['s2pi:submit-claimResponse'] || body?.['ns2:submit-claimResponse'] || {};
  let replyXml = replyWrapper?.return || replyWrapper?.reply || replyWrapper?.response || '';
  if (!replyXml) {
    const bodyStr = JSON.stringify(body);
    const match = bodyStr.match(/"(return|reply|response)"\s*:\s*"([^"]+)"/);
    if (match) replyXml = match[2].replace(/\\n/g, '\n').replace(/\\"/g, '"');
  }

  if (typeof replyXml === 'string' && replyXml.includes('&lt;')) {
    replyXml = replyXml.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&apos;/g, "'");
  }
  if (replyXml?.['_'] || replyXml?.['$']) {
    replyXml = replyXml['_'] || JSON.stringify(replyXml);
  }

  let innerParsed;
  try {
    innerParsed = await parser.parseStringPromise(replyXml);
  } catch (e) {
    throw new Error(`Failed to parse inner MK XML: ${e.message}. Raw: ${String(replyXml).substring(0, 200)}`);
  }

  const doc = innerParsed?.DOCUMENT || innerParsed;
  const tx = doc?.TX?.$;
  const rj = doc?.TX?.RJ;
  const auths = doc?.TX?.AUTHS;
  const cnt = doc?.TX?.CNT;

  const rejectionCode = rj ? (Array.isArray(rj) ? rj[0]?.$?.cd : rj?.$?.cd) : null;
  const rejectionDesc = rj ? (Array.isArray(rj) ? rj[0]?.$?.desc : rj?.$?.desc) : null;
  const gvNumber = auths?.$?.hnet || null;

  // Extract dependents for famcheck
  const patNodes = doc?.TX?.PAT;
  const dependents = [];
  if (patNodes) {
    const pats = Array.isArray(patNodes) ? patNodes : [patNodes];
    for (const p of pats) {
      const a = p?.$ || {};
      dependents.push({
        dep_cd: a.dep_cd || '',
        dob: a.dob || '',
        id_nbr: a.id_nbr || '',
        sname: a.sname || '',
        fname: a.fname || '',
        inits: a.inits || '',
        gender: a.gend || a.gender || '',
        status: a.st_descr || '',
      });
    }
  }

  return {
    success: tx?.res === 'A',
    res_code: tx?.res || null,
    gv_number: gvNumber,
    rejection_code: rejectionCode,
    rejection_desc: rejectionDesc,
    dependents,
    nbr_dependents: dependents.length,
    raw_xml: rawSoapResponse,
    parsed: innerParsed,
  };
}

function getTodayDate() {
  const d = new Date();
  return `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}`;
}

function generateTxNbr() {
  return `TX${Date.now()}${Math.floor(Math.random()*10000)}`;
}

// Health check
app.get('/health', (req, res) => {
  let pfxStatus = false;
  let pfxError = null;
  try {
    getHttpsAgent();
    pfxStatus = true;
  } catch (e) {
    pfxError = e.message;
  }
  res.json({ status: 'ok', env: MK_ENV, pfx_loaded: pfxStatus, error: pfxError });
});

app.post('/health', (req, res) => {
  res.json({ status: 'ok', env: MK_ENV });
});

// Main MediKredit proxy endpoint
app.post('/mk', async (req, res) => {
  const incomingSecret = req.headers['x-adapter-secret'];
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

  const dateStr = payload.date || getTodayDate();
  const txNbr = payload.tx_nbr || generateTxNbr();
  const spBhf = payload.sp_bhf || (action === 'smoketest' ? '0469939' : '');
  const spHpc = payload.sp_hpc || (action === 'smoketest' ? 'MP0672858' : '');
  const plan = payload.plan || (action === 'smoketest' ? '612346' : '');
  const chId = payload.ch_id || (action === 'smoketest' ? 'MK1990533' : '');
  const depCd = payload.dep_cd || '00';
  const sname = payload.sname || payload.mem_sname || 'TEST';
  const fname = payload.fname || payload.pat_fname || '';
  const inits = payload.inits || payload.mem_inits || 'T';
  const dob = (payload.dob || '19000101').replace(/-/g, '').slice(0, 8);
  const idNbr = payload.id_nbr || '';

  let innerXml = '';

  try {
    switch (action) {
      case 'smoketest':
      case 'claim':
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}"
      tx_nbr="${escapeXml(txNbr)}" plan="${escapeXml(plan)}"
      dt_cr="${escapeXml(dateStr)}" dt_os="${escapeXml(dateStr)}"
      tx_cd="20" nbr_items="1" pay_adv="P" clm_orig="E"
      msg_fmt="13" orig="03" bin="2" cntry_cd="ZA" sect_cd="PR">
    <VEND vend_id="2085" vend_ver="1.0.0"/>
    <MEM ch_id="${escapeXml(chId)}" sname="${escapeXml(sname)}" inits="${escapeXml(inits)}"/>
    <PAT dep_cd="${escapeXml(depCd)}" dob="${escapeXml(dob)}" id_nbr="${escapeXml(idNbr)}"
         sname="${escapeXml(sname)}" fname="${escapeXml(fname)}" inits="${escapeXml(inits)}"
         gend="1" rlnship="0" status="O"/>
    <ADDR line_1="BRYANSTON"/>
  </TX>
</DOCUMENT>`;
        break;

      case 'famcheck':
        // FIXED: ch_id must be in <MEM> child element, NOT on <TX> tag (S2PI spec tx_cd=30)
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}"
      tx_nbr="${escapeXml(txNbr)}" plan="${escapeXml(plan)}"
      dt_cr="${escapeXml(dateStr)}" dt_os="${escapeXml(dateStr)}"
      tx_cd="30" nbr_items="0" clm_orig="E"
      msg_fmt="13" orig="03" bin="2" cntry_cd="ZA" sect_cd="PR" pay_adv="P">
    <VEND vend_id="2085" vend_ver="1.0.0"/>
    <MEM ch_id="${escapeXml(chId)}" sname="${escapeXml(sname)}" inits="${escapeXml(inits)}"/>
    <PAT dep_cd="00" dob="" id_nbr=""
         sname="${escapeXml(sname)}" fname="${escapeXml(fname)}" inits="${escapeXml(inits)}"
         gend="1" rlnship="0" status="O"/>
    <ADDR line_1="BRYANSTON"/>
  </TX>
</DOCUMENT>`;
        break;

      case 'eligibility':
        // FIXED: ch_id in <MEM>, dep_cd in <PAT> (S2PI spec tx_cd=10)
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}"
      tx_nbr="${escapeXml(txNbr)}" plan="${escapeXml(plan)}"
      dt_cr="${escapeXml(dateStr)}" dt_os="${escapeXml(dateStr)}"
      tx_cd="10" nbr_items="0" clm_orig="E"
      msg_fmt="13" orig="03" bin="2" cntry_cd="ZA" sect_cd="PR" pay_adv="P">
    <VEND vend_id="2085" vend_ver="1.0.0"/>
    <MEM ch_id="${escapeXml(chId)}" sname="${escapeXml(sname)}" inits="${escapeXml(inits)}"/>
    <PAT dep_cd="${escapeXml(depCd)}" dob="${escapeXml(dob)}" id_nbr="${escapeXml(idNbr)}"
         sname="${escapeXml(sname)}" fname="${escapeXml(fname)}" inits="${escapeXml(inits)}"
         gend="1" rlnship="0" status="O"/>
    <ADDR line_1="BRYANSTON"/>
  </TX>
</DOCUMENT>`;
        break;

      case 'claim_reversal':
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}"
      tx_nbr="${escapeXml(txNbr)}" plan="${escapeXml(plan)}"
      dt_cr="${escapeXml(dateStr)}" dt_os="${escapeXml(dateStr)}"
      tx_cd="25" nbr_items="1" pay_adv="P" clm_orig="E"
      msg_fmt="13" orig="03" bin="2" cntry_cd="ZA" sect_cd="PR">
    <VEND vend_id="2085" vend_ver="1.0.0"/>
    <MEM ch_id="${escapeXml(chId)}" sname="${escapeXml(sname)}" inits="${escapeXml(inits)}"/>
  </TX>
</DOCUMENT>`;
        break;

      case 'resubmission':
        innerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT version="3.53" reply_tp="1">
  <TX sp_bhf="${escapeXml(spBhf)}" sp_hpc="${escapeXml(spHpc)}"
      tx_nbr="${escapeXml(txNbr)}" plan="${escapeXml(plan)}"
      dt_cr="${escapeXml(dateStr)}" dt_os="${escapeXml(dateStr)}"
      tx_cd="20" nbr_items="1" pay_adv="P" clm_orig="R"
      msg_fmt="13" orig="03" bin="2" cntry_cd="ZA" sect_cd="PR">
    <VEND vend_id="2085" vend_ver="1.0.0"/>
    <MEM ch_id="${escapeXml(chId)}" sname="${escapeXml(sname)}" inits="${escapeXml(inits)}"/>
    <PAT dep_cd="${escapeXml(depCd)}" dob="${escapeXml(dob)}" id_nbr="${escapeXml(idNbr)}"
         sname="${escapeXml(sname)}" fname="${escapeXml(fname)}" inits="${escapeXml(inits)}"
         gend="1" rlnship="0" status="O"/>
    <ADDR line_1="BRYANSTON"/>
  </TX>
</DOCUMENT>`;
        break;

      case 'raw_soap':
        // Passthrough: Base44 sends pre-built SOAP XML, adapter delivers via mTLS
        if (!payload.soap_body) {
          return res.status(400).json({ error: 'raw_soap requires payload.soap_body' });
        }
        try {
          const rawResult = await sendToMediKredit(payload.soap_body);
          let parsedRaw;
          try { parsedRaw = await parseMediKreditResponse(rawResult); } catch(_) { parsedRaw = null; }
          return res.json({ ...(parsedRaw || {}), raw_xml: rawResult });
        } catch(e) {
          return res.status(502).json({ error: e.message, raw_xml: '' });
        }

      default:
        return res.status(400).json({ error: `Unsupported action: ${action}` });
    }

    const soapEnvelope = buildSoapEnvelope(innerXml);
    const rawSoapResponse = await sendToMediKredit(soapEnvelope);
    let parsedResponse;
    try {
      parsedResponse = await parseMediKreditResponse(rawSoapResponse);
    } catch (parseErr) {
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
