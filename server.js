#!/usr/bin/env node
/**
 * ANDWELL CRM — FACEBOOK LEADS WEBHOOK SERVER
 * ─────────────────────────────────────────────
 * Receives Facebook Lead Ads webhooks and stores leads
 * so the Studio CRM sync script can pick them up.
 *
 * Deploy on Railway. Set these environment variables:
 *   FB_VERIFY_TOKEN   — any secret string you choose (e.g. "andwell2026")
 *   FB_APP_SECRET     — from Meta Developer App Settings > Basic
 *   PORT              — set automatically by Railway
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

// ─────────────────────────────────────────────────────────────
// CONFIG (from environment variables)
// ─────────────────────────────────────────────────────────────
const VERIFY_TOKEN = process.env.FB_VERIFY_TOKEN || 'andwell2026';
const APP_SECRET   = process.env.FB_APP_SECRET   || '';
const PORT         = parseInt(process.env.PORT)   || 3000;
const LEADS_FILE   = process.env.LEADS_FILE       || '/tmp/fb-leads.json';
const PAGE_TOKEN   = process.env.FB_PAGE_TOKEN    || '';

// ─────────────────────────────────────────────────────────────
// LEADS STORAGE
// ─────────────────────────────────────────────────────────────
function loadLeads() {
  try {
    if (fs.existsSync(LEADS_FILE)) {
      return JSON.parse(fs.readFileSync(LEADS_FILE, 'utf8'));
    }
  } catch {}
  return [];
}

function saveLeads(leads) {
  fs.writeFileSync(LEADS_FILE, JSON.stringify(leads, null, 2));
}

function addLead(lead) {
  const leads = loadLeads();
  // Dedup by leadgen_id
  if (leads.find(l => l.leadgenId === lead.leadgenId)) return false;
  leads.unshift(lead); // newest first
  saveLeads(leads);
  console.log(`✓ Lead saved: ${lead.firstName} ${lead.lastName} <${lead.email}>`);
  return true;
}

// ─────────────────────────────────────────────────────────────
// FACEBOOK API — fetch lead form data
// ─────────────────────────────────────────────────────────────
function fbGet(path) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'graph.facebook.com',
      path: `/v19.0/${path}`,
      headers: { 'Accept': 'application/json' },
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { reject(new Error(d)); } });
    });
    req.on('error', reject);
    req.end();
  });
}

async function fetchLeadData(leadgenId) {
  if (!PAGE_TOKEN) {
    console.warn('⚠ FB_PAGE_TOKEN not set — cannot fetch lead details');
    return null;
  }
  try {
    const data = await fbGet(`${leadgenId}?access_token=${PAGE_TOKEN}`);
    if (data.error) {
      console.error('FB API error:', data.error.message);
      return null;
    }
    return data;
  } catch (e) {
    console.error('Failed to fetch lead:', e.message);
    return null;
  }
}

function parseLeadFields(fieldData) {
  const fields = {};
  (fieldData.field_data || []).forEach(f => {
    fields[f.name] = (f.values || [])[0] || '';
  });

  const fullName = fields['full_name'] || fields['name'] || '';
  const nameParts = fullName.trim().split(' ');

  // Map fitness goal question (various wordings) to goals array
  const goalRaw = fields['what_is_your_main_fitness_goal'] ||
                  fields['fitness_goal'] ||
                  fields['main_goal'] ||
                  fields['your_fitness_goal'] ||
                  fields['what_are_your_fitness_goals'] || '';

  const goalMap = {
    'lose': 'Lose BF', 'fat': 'Lose BF', 'weight': 'Lose BF',
    'muscle': 'Gain Muscle', 'bulk': 'Gain Muscle', 'gain': 'Gain Muscle',
    'strength': 'Strength', 'strong': 'Strength',
    'consistent': 'Consistency', 'habit': 'Consistency',
    'energy': 'Energy', 'energi': 'Energy',
    'posture': 'Posture',
    'pull': 'Pull Up',
    'hyrox': 'Hyrox', 'race': 'Hyrox',
    'health': 'General Health', 'general': 'General Health',
  };

  const goals = [];
  if (goalRaw) {
    const lower = goalRaw.toLowerCase();
    for (const [kw, mapped] of Object.entries(goalMap)) {
      if (lower.includes(kw) && !goals.includes(mapped)) {
        goals.push(mapped);
      }
    }
    if (!goals.length) goals.push(goalRaw); // keep raw if no match
  }

  return {
    firstName:  nameParts[0] || fields['first_name'] || '',
    lastName:   nameParts.slice(1).join(' ') || fields['last_name'] || '',
    email:      (fields['email'] || '').toLowerCase(),
    phone:      fields['phone_number'] || fields['phone'] || '',
    goals,
    goalRaw,
    // Keep all raw fields for reference
    rawFields:  fields,
  };
}

// ─────────────────────────────────────────────────────────────
// WEBHOOK SIGNATURE VERIFICATION
// ─────────────────────────────────────────────────────────────
function verifySignature(rawBody, signature) {
  if (!APP_SECRET || !signature) return true; // skip if not configured
  const expected = 'sha256=' + crypto.createHmac('sha256', APP_SECRET)
    .update(rawBody).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch { return false; }
}

// ─────────────────────────────────────────────────────────────
// HTTP SERVER
// ─────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // ── GET /webhook — Facebook verification handshake ──────────
  if (req.method === 'GET' && url.pathname === '/webhook') {
    const mode      = url.searchParams.get('hub.mode');
    const token     = url.searchParams.get('hub.verify_token');
    const challenge = url.searchParams.get('hub.challenge');

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      console.log('✓ Facebook webhook verified');
      res.writeHead(200);
      res.end(challenge);
    } else {
      console.warn('✗ Webhook verification failed — token mismatch');
      res.writeHead(403);
      res.end('Forbidden');
    }
    return;
  }

  // ── POST /webhook — incoming lead event ─────────────────────
  if (req.method === 'POST' && url.pathname === '/webhook') {
    let rawBody = '';
    req.on('data', chunk => rawBody += chunk);
    req.on('end', async () => {
      // Verify signature
      const sig = req.headers['x-hub-signature-256'];
      if (!verifySignature(rawBody, sig)) {
        console.warn('✗ Invalid webhook signature');
        res.writeHead(403);
        res.end('Invalid signature');
        return;
      }

      // Always respond 200 immediately (Facebook requires this)
      res.writeHead(200);
      res.end('OK');

      // Process asynchronously
      try {
        const body = JSON.parse(rawBody);
        for (const entry of (body.entry || [])) {
          for (const change of (entry.changes || [])) {
            if (change.field !== 'leadgen') continue;
            const leadgenId = change.value?.leadgen_id;
            const formId    = change.value?.form_id;
            const pageId    = change.value?.page_id;
            if (!leadgenId) continue;

            console.log(`📥 New lead received: leadgen_id=${leadgenId}`);

            // Fetch full lead data from Facebook
            const leadData = await fetchLeadData(leadgenId);
            const parsed   = leadData ? parseLeadFields(leadData) : {};

            addLead({
              id:         `fb_${leadgenId}`,
              leadgenId,
              formId,
              pageId,
              source:     'facebook',
              status:     'New Lead',
              firstName:  parsed.firstName  || 'Unknown',
              lastName:   parsed.lastName   || '',
              email:      parsed.email      || '',
              phone:      parsed.phone      || '',
              goals:      parsed.goals      || [],
              goalRaw:    parsed.goalRaw    || '',
              rawFields:  parsed.rawFields  || {},
              receivedAt: new Date().toISOString(),
              needsContact: true,
              contacted:  false,
            });
          }
        }
      } catch (e) {
        console.error('Error processing webhook:', e.message);
      }
    });
    return;
  }

  // ── GET /leads — for sync script to fetch pending leads ─────
  if (req.method === 'GET' && url.pathname === '/leads') {
    const secret = url.searchParams.get('secret');
    if (secret !== VERIFY_TOKEN) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }
    const leads = loadLeads();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(leads));
    return;
  }

  // ── GET /leads/clear — mark all leads as synced ─────────────
  if (req.method === 'POST' && url.pathname === '/leads/clear') {
    const secret = url.searchParams.get('secret');
    if (secret !== VERIFY_TOKEN) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }
    saveLeads([]);
    res.writeHead(200);
    res.end('OK');
    return;
  }

  // ── GET / — health check ─────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/') {
    const leads = loadLeads();
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`Andwell CRM Webhook Server\nStatus: OK\nPending leads: ${leads.length}\nTime: ${new Date().toISOString()}\n`);
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════════╗`);
  console.log(`║   ANDWELL CRM — WEBHOOK SERVER             ║`);
  console.log(`║   Port: ${String(PORT).padEnd(35)}║`);
  console.log(`║   Verify token: ${VERIFY_TOKEN.slice(0,4)}...${String('').padEnd(27)}║`);
  console.log(`╚════════════════════════════════════════════╝\n`);
});
