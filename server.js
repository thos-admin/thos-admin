// THE HOUSE OF SERVICES — website + admin API
// One Render web service serves the public site (/), the admin panel (/admin) and the API (/api).

const dns = require('dns');
dns.setDefaultResultOrder('ipv4first'); // Render is IPv4-only; Supabase pooler resolves both

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { Pool, types } = require('pg');
types.setTypeParser(1082, (v) => v); // return DATE columns as 'YYYY-MM-DD' strings (no timezone shifts)
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) console.warn('[warn] JWT_SECRET not set: admin logins will reset on every restart.');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
});
pool.on('error', (e) => console.error('[db] idle client error', e.message));
const q = (text, params) => pool.query(text, params);

// Keep the pooler connection warm
setInterval(() => q('select 1').catch((e) => console.error('[db] ping failed', e.message)), 5 * 60 * 1000);

const app = express();
app.set('trust proxy', 1);
app.use('/api/admin/leads', express.json({ limit: '4mb' })); // proof screenshots
app.use(express.json({ limit: '200kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});

// ---------- tiny rate limiter ----------
function limiter(max, windowMs) {
  const hits = new Map();
  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    const rec = hits.get(key) || { n: 0, t: now };
    if (now - rec.t > windowMs) { rec.n = 0; rec.t = now; }
    rec.n++;
    hits.set(key, rec);
    if (hits.size > 5000) hits.clear();
    if (rec.n > max) return res.status(429).json({ error: 'Too many requests. Try again in a few minutes.' });
    next();
  };
}

const wrap = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((e) => {
  console.error('[api]', req.method, req.path, e.message);
  const msg = e.msgOverride ? e.msgOverride
            : e.status === 404 ? 'That record no longer exists.'
            : e.code === '23503' ? 'This record is linked to something that no longer exists, or is still used elsewhere.'
            : e.code === '23514' ? 'One of the values is not allowed. Check amounts are above zero and options are valid.'
            : e.code === '23505' ? 'That value already exists. Use a different one.'
            : e.code === '22P02' || e.code === '22007' || e.code === '22008' ? 'One of the fields has the wrong format. Check dates and amounts.'
            : 'Something went wrong on the server.';
  // in the admin panel, show the real reason so problems can be fixed quickly
  const detail = !e.msgOverride && !e.status && req.path.startsWith('/api/admin') ? ` (${e.message})` : '';
  res.status(e.status || 500).json({ error: msg + detail });
});

// ---------- health ----------
app.get('/healthz', (req, res) => res.json({ ok: true }));
// open /health/db in a browser to check the database connection and tables
app.get('/health/db', async (req, res) => {
  const out = {};
  try { await pool.query('select 1'); out.connection = 'ok'; } catch (e) { out.connection = 'FAILED: ' + e.message; return res.status(500).json(out); }
  for (const t of ['clients', 'transactions', 'retainer_months', 'contracts', 'leads', 'settings', 'client_balances']) {
    try { out[t] = Number((await pool.query(`select count(*) n from ${t}`)).rows[0].n); } catch (e) { out[t] = 'MISSING: ' + e.message; }
  }
  try { await pool.query('select charge_tx_id from retainer_months limit 1'); out.schema = 'latest'; } catch (e) { out.schema = 'OLD, run schema.sql again: ' + e.message; }
  res.status(Object.values(out).some(v => String(v).match(/MISSING|OLD|FAILED/)) ? 500 : 200).json(out);
});

// ---------- public API ----------
// The website may be hosted separately (e.g. Netlify/Afrihost); allow it to call these two public routes.
app.use(['/api/portfolio', '/api/leads'], (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.WEBSITE_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.get('/api/portfolio', wrap(async (req, res) => {
  const { rows } = await q('select id, name, category, url, blurb, image_url from portfolio where visible order by sort, id');
  res.set('Cache-Control', 'public, max-age=300').json(rows);
}));

app.post('/api/leads', limiter(8, 15 * 60 * 1000), wrap(async (req, res) => {
  const b = req.body || {};
  if (b.website) return res.json({ ok: true }); // honeypot
  const clean = (v, n = 500) => (typeof v === 'string' ? v.trim().slice(0, n) : '') || null;
  const name = clean(b.name, 120);
  const email = clean(b.email, 160);
  const phone = clean(b.phone, 40);
  if (!name) return res.status(400).json({ error: 'Add your name so we know who to reply to.' });
  if (!email && !phone) return res.status(400).json({ error: 'Add an email address or phone number so we can get back to you.' });
  const services = Array.isArray(b.services) ? b.services.map((s) => String(s).slice(0, 60)).slice(0, 12).join(', ') : clean(b.services, 400);
  // quote builder answers: { "Websites & web apps": { "What do you need?": "Landing page", ... }, ... }
  let details = null;
  if (b.details && typeof b.details === 'object' && !Array.isArray(b.details)) {
    const json = JSON.stringify(b.details);
    if (json.length <= 20000) details = json;
  }
  const lead = [name, clean(b.business, 160), email, phone, services, clean(b.message, 3000), details, clean(b.budget, 60), clean(b.timeline, 60), clean(b.contact_pref, 30)];
  const { rows } = await q(
    `insert into leads (name, business, email, phone, services, message, details, budget, timeline, contact_pref)
     values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10) returning id`, lead);
  const ref = 'Q-' + String(rows[0].id).padStart(4, '0');
  notifyLead({ ref, name, business: lead[1], email, phone, services, message: lead[5], details: b.details, budget: lead[7], timeline: lead[8], pref: lead[9] });
  res.json({ ok: true, ref });
}));

function notifyLead(l) {
  if (!process.env.SMTP_HOST || !process.env.NOTIFY_EMAIL) return;
  const nodemailer = require('nodemailer');
  const t = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_PORT || 465) === '465',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  const lines = [
    `Reference: ${l.ref}`, `Name: ${l.name}`, `Business: ${l.business || '-'}`, `Email: ${l.email || '-'}`, `Phone: ${l.phone || '-'}`,
    `Prefers: ${l.pref || '-'}`, `Services: ${l.services || '-'}`, `Budget: ${l.budget || '-'}`, `Timeline: ${l.timeline || '-'}`, '',
  ];
  if (l.details && typeof l.details === 'object') {
    for (const [svc, answers] of Object.entries(l.details)) {
      lines.push(`== ${svc} ==`);
      for (const [qn, ans] of Object.entries(answers || {})) lines.push(`${qn.replace(/\?$/, "")}: ${Array.isArray(ans) ? ans.join(', ') : ans}`);
      lines.push('');
    }
  }
  lines.push(l.message || '(no extra notes)');
  t.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: process.env.NOTIFY_EMAIL,
    replyTo: l.email || undefined,
    subject: `${l.ref} quote request: ${l.name}${l.business ? ' (' + l.business + ')' : ''}`,
    text: lines.join('\n'),
  }).catch((e) => console.error('[mail]', e.message));
}

// ---------- auth ----------
app.post('/api/login', limiter(10, 15 * 60 * 1000), wrap(async (req, res) => {
  const pw = String((req.body || {}).password || '');
  if (!pw) return res.status(401).json({ error: 'Type your password.' });
  let ok = false;
  if (process.env.ADMIN_PASSWORD_HASH) ok = await bcrypt.compare(pw, process.env.ADMIN_PASSWORD_HASH);
  else if (process.env.ADMIN_PASSWORD) {
    const a = Buffer.from(pw), b = Buffer.from(process.env.ADMIN_PASSWORD);
    ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  if (ok) return res.json({ token: jwt.sign({ role: 'admin', name: 'Owner' }, JWT_SECRET, { expiresIn: '12h' }), role: 'admin', name: 'Owner' });
  // not the owner: each salesperson has their own password, which tells us who they are
  const u = await findUserByPassword(pw);
  if (!u) return res.status(401).json({ error: 'That password is incorrect.' });
  res.json({ token: jwt.sign({ role: u.role, uid: u.id, name: u.name }, JWT_SECRET, { expiresIn: '12h' }), role: u.role, name: u.name });
}));

async function findUserByPassword(pw, activeOnly = true) {
  let users = [];
  try { users = (await q(`select * from app_users ${activeOnly ? 'where active' : ''}`)).rows; } catch { return null; } // table not created yet
  for (const u of users) if (await bcrypt.compare(pw, u.password_hash)) return u;
  return null;
}
async function isOwnerPassword(pw) {
  if (process.env.ADMIN_PASSWORD_HASH) return bcrypt.compare(pw, process.env.ADMIN_PASSWORD_HASH);
  return !!process.env.ADMIN_PASSWORD && pw === process.env.ADMIN_PASSWORD;
}
// Passwords must be unique, because the password is what identifies the person.
async function checkNewPassword(pw, exceptId) {
  if (pw.length < 6) throw badReq('Password must be at least 6 characters.');
  if (await isOwnerPassword(pw)) throw badReq("That's your owner password. Choose a different one.");
  const u = await findUserByPassword(pw, false);
  if (u && String(u.id) !== String(exceptId)) throw badReq('Someone else already uses that password. Choose a different one.');
}

// Salespeople can only reach the leads routes, and can't delete anything.
const ALLOWED = {
  sales: /^\/api\/admin\/(me|lead-stats|leads(\/\d+(\/(activity|contact))?)?|proofs\/\d+)$/,
  staff: /^\/api\/admin\/(me|time|time\/(clients|clock-in|clock-out))$/,
};
async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const path = req.originalUrl.split('?')[0];
  let token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token && req.query.t && path.startsWith('/api/admin/proofs/')) token = String(req.query.t); // proof images open in a new tab
  try { req.user = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Your session has ended. Log in again.' }); }
  if (req.user.role === 'admin') return next();
  try {
    const u = (await q('select active from app_users where id=$1', [req.user.uid])).rows[0];
    if (!u || !u.active) return res.status(401).json({ error: 'Your login has been switched off. Speak to the owner.' });
  } catch (e) { return res.status(500).json({ error: 'Something went wrong on the server.' }); }
  const ok = ALLOWED[req.user.role];
  if (!ok || !ok.test(path) || req.method === 'DELETE') return res.status(403).json({ error: 'You don\'t have access to that.' });
  next();
}
app.use('/api/admin', auth);
const isAdmin = (req) => req.user && req.user.role === 'admin';
const who = (req) => ({ id: req.user.uid || null, name: req.user.name || 'Owner' });
app.get('/api/admin/me', (req, res) => res.json({ role: req.user.role, name: req.user.name || 'Owner' }));

// ---------- leads + activity log (owner and salespeople) ----------
const LEAD_COLS = ['name', 'business', 'email', 'phone', 'services', 'message', 'status', 'budget', 'timeline', 'contact_pref'];
const LEAD_STATUS = ['new', 'contacted', 'follow_up', 'quoted', 'won', 'lost'];
const HOW = { call: 'Call', whatsapp: 'WhatsApp', email: 'Email', sms: 'SMS', meeting: 'Meeting', walk_in: 'Walk-in', other: 'Other' };
const badReq = (msg) => { const e = new Error(msg); e.status = 400; e.msgOverride = msg; return e; };

function parseProof(p) {
  if (!p) return null;
  const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(p));
  if (!m) throw badReq('The proof must be a photo or screenshot.');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 3e6) throw badReq('That picture is too big. Try a screenshot instead.');
  return { mime: m[1], buf };
}
async function addActivity(db, leadId, u, kind, { how = null, note = null, status = null, proof = null } = {}) {
  const a = (await db.query(
    `insert into lead_activity (lead_id, user_id, user_name, kind, how, note, status_to) values ($1,$2,$3,$4,$5,$6,$7) returning *`,
    [leadId, u.id, u.name, kind, how, note, status])).rows[0];
  if (proof) await db.query('insert into lead_proofs (activity_id, mime, data) values ($1,$2,$3)', [a.id, proof.mime, proof.buf]);
  await db.query('update leads set updated_at=now() where id=$1', [leadId]);
  return a;
}
function leadBody(b, required) {
  const v = {};
  for (const c of LEAD_COLS) if (c in b) v[c] = toNull(typeof b[c] === 'string' ? b[c].trim() : b[c]);
  if (required || 'name' in v) if (!v.name) throw badReq("Add the lead's name.");
  if (required && !v.phone && !v.email) throw badReq('Add a phone number or email.');
  if (v.status && !LEAD_STATUS.includes(v.status)) throw badReq('Choose a valid status.');
  return v;
}

app.get('/api/admin/leads', wrap(async (req, res) => {
  const { rows } = await q(`
    select l.*, la.created_at as last_at, la.user_name as last_by, la.how as last_how,
      (select count(*) from lead_activity x where x.lead_id=l.id and x.kind in ('created','contact'))::int as touches
    from leads l
    left join lateral (select created_at, user_name, how from lead_activity a where a.lead_id=l.id and a.kind in ('created','contact')
                       order by created_at desc limit 1) la on true
    order by l.created_at desc`);
  res.json(rows);
}));

app.post('/api/admin/leads', wrap(async (req, res) => {
  const b = req.body || {}, u = who(req);
  const v = leadBody(b, true);
  const proof = parseProof(b.proof);
  if (!isAdmin(req) && !proof) throw badReq('Upload proof that you contacted this lead: a screenshot of the call log, WhatsApp chat or email.');
  const how = HOW[b.how] ? b.how : null;
  if (!isAdmin(req) && !how) throw badReq('Choose how you contacted them.');
  v.status = v.status || (how ? 'contacted' : 'new');
  const lead = await inTx(async (db) => {
    const cols = [...Object.keys(v), 'created_by'], vals = [...Object.values(v), u.name];
    const l = (await db.query(`insert into leads (${cols.join(',')}) values (${cols.map((_, i) => '$' + (i + 1)).join(',')}) returning *`, vals)).rows[0];
    await addActivity(db, l.id, u, 'created', { how, note: toNull(b.note), status: l.status, proof });
    return l;
  });
  res.json(lead);
}));

app.put('/api/admin/leads/:id', wrap(async (req, res) => {
  const v = leadBody(req.body || {}, false);
  if (!Object.keys(v).length) throw badReq('Nothing to save.');
  const out = await inTx(async (db) => {
    const old = (await db.query('select * from leads where id=$1 for update', [req.params.id])).rows[0];
    if (!old) { const e = new Error('gone'); e.status = 404; throw e; }
    const changed = Object.keys(v).filter((k) => String(old[k] ?? '') !== String(v[k] ?? ''));
    if (!changed.length) return old;
    const cols = Object.keys(v);
    const l = (await db.query(`update leads set ${cols.map((c, i) => `${c}=$${i + 1}`).join(',')} where id=$${cols.length + 1} returning *`, [...Object.values(v), req.params.id])).rows[0];
    await addActivity(db, l.id, who(req), 'edited', { note: 'Changed ' + changed.map((c) => c.replace('_', ' ')).join(', '), status: changed.includes('status') ? l.status : null });
    return l;
  });
  res.json(out);
}));

app.delete('/api/admin/leads/:id', wrap(async (req, res) => {
  await q('delete from leads where id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// log a contact: call / WhatsApp / email..., with proof
app.post('/api/admin/leads/:id/contact', wrap(async (req, res) => {
  const b = req.body || {}, u = who(req);
  const how = HOW[b.how] ? b.how : null;
  if (!how) throw badReq('Choose how you contacted them.');
  const proof = parseProof(b.proof);
  if (!isAdmin(req) && !proof) throw badReq('Upload proof: a screenshot of the call log, WhatsApp chat or email.');
  const status = b.status && LEAD_STATUS.includes(b.status) ? b.status : null;
  const out = await inTx(async (db) => {
    const l = (await db.query('select * from leads where id=$1 for update', [req.params.id])).rows[0];
    if (!l) { const e = new Error('gone'); e.status = 404; throw e; }
    if (status && status !== l.status) await db.query('update leads set status=$1 where id=$2', [status, l.id]);
    return addActivity(db, l.id, u, 'contact', { how, note: toNull(b.note), status: status && status !== l.status ? status : null, proof });
  });
  res.json(out);
}));

app.get('/api/admin/leads/:id/activity', wrap(async (req, res) => {
  const { rows } = await q(`select a.*, (p.id is not null) as has_proof from lead_activity a left join lead_proofs p on p.activity_id=a.id
    where a.lead_id=$1 order by a.created_at desc, a.id desc`, [req.params.id]);
  res.json(rows);
}));

app.get('/api/admin/proofs/:activityId', wrap(async (req, res) => {
  const p = (await q('select mime, data from lead_proofs where activity_id=$1', [req.params.activityId])).rows[0];
  if (!p) return res.status(404).send('Not found');
  res.set('Cache-Control', 'private, max-age=86400').type(p.mime).send(p.data);
}));

// how much each person did per day (SA time). Salespeople only see their own.
app.get('/api/admin/lead-stats', wrap(async (req, res) => {
  const mine = isAdmin(req) ? '' : 'and a.user_id = $1';
  const params = isAdmin(req) ? [] : [req.user.uid];
  const { rows } = await q(`
    select to_char((a.created_at at time zone 'Africa/Johannesburg')::date, 'YYYY-MM-DD') as day, a.user_name,
      count(*) filter (where a.kind in ('created','contact'))::int as contacts,
      count(*) filter (where a.kind = 'created')::int as new_leads,
      count(*) filter (where a.status_to = 'won')::int as won,
      min(a.created_at) as first_at, max(a.created_at) as last_at
    from lead_activity a
    where a.created_at >= now() - interval '14 days' and a.kind in ('created','contact') ${mine}
    group by 1, 2 order by 1 desc, 2`, params);
  res.json(rows);
}));

// ---------- time tracking: employees clock in / out per client ----------
// Hours are worked out from the start and end times. Cost = hours x the rate saved on the entry.
const TIME_SELECT = `select t.*, c.name as client_name,
    round((extract(epoch from (coalesce(t.ended_at, now()) - t.started_at)) / 3600.0)::numeric, 2) as hours
  from time_entries t join clients c on c.id = t.client_id`;

app.get('/api/admin/time/clients', wrap(async (req, res) => {
  res.json((await q(`select id, name, billing, retainer_active from clients order by (billing='retainer' and retainer_active) desc, lower(name)`)).rows);
}));

app.post('/api/admin/time/clock-in', wrap(async (req, res) => {
  const b = req.body || {}, u = who(req);
  if (!u.id) throw badReq('Clocking in is for employee logins.');
  if (!b.client_id) throw badReq('Choose the client you are working on.');
  const out = await inTx(async (db) => {
    // switching client? close the running one first
    await db.query(`update time_entries set ended_at = now() where user_id = $1 and ended_at is null`, [u.id]);
    const rate = (await db.query('select hourly_rate from app_users where id=$1', [u.id])).rows[0]?.hourly_rate || 0;
    return (await db.query(`insert into time_entries (user_id, user_name, client_id, started_at, note, rate) values ($1,$2,$3,now(),$4,$5) returning *`,
      [u.id, u.name, b.client_id, toNull(b.note), rate])).rows[0];
  });
  res.json(out);
}));

app.post('/api/admin/time/clock-out', wrap(async (req, res) => {
  const b = req.body || {}, u = who(req);
  const e = (await q(`update time_entries set ended_at = now(), note = coalesce($2, note) where user_id = $1 and ended_at is null returning *`, [u.id, toNull(b.note)])).rows[0];
  if (!e) throw badReq("You're not clocked in.");
  res.json(e);
}));

// employees: their own entries (last 60 days). owner: everyone, with filters.
app.get('/api/admin/time', wrap(async (req, res) => {
  if (!isAdmin(req)) {
    const { rows } = await q(`${TIME_SELECT} where t.user_id = $1 and t.started_at >= now() - interval '60 days' order by t.started_at desc`, [req.user.uid]);
    return res.json(rows.map(({ rate, ...r }) => r)); // employees don't see rates
  }
  const { rows } = await q(`${TIME_SELECT} where t.started_at >= now() - interval '400 days' order by t.started_at desc`);
  res.json(rows);
}));

function timeBody(b) {
  const start = b.started_at ? new Date(b.started_at) : null, end = b.ended_at ? new Date(b.ended_at) : null;
  if (!b.user_id) throw badReq('Choose the employee.');
  if (!b.client_id) throw badReq('Choose the client.');
  if (!start || isNaN(start)) throw badReq('Add a start time.');
  if (end && (isNaN(end) || end <= start)) throw badReq('The end time must be after the start time.');
  if (end && end - start > 24 * 3600e3) throw badReq('One entry can be at most 24 hours.');
  return { start, end };
}
app.post('/api/admin/time', wrap(async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "You don't have access to that." });
  const b = req.body || {}, { start, end } = timeBody(b);
  const u = (await q('select name, hourly_rate from app_users where id=$1', [b.user_id])).rows[0];
  if (!u) throw badReq('Choose the employee.');
  const rate = b.rate !== undefined && b.rate !== '' ? Number(b.rate) || 0 : u.hourly_rate;
  res.json((await q(`insert into time_entries (user_id, user_name, client_id, started_at, ended_at, note, rate, edited)
    values ($1,$2,$3,$4,$5,$6,$7,true) returning *`, [b.user_id, u.name, b.client_id, start, end, toNull(b.note), rate])).rows[0]);
}));
app.put('/api/admin/time/:id', wrap(async (req, res) => {
  const b = req.body || {}, { start, end } = timeBody(b);
  const u = (await q('select name from app_users where id=$1', [b.user_id])).rows[0];
  const e = (await q(`update time_entries set user_id=$1, user_name=coalesce($2, user_name), client_id=$3, started_at=$4, ended_at=$5, note=$6,
      rate=coalesce($7, rate), edited=true where id=$8 returning *`,
    [b.user_id, u && u.name, b.client_id, start, end, toNull(b.note), b.rate === undefined || b.rate === '' ? null : Number(b.rate) || 0, req.params.id])).rows[0];
  if (!e) { const er = new Error('gone'); er.status = 404; throw er; }
  res.json(e);
}));
app.delete('/api/admin/time/:id', wrap(async (req, res) => {
  await q('delete from time_entries where id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// ---------- team logins (owner only) ----------
app.get('/api/admin/users', wrap(async (req, res) => {
  const { rows } = await q(`select u.id, u.name, u.username, u.role, u.active, u.created_at, u.hourly_rate,
      greatest((select max(created_at) from lead_activity a where a.user_id=u.id), (select max(coalesce(ended_at, started_at)) from time_entries t where t.user_id=u.id)) as last_at
    from app_users u order by u.active desc, lower(u.name)`);
  res.json(rows);
}));
app.post('/api/admin/users', wrap(async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim(), pw = String(b.password || '');
  const role = b.role === 'staff' ? 'staff' : 'sales', rate = Math.max(0, Number(b.hourly_rate) || 0);
  if (!name) throw badReq('Add their name.');
  await checkNewPassword(pw);
  const username = (name.toLowerCase().replace(/[^a-z0-9]+/g, '.') || 'user') + '.' + crypto.randomBytes(3).toString('hex'); // internal only
  try {
    const u = (await q(`insert into app_users (name, username, password_hash, role, hourly_rate) values ($1,$2,$3,$4,$5) returning id, name, username, role, hourly_rate, active`, [name, username, await bcrypt.hash(pw, 10), role, rate])).rows[0];
    res.json(u);
  } catch (e) { if (e.code === '23505') throw badReq('Try again.'); throw e; }
}));
app.put('/api/admin/users/:id', wrap(async (req, res) => {
  const b = req.body || {}, sets = [], vals = [];
  if (typeof b.name === 'string' && b.name.trim()) { vals.push(b.name.trim()); sets.push(`name=$${vals.length}`); }
  if (typeof b.active === 'boolean') { vals.push(b.active); sets.push(`active=$${vals.length}`); }
  if (b.hourly_rate !== undefined && b.hourly_rate !== '') { vals.push(Math.max(0, Number(b.hourly_rate) || 0)); sets.push(`hourly_rate=$${vals.length}`); }
  if (['sales', 'staff'].includes(b.role)) { vals.push(b.role); sets.push(`role=$${vals.length}`); }
  if (b.password) { await checkNewPassword(String(b.password), req.params.id); vals.push(await bcrypt.hash(String(b.password), 10)); sets.push(`password_hash=$${vals.length}`); }
  if (!sets.length) throw badReq('Nothing to save.');
  vals.push(req.params.id);
  const u = (await q(`update app_users set ${sets.join(',')} where id=$${vals.length} returning id, name, username, role, hourly_rate, active`, vals)).rows[0];
  if (!u) { const e = new Error('gone'); e.status = 404; throw e; }
  res.json(u);
}));

// ---------- generic CRUD ----------
const toNull = (v) => (v === '' || v === undefined ? null : v);
const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const monthLabel = (y, m) => `${MONTHS[m - 1]} ${y}`;

const resources = {
  contracts: {
    cols: ['client_id', 'title', 'kind', 'value', 'start_date', 'end_date', 'status', 'file_url', 'notes'],
    list: `select t.*, c.name client_name from contracts t join clients c on c.id=t.client_id order by t.status='active' desc, t.end_date nulls last, t.id desc`,
  },
};

for (const [table, cfg] of Object.entries(resources)) {
  const base = `/api/admin/${table}`;
  app.get(base, wrap(async (req, res) => res.json((await q(cfg.list)).rows)));
  app.post(base, wrap(async (req, res) => {
    const cols = cfg.cols.filter((c) => c in req.body);
    if (!cols.length) return res.status(400).json({ error: 'Nothing to save.' });
    const vals = cols.map((c) => toNull(req.body[c]));
    const sql = `insert into ${table} (${cols.join(',')}) values (${cols.map((_, i) => '$' + (i + 1)).join(',')}) returning *`;
    res.json((await q(sql, vals)).rows[0]);
  }));
  app.put(`${base}/:id`, wrap(async (req, res) => {
    const cols = cfg.cols.filter((c) => c in req.body);
    if (!cols.length) return res.status(400).json({ error: 'Nothing to save.' });
    const vals = cols.map((c) => toNull(req.body[c]));
    const sql = `update ${table} set ${cols.map((c, i) => `${c}=$${i + 1}`).join(',')} where id=$${cols.length + 1} returning *`;
    const { rows } = await q(sql, [...vals, req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'That record no longer exists.' });
    res.json(rows[0]);
  }));
  app.delete(`${base}/:id`, wrap(async (req, res) => {
    await q(`delete from ${table} where id=$1`, [req.params.id]);
    res.json({ ok: true });
  }));
}

// ---------- retainer months: create the year, roll over, tick off ----------
// Every active retainer gets 12 months for the year (N/A before they started, otherwise "not billed yet").
async function ensureRetainerYear(db, year) {
  await db.query(`
    insert into retainer_months (client_id, year, month, status, amount, billable)
    select c.id, $1::int, m,
      case when make_date($1::int, m, 1) < date_trunc('month', coalesce(c.retainer_start, current_date))::date then 'na' else null end,
      0, true
    from clients c cross join generate_series(1, 12) m
    where c.billing = 'retainer' and c.retainer_active
      and (c.retainer_start is null or date_trunc('year', c.retainer_start) <= make_date($1::int, 1, 1))
    on conflict (client_id, year, month) do nothing`, [year]);
}
async function syncRetainers(db = pool) { await ensureRetainerYear(db, new Date().getFullYear()); }

// Tick off the oldest billed, unpaid months a payment fully covers. Returns the months ticked.
async function allocatePayment(db, tx) {
  if (tx.type !== 'payment' || !tx.client_id) return [];
  const { rows: months } = await db.query(
    `select id, year, month, amount from retainer_months
     where client_id=$1 and status='not_rec' and amount > 0 and tx_id is null order by year, month`, [tx.client_id]);
  let left = Number(tx.amount);
  const ticked = [];
  for (const m of months) {
    if (left + 0.001 < Number(m.amount)) break;
    await db.query(`update retainer_months set status='rec', tx_id=$1 where id=$2`, [tx.id, m.id]);
    left -= Number(m.amount);
    ticked.push(monthLabel(m.year, m.month));
  }
  // Balance fully cleared? Then any months still "not received" (e.g. ones inside the opening balance) are paid too.
  const bal = (await db.query(`select charges - paid as b from client_balances where client_id=$1`, [tx.client_id])).rows[0];
  if (bal && Number(bal.b) <= 0.001) {
    const rest = (await db.query(`update retainer_months set status='rec', tx_id=$1 where client_id=$2 and status='not_rec' returning year, month`, [tx.id, tx.client_id])).rows;
    rest.sort((x, y) => x.year - y.year || x.month - y.month).forEach((m) => ticked.push(monthLabel(m.year, m.month)));
  }
  return ticked;
}
async function releasePayment(db, txId) {
  await db.query(`update retainer_months set status='not_rec', tx_id=null where tx_id=$1 and status='rec'`, [txId]);
  await db.query(`update retainer_months set tx_id=null where tx_id=$1`, [txId]);
}
// A month's "amount owed" was changed or removed in Transactions: keep the month in step
async function syncChargeMonths(db, tx, deleted) {
  if (deleted) {
    await db.query(`update retainer_months set amount=0, charge_tx_id=null, status=case when status='not_rec' then null else status end where charge_tx_id=$1`, [tx.id]);
  } else {
    await db.query(`update retainer_months set amount=$2 where charge_tx_id=$1`, [tx.id, tx.amount]);
  }
}
// Bill (or re-bill) one month for one client. amount 0 = remove the bill.
async function billMonth(db, clientId, year, month, amount) {
  amount = Number(amount) || 0;
  await db.query(`insert into retainer_months (client_id, year, month, status, amount) values ($1,$2,$3,null,0) on conflict do nothing`, [clientId, year, month]);
  const m = (await db.query('select * from retainer_months where client_id=$1 and year=$2 and month=$3 for update', [clientId, year, month])).rows[0];
  if (m.charge_tx_id) {
    if (amount > 0) await db.query('update transactions set amount=$2 where id=$1', [m.charge_tx_id, amount]);
    else await db.query('delete from transactions where id=$1', [m.charge_tx_id]);
  } else if (amount > 0) {
    const txId = (await db.query(
      `insert into transactions (tx_date, type, client_id, amount, description) values ($1, 'charge', $2, $3, $4) returning id`,
      [todaySA(), clientId, amount, `Retainer ${monthLabel(year, month)}`])).rows[0].id;
    await db.query('update retainer_months set charge_tx_id=$1 where id=$2', [txId, m.id]);
  }
  const status = amount > 0 ? (m.status === 'rec' ? 'rec' : 'not_rec') : (m.status === 'not_rec' ? null : m.status);
  return (await db.query(`update retainer_months set amount=$1::numeric, status=$2, billable=true, charge_tx_id=case when $1::numeric > 0 then charge_tx_id else null end where id=$3 returning *`, [amount, status, m.id])).rows[0];
}
const todaySA = () => new Date(Date.now() + 2 * 3600e3).toISOString().slice(0, 10);

async function inTx(fn) {
  const db = await pool.connect();
  try { await db.query('begin'); const out = await fn(db); await db.query('commit'); return out; }
  catch (e) { await db.query('rollback').catch(() => {}); throw e; }
  finally { db.release(); }
}

const BAL = `(b.charges - b.paid)`;

// ---------- clients ----------
const CLIENT_COLS = ['name', 'contact_person', 'email', 'phone', 'address', 'industry', 'notes', 'billing', 'retainer_active', 'retainer_start'];

app.get('/api/admin/clients', wrap(async (req, res) => {
  await syncRetainers();
  const { rows } = await q(`
    select c.*, ${BAL} as balance,
      (select count(*) from retainer_months m where m.client_id=c.id and m.status='not_rec')::int as months_unpaid
    from clients c join client_balances b on b.client_id=c.id
    order by lower(c.name)`);
  res.json(rows);
}));

async function applyRetainerChange(db, before, after) {
  const now = new Date(); const y = now.getFullYear(), m = now.getMonth() + 1;
  const wasRet = before.billing === 'retainer' && before.retainer_active;
  const isRet = after.billing === 'retainer' && after.retainer_active;
  if (wasRet && !isRet) {
    // cancelled: every unbilled month after this one becomes N/A
    await db.query(`update retainer_months set status='na' where client_id=$1 and (year > $2 or (year = $2 and month > $3)) and status is null and charge_tx_id is null`, [after.id, y, m]);
  } else if (!wasRet && isRet) {
    await db.query(`update retainer_months set status=null where client_id=$1 and status='na' and charge_tx_id is null and (year > $2 or (year = $2 and month > $3))`, [after.id, y, m]);
    await ensureRetainerYear(db, y);
  }
}

app.post('/api/admin/clients', wrap(async (req, res) => {
  const b = req.body || {};
  if (!String(b.name || '').trim()) return res.status(400).json({ error: 'Add the client name.' });
  const cols = CLIENT_COLS.filter((c) => c in b);
  const vals = cols.map((c) => toNull(b[c]));
  const row = await inTx(async (db) => {
    const r = (await db.query(`insert into clients (${cols.join(',')}) values (${cols.map((_, i) => '$' + (i + 1)).join(',')}) returning *`, vals)).rows[0];
    if (r.billing === 'retainer' && r.retainer_active) await ensureRetainerYear(db, new Date().getFullYear());
    return r;
  });
  res.json(row);
}));

app.put('/api/admin/clients/:id', wrap(async (req, res) => {
  const b = req.body || {};
  const cols = CLIENT_COLS.filter((c) => c in b);
  if (!cols.length) return res.status(400).json({ error: 'Nothing to save.' });
  const row = await inTx(async (db) => {
    const before = (await db.query('select * from clients where id=$1 for update', [req.params.id])).rows[0];
    if (!before) { const e = new Error('gone'); e.status = 404; throw e; }
    const vals = cols.map((c) => toNull(b[c]));
    const after = (await db.query(`update clients set ${cols.map((c, i) => `${c}=$${i + 1}`).join(',')} where id=$${cols.length + 1} returning *`, [...vals, req.params.id])).rows[0];
    await applyRetainerChange(db, before, after);
    return after;
  });
  res.json(row);
}));

app.delete('/api/admin/clients/:id', wrap(async (req, res) => {
  await q('delete from clients where id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// ---------- transactions ----------
const TX_COLS = ['tx_date', 'type', 'client_id', 'amount', 'description', 'method', 'reference'];
function txValues(b) {
  const bad = (msg) => { const e = new Error(msg); e.status = 400; e.msgOverride = msg; throw e; };
  if (!['payment', 'expense', 'charge', 'credit'].includes(b.type)) bad('Choose what kind of transaction this is.');
  if (!(Number(b.amount) > 0)) bad('Enter an amount above zero.');
  if (['charge', 'credit'].includes(b.type) && !b.client_id) bad('Choose the client.');
  if (b.type !== 'payment' && !b.description && !b.client_id) bad('Add details, for example: Shopify, Meta ads, Kwik Print.');
  const v = { ...b, tx_date: b.tx_date || todaySA() };
  if (b.type === 'expense') v.client_id = null;   // money out is never linked to a debtor
  return TX_COLS.map((c) => toNull(v[c]));
}
const MONTHS_FOR = (col) => `(select string_agg(to_char(make_date(m.year, m.month, 1), 'Mon YYYY'), ', ' order by m.year, m.month) from retainer_months m where m.${col} = t.id)`;

app.get('/api/admin/transactions', wrap(async (req, res) => {
  const { rows } = await q(`
    select t.*, c.name client_name, c.billing, ${MONTHS_FOR('tx_id')} as months, ${MONTHS_FOR('charge_tx_id')} as billed_for,
      case when t.type in ('payment','expense') then
        sum(case t.type when 'payment' then t.amount when 'expense' then -t.amount else 0 end) over (order by t.tx_date, t.id)
      end as running
    from transactions t left join clients c on c.id = t.client_id
    order by t.tx_date desc, t.id desc`);
  res.json(rows);
}));

app.post('/api/admin/transactions', wrap(async (req, res) => {
  const b = req.body || {};
  const vals = txValues(b);
  const out = await inTx(async (db) => {
    const tx = (await db.query(`insert into transactions (${TX_COLS.join(',')}) values (${TX_COLS.map((_, i) => '$' + (i + 1)).join(',')}) returning *`, vals)).rows[0];
    const ticked = b.allocate === false ? [] : await allocatePayment(db, tx);
    return { ...tx, ticked };
  });
  res.json(out);
}));

app.put('/api/admin/transactions/:id', wrap(async (req, res) => {
  const b = req.body || {};
  const vals = txValues(b);
  const out = await inTx(async (db) => {
    await releasePayment(db, req.params.id);
    const tx = (await db.query(`update transactions set ${TX_COLS.map((c, i) => `${c}=$${i + 1}`).join(',')}, auto=false where id=$${TX_COLS.length + 1} returning *`, [...vals, req.params.id])).rows[0];
    if (!tx) { const e = new Error('gone'); e.status = 404; throw e; }
    if (tx.type === 'charge') await syncChargeMonths(db, tx, false);
    const ticked = b.allocate === false ? [] : await allocatePayment(db, tx);
    return { ...tx, ticked };
  });
  res.json(out);
}));

app.delete('/api/admin/transactions/:id', wrap(async (req, res) => {
  await inTx(async (db) => {
    await releasePayment(db, req.params.id);
    await syncChargeMonths(db, { id: req.params.id }, true);
    await db.query('delete from transactions where id=$1', [req.params.id]);
  });
  res.json({ ok: true });
}));

// ---------- retainer tracker ----------
app.get('/api/admin/retainers', wrap(async (req, res) => {
  const now = new Date().getFullYear();
  const year = Number(req.query.year) || now;
  await syncRetainers();
  if (year > now && year <= now + 1) await ensureRetainerYear(pool, year);
  const { rows: months } = await q(`select id, client_id, month, status, amount, tx_id, charge_tx_id from retainer_months where year=$1 order by client_id, month`, [year]);
  const ids = [...new Set(months.map((m) => m.client_id))];
  const { rows: clients } = ids.length ? await q(`select c.id, c.name, c.billing, c.retainer_active from clients c where c.id = any($1) order by lower(c.name)`, [ids]) : { rows: [] };
  const { rows: yrs } = await q('select distinct year from retainer_months order by year');
  const years = [...new Set([...yrs.map((r) => r.year), now, now + 1])].sort();
  res.json({ year, years, clients: clients.map((c) => ({ ...c, months: months.filter((m) => m.client_id === c.id) })) });
}));

// Change one month's status or amount
app.put('/api/admin/retainers/:id', wrap(async (req, res) => {
  const out = await inTx(async (db) => {
    let m = (await db.query(`select * from retainer_months where id=$1 for update`, [req.params.id])).rows[0];
    if (!m) { const e = new Error('gone'); e.status = 404; throw e; }
    if ('amount' in req.body) m = await billMonth(db, m.client_id, m.year, m.month, req.body.amount);
    if (!('status' in req.body)) return m;
    const status = req.body.status === '' ? null : req.body.status;
    if (![null, 'rec', 'not_rec', 'na'].includes(status)) { const e = new Error('x'); e.status = 400; e.msgOverride = 'Choose received, not received or N/A.'; throw e; }
    if (m.status === status) return m;
    if (m.status === 'rec' && m.tx_id) {
      const tx = (await db.query('select * from transactions where id=$1', [m.tx_id])).rows[0];
      await db.query('update retainer_months set tx_id=null where id=$1', [m.id]);
      if (tx && tx.auto) await db.query('delete from transactions where id=$1', [tx.id]);
    }
    if (status === 'na' && m.charge_tx_id) m = await billMonth(db, m.client_id, m.year, m.month, 0); // no fee this month: remove the bill
    let txId = null;
    if (status === 'rec' && Number(m.amount) > 0) {
      txId = (await db.query(
        `insert into transactions (tx_date, type, client_id, amount, description, method, auto) values ($1, 'payment', $2, $3, $4, 'EFT', true) returning id`,
        [todaySA(), m.client_id, m.amount, `Retainer ${monthLabel(m.year, m.month)}`])).rows[0].id;
    }
    return (await db.query('update retainer_months set status=$1, tx_id=$2 where id=$3 returning *', [status, txId, m.id])).rows[0];
  });
  res.json(out);
}));

// Monthly billing: list every active retainer for a month, with what was billed last time
app.get('/api/admin/retainers/bill', wrap(async (req, res) => {
  const y = Number(req.query.year), m = Number(req.query.month);
  await ensureRetainerYear(pool, y);
  const { rows } = await q(`
    select c.id client_id, c.name, rm.id month_id, rm.status, rm.amount, rm.charge_tx_id,
      (select p.amount from retainer_months p where p.client_id=c.id and p.amount > 0 and (p.year < $1 or (p.year = $1 and p.month < $2)) order by p.year desc, p.month desc limit 1) as last_amount
    from clients c left join retainer_months rm on rm.client_id=c.id and rm.year=$1 and rm.month=$2
    where c.billing='retainer' and c.retainer_active and (c.retainer_start is null or c.retainer_start <= make_date($1, $2, 1))
      and coalesce(rm.status, '') <> 'na'
    order by lower(c.name)`, [y, m]);
  res.json(rows);
}));
app.post('/api/admin/retainers/bill', wrap(async (req, res) => {
  const { year, month, items } = req.body || {};
  if (!year || !month || !Array.isArray(items)) return res.status(400).json({ error: 'Choose a month and enter amounts.' });
  const done = await inTx(async (db) => {
    let n = 0, total = 0;
    for (const it of items) {
      if (it.amount === '' || it.amount == null) continue;
      await billMonth(db, it.client_id, year, month, it.amount);
      if (Number(it.amount) > 0) { n++; total += Number(it.amount); }
    }
    return { n, total };
  });
  res.json(done);
}));

// ---------- client statement ----------
app.get('/api/admin/clients/:id/statement', wrap(async (req, res) => {
  const id = req.params.id;
  await syncRetainers();
  const c = (await q(`select c.*, ${BAL} as balance, b.charges, b.paid from clients c join client_balances b on b.client_id=c.id where c.id=$1`, [id])).rows[0];
  if (!c) return res.status(404).json({ error: 'That client no longer exists.' });
  const [tx, months, con] = await Promise.all([
    q(`select t.*, ${MONTHS_FOR('tx_id')} months, ${MONTHS_FOR('charge_tx_id')} billed_for from transactions t where client_id=$1 order by tx_date desc, id desc`, [id]),
    q('select * from retainer_months where client_id=$1 order by year desc, month', [id]),
    q('select * from contracts where client_id=$1 order by start_date desc nulls last', [id]),
  ]);
  res.json({ client: c, transactions: tx.rows, months: months.rows, contracts: con.rows });
}));

// ---------- debtors ----------
app.get('/api/admin/debtors', wrap(async (req, res) => {
  await syncRetainers();
  const { rows } = await q(`
    select c.id, c.name, c.phone, c.billing, c.retainer_active, ${BAL} as balance,
      (select string_agg(to_char(make_date(m.year, m.month, 1), 'Mon YY'), ', ' order by m.year, m.month)
         from retainer_months m where m.client_id=c.id and m.status='not_rec') as unpaid_months,
      (select max(tx_date) from transactions t where t.client_id=c.id and t.type='payment') as last_paid
    from clients c join client_balances b on b.client_id=c.id
    where ${BAL} <> 0 or (c.billing='retainer' and c.retainer_active) or exists (select 1 from transactions t where t.client_id=c.id)
    order by ${BAL} desc, lower(c.name)`);
  res.json(rows);
}));

// ---------- dashboard ----------
app.get('/api/admin/dashboard', wrap(async (req, res) => {
  await syncRetainers();
  const one = async (sql) => Number((await q(sql)).rows[0].v || 0);
  const m = `date_trunc('month', current_date)`;
  const [incomeMonth, incomeLast, billedMonth, outstanding, activeRet, unbilled, newLeads, notRecCount, notRecAmt, outMonth, bank] = await Promise.all([
    one(`select sum(amount) v from transactions where type='payment' and tx_date >= ${m}`),
    one(`select sum(amount) v from transactions where type='payment' and tx_date >= ${m} - interval '1 month' and tx_date < ${m}`),
    one(`select sum(amount) v from transactions where type='charge' and tx_date >= ${m} and coalesce(description,'') not like 'Opening balance%'`),
    one(`select sum(greatest(${BAL}, 0)) v from client_balances b`),
    one(`select count(*) v from clients where billing='retainer' and retainer_active and (retainer_start is null or retainer_start <= current_date)`),
    one(`select count(*) v from retainer_months m join clients c on c.id=m.client_id where c.retainer_active and c.billing='retainer' and m.status is null
           and m.year=extract(year from current_date) and m.month=extract(month from current_date)`),
    one(`select count(*) v from leads where status = 'new'`),
    one(`select count(*) v from retainer_months where status='not_rec' and amount > 0`),
    one(`select sum(amount) v from retainer_months where status='not_rec' and amount > 0`),
    one(`select sum(amount) v from transactions where type='expense' and tx_date >= ${m}`),
    one(`select sum(case type when 'payment' then amount else -amount end) v from transactions where type in ('payment','expense')`),
  ]);
  const series = (await q(`
    with months as (select generate_series(${m} - interval '11 months', ${m}, interval '1 month')::date as month)
    select to_char(mo.month,'Mon YY') label, mo.month,
      coalesce((select sum(amount) from transactions where type='payment' and date_trunc('month', tx_date) = mo.month),0) income,
      coalesce((select sum(amount) from transactions where type='charge' and coalesce(description,'') not like 'Opening balance%' and date_trunc('month', tx_date) = mo.month),0) billed,
      coalesce((select sum(amount) from transactions where type='expense' and date_trunc('month', tx_date) = mo.month),0) out
    from months mo order by mo.month`)).rows;
  const topDebtors = (await q(`select c.id client_id, c.name client_name, c.billing, ${BAL} balance from clients c join client_balances b on b.client_id=c.id
    where ${BAL} > 0 order by ${BAL} desc limit 6`)).rows;
  const ending = (await q(`select k.id, k.title, k.end_date, k.value, k.kind, c.name client_name from contracts k join clients c on c.id=k.client_id
    where k.status='active' and k.end_date between current_date and current_date + 45 order by k.end_date`)).rows;
  const recentPayments = (await q(`select t.amount, t.tx_date paid_on, t.method, case when c.name is null then null else t.description end description, coalesce(c.name, t.description, 'Money in') client_name from transactions t
    left join clients c on c.id=t.client_id where t.type='payment' order by t.tx_date desc, t.id desc limit 6`)).rows;
  res.json({
    kpis: { incomeMonth, incomeLast, billedMonth, outstanding, activeRet, unbilled, newLeads, notRecCount, notRecAmt, outMonth, bank },
    series, topDebtors, ending, recentPayments,
  });
}));

// ---------- settings ----------
app.get('/api/admin/settings', wrap(async (req, res) => {
  const r = await q('select data from settings where id=1');
  res.json(r.rows[0] ? r.rows[0].data : {});
}));
app.put('/api/admin/settings', wrap(async (req, res) => {
  const r = await q(`insert into settings (id, data) values (1, $1) on conflict (id) do update set data = excluded.data returning data`, [req.body || {}]);
  res.json(r.rows[0].data);
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Unknown API route.' }));

// ---------- static ----------
// Works with either layout:
//   1) repo with folders:  backend/server.js + admin/index.html + frontend/index.html
//   2) flat repo:          server.js + index.html (admin panel) [+ public/index.html for the website]
const fs = require('fs');
const has = (dir) => fs.existsSync(path.join(dir, 'index.html'));
const pick = (...dirs) => dirs.find(has);
const ADMIN_DIR = pick(path.join(__dirname, '..', 'admin'), path.join(__dirname, 'admin'));
const FRONT_DIR = pick(path.join(__dirname, '..', 'frontend'), path.join(__dirname, 'frontend'), path.join(__dirname, 'public'));
const FLAT_INDEX = has(__dirname) ? path.join(__dirname, 'index.html') : null; // flat repo: root index.html is the admin panel

if (ADMIN_DIR) app.use('/admin', express.static(ADMIN_DIR, { index: 'index.html' }));
else if (FLAT_INDEX) app.get(['/admin', '/admin/'], (req, res) => res.sendFile(FLAT_INDEX));

if (FRONT_DIR) {
  app.use(express.static(FRONT_DIR, { extensions: ['html'], maxAge: '1h' }));
  app.use((req, res) => res.status(404).sendFile(path.join(FRONT_DIR, 'index.html')));
} else if (FLAT_INDEX) {
  // no public website in this repo: send visitors to the admin panel
  app.get('/', (req, res) => res.redirect('/admin'));
  app.use((req, res) => res.status(404).send('Not found'));
} else {
  app.use((req, res) => res.status(404).send('Not found'));
}
console.log(`[static] admin: ${ADMIN_DIR || FLAT_INDEX || 'none'} | website: ${FRONT_DIR || 'none'}`);

// ---------- keep the database up to date (safe to run on every start) ----------
const MIGRATION = `
-- people who can log in besides you (salespeople only see Leads)
create table if not exists app_users (
  id            bigserial primary key,
  name          text not null,
  username      text not null unique,
  password_hash text not null,
  role          text not null default 'sales',
  active        boolean not null default true,
  created_at    timestamptz not null default now()
);

-- who added the lead, and when it was last touched
alter table leads add column if not exists created_by text;
alter table leads add column if not exists updated_at timestamptz;
alter table leads drop constraint if exists leads_status_check;
alter table leads add constraint leads_status_check check (status in ('new','contacted','follow_up','quoted','won','lost'));

-- every action on a lead, with a timestamp: added, contacted (call / WhatsApp / email...), edited
create table if not exists lead_activity (
  id         bigserial primary key,
  lead_id    bigint not null references leads(id) on delete cascade,
  user_id    bigint references app_users(id) on delete set null,
  user_name  text not null,
  kind       text not null check (kind in ('created','contact','edited')),
  how        text,
  note       text,
  status_to  text,
  created_at timestamptz not null default now()
);
create index if not exists idx_la_lead on lead_activity(lead_id);
create index if not exists idx_la_time on lead_activity(created_at);

-- proof screenshots / photos (compressed before upload)
create table if not exists lead_proofs (
  id          bigserial primary key,
  activity_id bigint not null unique references lead_activity(id) on delete cascade,
  mime        text not null,
  data        bytea not null,
  created_at  timestamptz not null default now()
);

alter table app_users     enable row level security;
alter table lead_activity enable row level security;
alter table lead_proofs   enable row level security;

alter table transactions add column if not exists imported boolean not null default false;
-- employees + time tracking
alter table app_users add column if not exists hourly_rate numeric(10,2) not null default 0;
alter table app_users drop constraint if exists app_users_role_check;
alter table app_users add constraint app_users_role_check check (role in ('sales','staff'));
create table if not exists time_entries (
  id          bigserial primary key,
  user_id     bigint references app_users(id) on delete set null,
  user_name   text not null,
  client_id   bigint not null references clients(id) on delete cascade,
  started_at  timestamptz not null,
  ended_at    timestamptz,
  note        text,
  rate        numeric(10,2) not null default 0,
  edited      boolean not null default false,
  created_at  timestamptz not null default now()
);
create index if not exists idx_time_user on time_entries(user_id);
create index if not exists idx_time_client on time_entries(client_id);
create index if not exists idx_time_start on time_entries(started_at);
create unique index if not exists one_running_timer on time_entries(user_id) where ended_at is null;
alter table time_entries enable row level security;
-- clients who already paid everything off: tick their leftover months
update retainer_months m set status = 'rec'
where m.status = 'not_rec' and m.amount = 0
  and exists (select 1 from client_balances b where b.client_id = m.client_id and b.charges - b.paid <= 0)
  and exists (select 1 from transactions t where t.client_id = m.client_id and t.type = 'payment' and not t.imported);
`;
async function migrate() {
  try { await pool.query(MIGRATION); console.log('[db] tables up to date'); }
  catch (e) { console.error('[db] could not update tables:', e.message); }
}

migrate().finally(() => app.listen(PORT, () => console.log(`THOS running on :${PORT}`)));
