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
  const msg = e.code === '23503' ? 'This record is linked to something that no longer exists, or is still used elsewhere.'
            : e.code === '23514' ? 'One of the values is not allowed. Check amounts are above zero and options are valid.'
            : e.code === '23505' ? 'That value already exists. Use a different one.'
            : e.code === '22P02' || e.code === '22007' || e.code === '22008' ? 'One of the fields has the wrong format. Check dates and amounts.'
            : 'Something went wrong on the server.';
  res.status(e.status || 500).json({ error: msg });
});

// ---------- health ----------
app.get('/healthz', (req, res) => res.json({ ok: true }));

// ---------- public API ----------
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
  let ok = false;
  if (process.env.ADMIN_PASSWORD_HASH) ok = await bcrypt.compare(pw, process.env.ADMIN_PASSWORD_HASH);
  else if (process.env.ADMIN_PASSWORD) {
    const a = Buffer.from(pw), b = Buffer.from(process.env.ADMIN_PASSWORD);
    ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  if (!ok) return res.status(401).json({ error: 'That password is incorrect.' });
  res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' }) });
}));

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  try { jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Your session has ended. Log in again.' }); }
}
app.use('/api/admin', auth);

// ---------- generic CRUD ----------
const toNull = (v) => (v === '' || v === undefined ? null : v);

const resources = {
  clients: {
    cols: ['name', 'contact_person', 'email', 'phone', 'address', 'industry', 'status', 'notes'],
    list: `select c.*,
             coalesce((select sum(total) from invoice_summary s where s.client_id=c.id and s.status not in ('void','draft')),0)
             - coalesce((select sum(amount) from payments p where p.client_id=c.id),0)
             - coalesce((select sum(amount) from credit_notes n where n.client_id=c.id),0) as balance,
             (select count(*) from contracts k where k.client_id=c.id and k.status='active')::int as active_contracts
           from clients c order by c.name`,
  },
  contracts: {
    cols: ['client_id', 'title', 'kind', 'value', 'start_date', 'end_date', 'status', 'file_url', 'notes'],
    list: `select t.*, c.name client_name from contracts t join clients c on c.id=t.client_id order by t.status='active' desc, t.end_date nulls last, t.id desc`,
  },
  payments: {
    cols: ['client_id', 'invoice_id', 'amount', 'paid_on', 'method', 'reference', 'notes'],
    list: `select t.*, c.name client_name, i.number invoice_number from payments t join clients c on c.id=t.client_id left join invoices i on i.id=t.invoice_id order by t.paid_on desc, t.id desc`,
  },
  credit_notes: {
    cols: ['client_id', 'invoice_id', 'amount', 'issued_on', 'reason'],
    list: `select t.*, c.name client_name, i.number invoice_number from credit_notes t join clients c on c.id=t.client_id left join invoices i on i.id=t.invoice_id order by t.issued_on desc, t.id desc`,
  },
  ad_spend: {
    cols: ['client_id', 'platform', 'month', 'budget', 'spend', 'fee', 'notes'],
    list: `select t.*, c.name client_name from ad_spend t join clients c on c.id=t.client_id order by t.month desc, c.name`,
  },
  expenses: {
    cols: ['spent_on', 'category', 'supplier', 'description', 'amount', 'client_id'],
    list: `select t.*, c.name client_name from expenses t left join clients c on c.id=t.client_id order by t.spent_on desc, t.id desc`,
  },
  leads: {
    cols: ['name', 'business', 'email', 'phone', 'services', 'message', 'status', 'budget', 'timeline', 'contact_pref'],
    list: `select * from leads order by created_at desc`,
  },
  portfolio: {
    cols: ['name', 'category', 'url', 'blurb', 'image_url', 'sort', 'visible'],
    list: `select * from portfolio order by sort, id`,
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

// ---------- invoices ----------
app.get('/api/admin/invoices', wrap(async (req, res) => {
  res.json((await q('select * from invoice_summary order by issue_date desc, id desc')).rows);
}));

app.get('/api/admin/invoices/:id', wrap(async (req, res) => {
  const id = req.params.id;
  const inv = (await q('select s.*, c.email client_email, c.address client_address, c.contact_person, c.phone client_phone from invoice_summary s join clients c on c.id=s.client_id where s.id=$1', [id])).rows[0];
  if (!inv) return res.status(404).json({ error: 'That invoice no longer exists.' });
  const [items, payments, credits] = await Promise.all([
    q('select * from invoice_items where invoice_id=$1 order by sort, id', [id]),
    q('select * from payments where invoice_id=$1 order by paid_on', [id]),
    q('select * from credit_notes where invoice_id=$1 order by issued_on', [id]),
  ]);
  res.json({ ...inv, items: items.rows, payments: payments.rows, credits: credits.rows });
}));

async function saveInvoice(req, res, id) {
  const b = req.body || {};
  const items = Array.isArray(b.items) ? b.items.filter((i) => i && String(i.description || '').trim()) : [];
  if (!b.client_id) return res.status(400).json({ error: 'Choose a client for this invoice.' });
  if (!items.length) return res.status(400).json({ error: 'Add at least one line item.' });
  const client = await pool.connect();
  try {
    await client.query('begin');
    const f = [b.client_id, toNull(b.contract_id), toNull(b.issue_date), toNull(b.due_date), b.status || 'sent', toNull(b.notes)];
    let invId = id;
    if (id) {
      const r = await client.query(
        `update invoices set client_id=$1, contract_id=$2, issue_date=coalesce($3::date, issue_date), due_date=coalesce($4::date, due_date), status=$5, notes=$6 where id=$7 returning id`,
        [...f, id]);
      if (!r.rows.length) { await client.query('rollback'); return res.status(404).json({ error: 'That invoice no longer exists.' }); }
      await client.query('delete from invoice_items where invoice_id=$1', [id]);
    } else {
      const r = await client.query(
        `insert into invoices (client_id, contract_id, issue_date, due_date, status, notes)
         values ($1,$2,coalesce($3::date,current_date),coalesce($4::date,current_date+7),$5,$6) returning id`, f);
      invId = r.rows[0].id;
    }
    for (const [i, it] of items.entries()) {
      await client.query('insert into invoice_items (invoice_id, description, qty, unit_price, sort) values ($1,$2,$3,$4,$5)',
        [invId, String(it.description).slice(0, 500), Number(it.qty) || 1, Number(it.unit_price) || 0, i]);
    }
    await client.query('commit');
    res.json((await q('select * from invoice_summary where id=$1', [invId])).rows[0]);
  } catch (e) { await client.query('rollback').catch(() => {}); throw e; }
  finally { client.release(); }
}
app.post('/api/admin/invoices', wrap((req, res) => saveInvoice(req, res, null)));
app.put('/api/admin/invoices/:id', wrap((req, res) => saveInvoice(req, res, req.params.id)));
app.delete('/api/admin/invoices/:id', wrap(async (req, res) => {
  await q('delete from invoices where id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// ---------- client statement ----------
app.get('/api/admin/clients/:id/statement', wrap(async (req, res) => {
  const id = req.params.id;
  const c = (await q('select * from clients where id=$1', [id])).rows[0];
  if (!c) return res.status(404).json({ error: 'That client no longer exists.' });
  const [inv, pay, cr, con, ads] = await Promise.all([
    q('select * from invoice_summary where client_id=$1 order by issue_date desc', [id]),
    q('select p.*, i.number invoice_number from payments p left join invoices i on i.id=p.invoice_id where p.client_id=$1 order by paid_on desc', [id]),
    q('select n.*, i.number invoice_number from credit_notes n left join invoices i on i.id=n.invoice_id where n.client_id=$1 order by issued_on desc', [id]),
    q('select * from contracts where client_id=$1 order by start_date desc nulls last', [id]),
    q('select * from ad_spend where client_id=$1 order by month desc', [id]),
  ]);
  const sum = (rows, k) => rows.reduce((a, r) => a + Number(r[k] || 0), 0);
  const billed = sum(inv.rows.filter((r) => !['void', 'draft'].includes(r.status)), 'total');
  const paid = sum(pay.rows, 'amount'), credited = sum(cr.rows, 'amount');
  res.json({ client: c, invoices: inv.rows, payments: pay.rows, credits: cr.rows, contracts: con.rows, ad_spend: ads.rows,
    totals: { billed, paid, credited, balance: billed - paid - credited } });
}));

// ---------- debtors ----------
app.get('/api/admin/debtors', wrap(async (req, res) => {
  const { rows } = await q(`
    with open as (
      select client_id, balance, days_overdue from invoice_summary
      where status not in ('void','draft') and balance > 0
    ),
    unalloc as (
      select client_id, sum(amount) amt from (
        select client_id, amount from payments where invoice_id is null
        union all select client_id, amount from credit_notes where invoice_id is null
      ) x group by client_id
    )
    select c.id, c.name, c.phone, c.email,
      coalesce(sum(o.balance) filter (where o.days_overdue = 0), 0)              as current,
      coalesce(sum(o.balance) filter (where o.days_overdue between 1 and 30), 0) as d30,
      coalesce(sum(o.balance) filter (where o.days_overdue between 31 and 60), 0) as d60,
      coalesce(sum(o.balance) filter (where o.days_overdue between 61 and 90), 0) as d90,
      coalesce(sum(o.balance) filter (where o.days_overdue > 90), 0)             as d90plus,
      coalesce(max(u.amt), 0) as unallocated,
      coalesce(sum(o.balance), 0) - coalesce(max(u.amt), 0) as balance,
      count(o.*)::int as open_invoices
    from clients c
    left join open o on o.client_id = c.id
    left join unalloc u on u.client_id = c.id
    group by c.id
    having coalesce(sum(o.balance), 0) <> 0 or coalesce(max(u.amt), 0) <> 0
    order by balance desc`);
  res.json(rows);
}));

// ---------- dashboard ----------
app.get('/api/admin/dashboard', wrap(async (req, res) => {
  const one = async (sql) => Number((await q(sql)).rows[0].v || 0);
  const m = `date_trunc('month', current_date)`;
  const [incomeMonth, incomeLast, expMonth, adMonth, adFeeMonth, outstanding, overdue, mrr, newLeads] = await Promise.all([
    one(`select sum(amount) v from payments where paid_on >= ${m}`),
    one(`select sum(amount) v from payments where paid_on >= ${m} - interval '1 month' and paid_on < ${m}`),
    one(`select sum(amount) v from expenses where spent_on >= ${m}`),
    one(`select sum(spend) v from ad_spend where month = ${m}::date`),
    one(`select sum(fee) v from ad_spend where month = ${m}::date`),
    one(`select (select coalesce(sum(balance),0) from invoice_summary where status not in ('void','draft') and balance > 0)
               - (select coalesce(sum(amount),0) from payments where invoice_id is null)
               - (select coalesce(sum(amount),0) from credit_notes where invoice_id is null) v`),
    one(`select sum(balance) v from invoice_summary where pay_status = 'overdue'`),
    one(`select sum(value) v from contracts where kind='retainer' and status='active' and (end_date is null or end_date >= current_date)`),
    one(`select count(*) v from leads where status = 'new'`),
  ]);
  const series = (await q(`
    with months as (select generate_series(${m} - interval '11 months', ${m}, interval '1 month')::date as month)
    select to_char(mo.month,'Mon YY') label, mo.month,
      coalesce((select sum(amount) from payments where date_trunc('month', paid_on) = mo.month),0) income,
      coalesce((select sum(amount) from expenses where date_trunc('month', spent_on) = mo.month),0) expenses,
      coalesce((select sum(spend) from ad_spend where month = mo.month),0) ad_spend
    from months mo order by mo.month`)).rows;
  const topDebtors = (await q(`select client_id, client_name, sum(balance) balance, max(days_overdue) days
    from invoice_summary where status not in ('void','draft') and balance > 0 group by client_id, client_name order by balance desc limit 5`)).rows;
  const ending = (await q(`select k.id, k.title, k.end_date, k.value, k.kind, c.name client_name from contracts k join clients c on c.id=k.client_id
    where k.status='active' and k.end_date between current_date and current_date + 45 order by k.end_date`)).rows;
  const recentPayments = (await q(`select p.amount, p.paid_on, p.method, c.name client_name, i.number invoice_number from payments p
    join clients c on c.id=p.client_id left join invoices i on i.id=p.invoice_id order by p.paid_on desc, p.id desc limit 6`)).rows;
  res.json({
    kpis: { incomeMonth, incomeLast, expMonth, profitMonth: incomeMonth - expMonth, adMonth, adFeeMonth, outstanding, overdue, mrr, newLeads },
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
const FRONT = path.join(__dirname, '..', 'frontend');
const ADMIN = path.join(__dirname, '..', 'admin');
app.use('/admin', express.static(ADMIN, { index: 'index.html' }));
app.use(express.static(FRONT, { extensions: ['html'], maxAge: '1h' }));
app.use((req, res) => res.status(404).sendFile(path.join(FRONT, 'index.html')));

app.listen(PORT, () => console.log(`THOS running on :${PORT}`));
