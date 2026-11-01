#!/usr/bin/env node
'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),tls=require('tls');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT=3000;
const DATA_FILE=path.join(__dirname,'data.enc');
const PUB_DIR=path.join(__dirname,'public');
const ENC_PASSWORD='Z@Yn00@17';
const ENC_SALT='tradeled_salt_2024';
const ZOHO_HOST='smtp.zoho.com';
const ZOHO_PORT=465;
const ZOHO_USER='shamikh@thehouseofservices.co.za';
const ZOHO_PASS='Z@Yn00@17';
const BACKUP_TO='shamikh@thehouseofservices.co.za';

// ── Encryption ────────────────────────────────────────────────────────────────
function deriveKey(){ return crypto.scryptSync(ENC_PASSWORD,ENC_SALT,32); }
function encryptDB(obj){
  const iv=crypto.randomBytes(16);
  const cipher=crypto.createCipheriv('aes-256-cbc',deriveKey(),iv);
  const json=JSON.stringify(obj);
  const enc=Buffer.concat([cipher.update(json,'utf8'),cipher.final()]);
  return Buffer.concat([iv,enc]);
}
function decryptDB(buf){
  const iv=buf.slice(0,16),enc=buf.slice(16);
  const decipher=crypto.createDecipheriv('aes-256-cbc',deriveKey(),iv);
  const json=Buffer.concat([decipher.update(enc),decipher.final()]).toString('utf8');
  return JSON.parse(json);
}

// ── DB ────────────────────────────────────────────────────────────────────────
const empty={
  companies:[],parties:[],
  stock:[{
    id:1,name:'Au',unit:'g',quantity:0,opening_quantity:0,
    avg_cost:0,selling_price:0,is_gold:true,description:'Gold (Au) — fine weight',
    created_at:new Date().toISOString()
  }],
  transactions:[],cash_balance:0,suspense:[]
};
let db;
function loadDB(){
  if(fs.existsSync(DATA_FILE)){
    const raw=fs.readFileSync(DATA_FILE);
    // Try encrypted first
    try{ db=decryptDB(raw); }
    catch(e1){
      // Try plain JSON fallback (in case old version saved unencrypted)
      try{ db=JSON.parse(raw.toString('utf8')); console.log('Loaded plain JSON backup.'); }
      catch(e2){
        console.error('Cannot read data.enc — backing it up and starting fresh.');
        fs.renameSync(DATA_FILE, DATA_FILE+'.corrupt.'+Date.now());
        db=JSON.parse(JSON.stringify(empty));
      }
    }
  } else {
    db=JSON.parse(JSON.stringify(empty));
  }
  if(!db.cash_balance) db.cash_balance=0;
  if(!db.suspense) db.suspense=[];
  if(!db.investors) db.investors=[];
  if(!db.stock) db.stock=[];
  if(!db.stock.find(s=>s.name==='Au')){
    db.stock.unshift({id:1,name:'Au',unit:'g',quantity:0,opening_quantity:0,avg_cost:0,selling_price:0,is_gold:true,created_at:new Date().toISOString()});
  }
  // ── One-time data fix: old cash_out records where party_id === pool_party_id ──
  // Before the fix, saveCashTxn() set party_id = pool_party_id (wrong).
  // These records should have party_id = null (the recipient wasn't recorded).
  db.transactions.forEach(t=>{
    if(t.type==='cash_out' && t.pool_party_id && parseInt(t.party_id)===parseInt(t.pool_party_id)){
      t.party_id=null;
    }
  });
  // ── One-time data fix: gold sells split across several pools ──────────────────
  // The old server overwrote each row's quantity with the TOTAL fine weight.
  // Recover each row's real grams from its own amount: total / (rate × (1−discount)).
  (function repairSplitSells(){
    // Group sells that were posted together: same date, same customer, same stock,
    // same (combined) fine weight, and each row's quantity still equals that combined weight.
    const bad=db.transactions.filter(t=>t.type==='sell'&&t.supplier_party_id&&t.fine_weight
      &&Math.abs((t.quantity||0)-(t.fine_weight||0))<1e-6);
    const groups={};
    bad.forEach(t=>{
      const k=[t.date,t.party_id,t.stock_item_id,(+t.fine_weight).toFixed(4)].join('|');
      (groups[k]=groups[k]||[]).push(t);
    });
    let fixed=0;
    Object.values(groups).forEach(g=>{
      if(g.length<2) return;
      const combined=g[0].fine_weight;
      const groupTotal=g.reduce((a,t)=>a+(parseFloat(t.total_amount)||0),0);
      if(groupTotal<=0) return;
      // Each row's real grams = its share of the money × the combined weight
      g.forEach(t=>{
        const q=+((parseFloat(t.total_amount)||0)/groupTotal*combined).toFixed(4);
        if(q>0&&q<combined-0.0005){ t.quantity=q; t.fine_weight=q; t.split_repaired=true; fixed++; }
      });
    });
    console.log(fixed?`Repaired ${fixed} split gold sell record(s).`:'Split-sell check: nothing to repair.');
  })();
  rebuildBalances();
  // Always re-save in current encrypted format on startup
  saveDB();
}
// ── Rebuild all derived balances from scratch (startup + after edits) ─────────
function rebuildBalances(){
  db.parties.forEach(p=>{ p.balance=p.opening_balance||0; });
  db.companies.forEach(c=>{ c.bank_balance=c.opening_balance||0; });
  db.stock.forEach(s=>{ s.quantity=s.opening_quantity||0; s.avg_cost=0; });
  db.cash_balance=0;
  // Replay all transactions in chronological order
  [...db.transactions]
    .sort((a,b)=>a.date.localeCompare(b.date)||(parseInt(a.id)-parseInt(b.id)))
    .forEach(t=>applyTransaction(t,db));
}
function saveDB(){ fs.writeFileSync(DATA_FILE,encryptDB(db)); }
function nextId(arr){ return arr.length?Math.max(0,...arr.map(x=>parseInt(x.id)||0))+1:1; }

// ── Transaction helpers ───────────────────────────────────────────────────────
function enrichTxn(t,d){
  const p=d.parties.find(x=>x.id===t.party_id);
  const s=d.stock.find(x=>x.id===t.stock_item_id);
  const c=d.companies.find(x=>x.id===t.company_id);
  const sp=d.parties.find(x=>x.id===t.supplier_party_id);
  const inv=t.investor_id&&d.investors?d.investors.find(x=>parseInt(x.id)===parseInt(t.investor_id)):null;
  const tc=t.to_company_id?d.companies.find(x=>parseInt(x.id)===parseInt(t.to_company_id)):null;
  const sb=t.source_buy_id?d.transactions.find(x=>parseInt(x.id)===parseInt(t.source_buy_id)):null;
  return{
    ...t,
    party_name:p?p.name:null,
    stock_name:s?s.name:null,
    stock_unit:s?s.unit:null,
    company_name:c?c.name:null,
    to_company_name:tc?tc.name:null,
    investor_name:inv?inv.name:null,
    supplier_party_name:sp?sp.name:null,
    source_buy_date:sb?sb.date:null,
    source_buy_ref:sb?(sb.reference||null):null
  };
}

function applyTransaction(t,d){
  const{type,party_id,stock_item_id,quantity,unit_price,company_id}=t;
  const total_amount=Math.abs(parseFloat(t.total_amount)||0); // always positive
  // Party balance: positive = they owe us (receivable)
  if(party_id){
    const i=d.parties.findIndex(x=>parseInt(x.id)===parseInt(party_id));
    if(i>=0){
      // sell/income/cash_out/pay_supplier → Dr → balance up (they owe us more / we owe them less)
      if(type==='sell'||type==='income'||type==='cash_out'||type==='pay_supplier') d.parties[i].balance=(d.parties[i].balance||0)+total_amount;
      // buy/receive_payment/cash_in → Cr → balance down (they owe us less / we owe them more)
      else if(type==='buy'||type==='receive_payment'||type==='cash_in') d.parties[i].balance=(d.parties[i].balance||0)-total_amount;
    }
  }
  // Investors: paid = money out, received = money in — from/to a company bank or cash
  if(type==='investor_payment'||type==='investor_receipt'){
    const sign=type==='investor_receipt'?1:-1;
    if(t.source==='cash') d.cash_balance=(d.cash_balance||0)+sign*total_amount;
    else{
      const i=d.companies.findIndex(x=>parseInt(x.id)===parseInt(company_id));
      if(i>=0) d.companies[i].bank_balance=(d.companies[i].bank_balance||0)+sign*total_amount;
    }
    return;
  }
  // Transfer between companies: out of company_id, into to_company_id
  if(type==='transfer'){
    const f=d.companies.findIndex(x=>parseInt(x.id)===parseInt(company_id));
    const to=d.companies.findIndex(x=>parseInt(x.id)===parseInt(t.to_company_id));
    if(f>=0) d.companies[f].bank_balance=(d.companies[f].bank_balance||0)-total_amount;
    if(to>=0) d.companies[to].bank_balance=(d.companies[to].bank_balance||0)+total_amount;
    return;
  }
  // Company bank balance
  if(company_id){
    const i=d.companies.findIndex(x=>parseInt(x.id)===parseInt(company_id));
    if(i>=0){
      if(['receive_payment','income','sell','cash_in'].includes(type)) d.companies[i].bank_balance=(d.companies[i].bank_balance||0)+total_amount;
      else d.companies[i].bank_balance=(d.companies[i].bank_balance||0)-total_amount;
    }
  }
  // Stock quantity
  if(stock_item_id&&(type==='buy'||type==='sell')){
    const i=d.stock.findIndex(x=>parseInt(x.id)===parseInt(stock_item_id));
    if(i>=0){
      const si=d.stock[i];
      if(type==='buy'){
        const prev_qty=si.quantity||0;
        const prev_cost=si.avg_cost||0;
        const new_qty=prev_qty+(quantity||0);
        if(new_qty>0) si.avg_cost=(prev_qty*prev_cost+(quantity||0)*(unit_price||0))/new_qty;
        si.quantity=new_qty;
      } else {
        si.quantity=Math.max(0,(si.quantity||0)-(quantity||0));
      }
    }
  }
  // Cash balance
  // Cash handling fees don't move physical cash — party ledger + Cash Fee Profit only
  if(t.expense_category==='Cash Fee') return;
  if(type==='cash_in') d.cash_balance=(d.cash_balance||0)+total_amount;
  else if(type==='cash_out') d.cash_balance=(d.cash_balance||0)-total_amount;
}

function reverseTransaction(t,d){
  const{type,party_id,stock_item_id,quantity,company_id}=t;
  const total_amount=Math.abs(parseFloat(t.total_amount)||0); // always positive
  if(type==='investor_payment'||type==='investor_receipt'){
    const sign=type==='investor_receipt'?1:-1;
    if(t.source==='cash') d.cash_balance=(d.cash_balance||0)-sign*total_amount;
    else{
      const i=d.companies.findIndex(x=>parseInt(x.id)===parseInt(company_id));
      if(i>=0) d.companies[i].bank_balance=(d.companies[i].bank_balance||0)-sign*total_amount;
    }
    return;
  }
  if(type==='transfer'){
    const f=d.companies.findIndex(x=>parseInt(x.id)===parseInt(company_id));
    const to=d.companies.findIndex(x=>parseInt(x.id)===parseInt(t.to_company_id));
    if(f>=0) d.companies[f].bank_balance=(d.companies[f].bank_balance||0)+total_amount;
    if(to>=0) d.companies[to].bank_balance=(d.companies[to].bank_balance||0)-total_amount;
    return;
  }
  if(party_id){
    const i=d.parties.findIndex(x=>parseInt(x.id)===parseInt(party_id));
    if(i>=0){
      if(type==='sell'||type==='income'||type==='cash_out'||type==='pay_supplier') d.parties[i].balance=(d.parties[i].balance||0)-total_amount;
      else if(type==='buy'||type==='receive_payment'||type==='cash_in') d.parties[i].balance=(d.parties[i].balance||0)+total_amount;
    }
  }
  if(company_id){
    const i=d.companies.findIndex(x=>parseInt(x.id)===parseInt(company_id));
    if(i>=0){
      if(['receive_payment','income','sell','cash_in'].includes(type)) d.companies[i].bank_balance=(d.companies[i].bank_balance||0)-total_amount;
      else d.companies[i].bank_balance=(d.companies[i].bank_balance||0)+total_amount;
    }
  }
  if(stock_item_id&&(type==='buy'||type==='sell')){
    const i=d.stock.findIndex(x=>parseInt(x.id)===parseInt(stock_item_id));
    if(i>=0){
      if(type==='buy') d.stock[i].quantity=Math.max(0,(d.stock[i].quantity||0)-(quantity||0));
      else d.stock[i].quantity=(d.stock[i].quantity||0)+(quantity||0);
    }
  }
  if(t.expense_category==='Cash Fee') return;
  if(type==='cash_in') d.cash_balance=(d.cash_balance||0)-total_amount;
  else if(type==='cash_out') d.cash_balance=(d.cash_balance||0)+total_amount;
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
function mime(fp){
  const ext=path.extname(fp).toLowerCase();
  const m={'.html':'text/html','.css':'text/css','.js':'application/javascript','.json':'application/json','.png':'image/png','.ico':'image/x-icon'};
  return m[ext]||'application/octet-stream';
}
function json(res,data,status=200){
  const body=JSON.stringify(data);
  res.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'Access-Control-Allow-Origin':'*'});
  res.end(body);
}
function err(res,msg,status=400){ json(res,{error:msg},status); }
function readBody(req){
  return new Promise((resolve,reject)=>{
    let buf='';
    req.on('data',c=>buf+=c);
    req.on('end',()=>{try{resolve(buf?JSON.parse(buf):{});}catch(e){resolve({});}});
    req.on('error',reject);
  });
}

// ── SMTP TLS (Zoho) ───────────────────────────────────────────────────────────
function sendEmail(to,subject,body){
  return new Promise((resolve,reject)=>{
    const sock=tls.connect({host:ZOHO_HOST,port:ZOHO_PORT,rejectUnauthorized:true},()=>{
      const b64cred=Buffer.from(`\0${ZOHO_USER}\0${ZOHO_PASS}`).toString('base64');
      let step=0;
      const cmds=[
        ()=>`EHLO tradeled\r\n`,
        ()=>`AUTH PLAIN ${b64cred}\r\n`,
        ()=>`MAIL FROM:<${ZOHO_USER}>\r\n`,
        ()=>`RCPT TO:<${to}>\r\n`,
        ()=>`DATA\r\n`,
        ()=>`From: TradeLedger <${ZOHO_USER}>\r\nTo: ${to}\r\nSubject: ${subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain;charset=UTF-8\r\n\r\n${body}\r\n.\r\n`,
        ()=>`QUIT\r\n`
      ];
      function next(){ if(step<cmds.length) sock.write(cmds[step++]()); }
      sock.on('data',d=>{
        const s=d.toString();
        if(/^220 /.test(s)||/^250/.test(s)||/^235/.test(s)||/^354/.test(s)) next();
        else if(/^221/.test(s)){ sock.destroy(); resolve('sent'); }
        else if(/^[45]/.test(s)){ sock.destroy(); reject(new Error('SMTP: '+s.trim())); }
      });
      sock.on('error',reject);
    });
    sock.on('error',reject);
  });
}

// ── Router ────────────────────────────────────────────────────────────────────
async function handleRequest(req,res){
  const url=new URL(req.url,`http://localhost:${PORT}`);
  const p=url.pathname;
  const method=req.method.toUpperCase();

  if(method==='OPTIONS'){
    res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE','Access-Control-Allow-Headers':'Content-Type'});
    res.end(); return;
  }

  // Static files
  if(method==='GET'&&!p.startsWith('/api/')){
    let fp=path.join(PUB_DIR,p==='/'?'app.html':p);
    if(!fp.startsWith(PUB_DIR)){err(res,'Forbidden',403);return;}
    if(!fs.existsSync(fp)){err(res,'Not found',404);return;}
    const buf=fs.readFileSync(fp);
    res.writeHead(200,{'Content-Type':mime(fp),'Content-Length':buf.length});
    res.end(buf); return;
  }

  // ── Companies ──────────────────────────────────────────────────────────────
  if(p==='/api/companies'){
    if(method==='GET'){ json(res,db.companies); return; }
    if(method==='POST'){
      const body=await readBody(req);
      if(!body.name){err(res,'name required');return;}
      const ob=parseFloat(body.opening_balance)||0;
      const c={id:nextId(db.companies),name:body.name,bank_name:body.bank_name||'',opening_balance:ob,bank_balance:ob,created_at:new Date().toISOString()};
      db.companies.push(c); saveDB(); json(res,c,201); return;
    }
  }
  const cm=p.match(/^\/api\/companies\/(\d+)$/);
  if(cm){
    const id=parseInt(cm[1]),i=db.companies.findIndex(x=>parseInt(x.id)===id);
    if(method==='PUT'){
      if(i<0){err(res,'Not found',404);return;}
      const body=await readBody(req);
      const oldOB=db.companies[i].opening_balance||0;
      const newOB=body.opening_balance!==undefined?parseFloat(body.opening_balance):oldOB;
      const diff=newOB-oldOB;
      db.companies[i]={...db.companies[i],...body,id,opening_balance:newOB,bank_balance:(db.companies[i].bank_balance||0)+diff};
      saveDB(); json(res,db.companies[i]); return;
    }
    if(method==='DELETE'){
      if(i<0){err(res,'Not found',404);return;}
      db.companies.splice(i,1); saveDB(); json(res,{ok:true}); return;
    }
  }

  // ── Investors ──────────────────────────────────────────────────────────────
  if(p==='/api/investors'){
    if(method==='GET'){ json(res,db.investors||[]); return; }
    if(method==='POST'){
      const body=await readBody(req);
      if(!body.name){err(res,'name required');return;}
      const inv={id:nextId(db.investors),name:body.name,phone:body.phone||'',email:body.email||'',notes:body.notes||'',
        opening_balance:parseFloat(body.opening_balance)||0,created_at:new Date().toISOString()};
      db.investors.push(inv); saveDB(); json(res,inv,201); return;
    }
  }
  const ivm=p.match(/^\/api\/investors\/(\d+)$/);
  if(ivm){
    const id=parseInt(ivm[1]),i=db.investors.findIndex(x=>parseInt(x.id)===id);
    if(i<0){err(res,'Not found',404);return;}
    if(method==='PUT'){
      const body=await readBody(req);
      const inv=db.investors[i];
      ['name','phone','email','notes'].forEach(k=>{ if(body[k]!==undefined) inv[k]=body[k]; });
      if(body.opening_balance!==undefined) inv.opening_balance=parseFloat(body.opening_balance)||0;
      saveDB(); json(res,inv); return;
    }
    if(method==='DELETE'){
      if(db.transactions.some(t=>parseInt(t.investor_id)===id)){err(res,'This investor has ledger entries. Delete those first.');return;}
      db.investors.splice(i,1); saveDB(); json(res,{ok:true}); return;
    }
  }
  const ilm=p.match(/^\/api\/ledger\/investor\/(\d+)$/);
  if(ilm&&method==='GET'){
    const id=parseInt(ilm[1]);
    const investor=db.investors.find(x=>parseInt(x.id)===id);
    if(!investor){err(res,'Not found',404);return;}
    const txns=db.transactions.filter(t=>parseInt(t.investor_id)===id)
      .sort((a,b)=>a.date.localeCompare(b.date)||parseInt(a.id)-parseInt(b.id)).map(t=>enrichTxn(t,db));
    json(res,{investor,transactions:txns}); return;
  }

  // ── Parties ────────────────────────────────────────────────────────────────
  if(p==='/api/parties'){
    if(method==='GET'){ json(res,db.parties); return; }
    if(method==='POST'){
      const body=await readBody(req);
      if(!body.name){err(res,'name required');return;}
      const ob=parseFloat(body.opening_balance)||0;
      const party={id:nextId(db.parties),name:body.name,type:body.type||'supplier',phone:body.phone||'',email:body.email||'',notes:body.notes||'',opening_balance:ob,balance:ob,created_at:new Date().toISOString()};
      db.parties.push(party); saveDB(); json(res,party,201); return;
    }
  }
  const pm=p.match(/^\/api\/parties\/(\d+)$/);
  if(pm){
    const id=parseInt(pm[1]),i=db.parties.findIndex(x=>parseInt(x.id)===id);
    if(method==='PUT'){
      if(i<0){err(res,'Not found',404);return;}
      const body=await readBody(req);
      const oldOB=db.parties[i].opening_balance||0;
      const newOB=body.opening_balance!==undefined?parseFloat(body.opening_balance):oldOB;
      const diff=newOB-oldOB;
      db.parties[i]={...db.parties[i],...body,id,opening_balance:newOB,balance:(db.parties[i].balance||0)+diff};
      saveDB(); json(res,db.parties[i]); return;
    }
    if(method==='DELETE'){
      if(i<0){err(res,'Not found',404);return;}
      db.parties.splice(i,1); saveDB(); json(res,{ok:true}); return;
    }
  }

  // ── Stock ──────────────────────────────────────────────────────────────────
  if(p==='/api/stock'){
    if(method==='GET'){ json(res,db.stock); return; }
    if(method==='POST'){
      const body=await readBody(req);
      if(!body.name){err(res,'name required');return;}
      const oq=parseFloat(body.opening_quantity)||0;
      const s={id:nextId(db.stock),name:body.name,unit:body.unit||'units',description:body.description||'',selling_price:parseFloat(body.selling_price)||0,avg_cost:0,quantity:oq,opening_quantity:oq,is_gold:!!body.is_gold,created_at:new Date().toISOString()};
      db.stock.push(s); saveDB(); json(res,s,201); return;
    }
  }
  const sm=p.match(/^\/api\/stock\/(\d+)$/);
  if(sm){
    const id=parseInt(sm[1]),i=db.stock.findIndex(x=>parseInt(x.id)===id);
    if(method==='PUT'){
      if(i<0){err(res,'Not found',404);return;}
      const body=await readBody(req);
      const oldOQ=db.stock[i].opening_quantity||0;
      const newOQ=body.opening_quantity!==undefined?parseFloat(body.opening_quantity):oldOQ;
      const diff=newOQ-oldOQ;
      db.stock[i]={...db.stock[i],...body,id,opening_quantity:newOQ,quantity:(db.stock[i].quantity||0)+diff};
      saveDB(); json(res,db.stock[i]); return;
    }
    if(method==='DELETE'){
      if(i<0){err(res,'Not found',404);return;}
      db.stock.splice(i,1); saveDB(); json(res,{ok:true}); return;
    }
  }

  // ── Transactions ───────────────────────────────────────────────────────────
  if(p==='/api/transactions'){
    if(method==='GET'){ json(res,db.transactions.map(t=>enrichTxn(t,db))); return; }
    if(method==='POST'){
      const body=await readBody(req);
      if(!body.type){err(res,'type required');return;}
      if(body.type==='investor_payment'||body.type==='investor_receipt'){
        if(!body.investor_id){err(res,'investor_id required');return;}
        if(body.source!=='cash'&&!body.company_id){err(res,'Choose a company or cash');return;}
        if(body.source==='cash') body.company_id=null;
        body.party_id=null; body.stock_item_id=null; body.payment_status='paid';
      }
      if(body.type==='transfer'){
        if(!body.company_id||!body.to_company_id){err(res,'Transfer needs a from and a to company');return;}
        if(parseInt(body.company_id)===parseInt(body.to_company_id)){err(res,'From and To company must be different');return;}
        body.party_id=null; body.stock_item_id=null; body.payment_status='paid';
      }
      const total=parseFloat(body.total_amount)||0;
      // For Au (gold) transactions: fine_weight IS the quantity
      let qty=parseFloat(body.quantity)||null;
      if(body.type==='buy'&&body.fine_weight){
        qty=parseFloat(body.fine_weight)||qty;
      }
      // Sells: the per-lot quantity sent by the client wins. (Previously the TOTAL
      // fine weight overwrote it, so a sell split across 2+ pools deducted the
      // full weight from every pool and drove them negative.)
      if(body.type==='sell'&&!qty&&body.fine_weight) qty=parseFloat(body.fine_weight)||null;
      if(body.type==='sell'&&body.fine_weight&&qty) body.fine_weight=qty;
      const t={
        id:nextId(db.transactions),
        type:body.type,
        date:body.date||new Date().toISOString().slice(0,10),
        reference:body.reference||('TXN-'+nextId(db.transactions)),
        description:body.description||'',
        company_id:body.company_id?parseInt(body.company_id):null,
        to_company_id:body.to_company_id?parseInt(body.to_company_id):null,
        investor_id:body.investor_id?parseInt(body.investor_id):null,
        pool_party_id:body.pool_party_id?parseInt(body.pool_party_id):null,
        source:body.source==='cash'?'cash':(body.investor_id?'company':null),
        party_id:body.party_id?parseInt(body.party_id):null,
        stock_item_id:body.stock_item_id?parseInt(body.stock_item_id):null,
        // supplier_party_id = which supplier's stock is being sold (sell transactions)
        supplier_party_id:body.supplier_party_id?parseInt(body.supplier_party_id):null,
        // source_buy_id = the exact purchase (lot) this sell draws from
        source_buy_id:body.source_buy_id?parseInt(body.source_buy_id):null,
        charged_at_cost:!!body.charged_at_cost,
        // non-Au sells drawn from several lots in one ledger line
        pool_allocations:Array.isArray(body.pool_allocations)?body.pool_allocations.map(a=>({
          buy_id:parseInt(a.buy_id)||null,supplier_party_id:parseInt(a.supplier_party_id)||null,quantity:parseFloat(a.quantity)||0,at_cost:!!a.at_cost,amount:parseFloat(a.amount)||null
        })).filter(a=>a.buy_id&&a.quantity>0):null,
        quantity:qty,
        unit_price:parseFloat(body.unit_price)||null,
        total_amount:total,
        payment_status:body.payment_status||'unpaid',
        amount_paid:0,
        gross_weight:body.gross_weight?parseFloat(body.gross_weight):null,
        fine_weight:body.fine_weight?parseFloat(body.fine_weight):null,
        purity:body.purity?parseFloat(body.purity):null,
        discount:body.discount?parseFloat(body.discount):null,
        expense_category:body.expense_category||null,
        expense_sub:body.expense_sub||null,
        created_at:new Date().toISOString()
      };
      if(t.payment_status==='paid') t.amount_paid=total;
      db.transactions.push(t);
      applyTransaction(t,db);
      saveDB();
      json(res,enrichTxn(t,db),201); return;
    }
  }
  const txm=p.match(/^\/api\/transactions\/(\d+)$/);
  if(txm){
    const id=parseInt(txm[1]),i=db.transactions.findIndex(x=>parseInt(x.id)===id);
    if(method==='PUT'){
      if(i<0){err(res,'Not found',404);return;}
      const body=await readBody(req);
      if(body.record_payment){
        const t=db.transactions[i];
        const amt=parseFloat(body.payment_amount)||0;
        if(amt<=0){err(res,'payment_amount required');return;}
        const paid_so_far=(t.amount_paid||0)+amt;
        const new_status=paid_so_far>=(t.total_amount||0)?'paid':'partial';
        db.transactions[i].amount_paid=paid_so_far;
        db.transactions[i].payment_status=new_status;
        const payType=t.type==='sell'?'receive_payment':'pay_supplier';
        const payTxn={
          id:nextId(db.transactions),type:payType,
          date:body.date||new Date().toISOString().slice(0,10),
          reference:(t.reference||'TXN')+'-PMT',
          description:`Payment for: ${t.description||t.reference||''}`,
          company_id:body.company_id?parseInt(body.company_id):null,
          party_id:t.party_id,stock_item_id:null,
          quantity:null,unit_price:null,total_amount:amt,
          payment_status:'paid',amount_paid:amt,
          created_at:new Date().toISOString()
        };
        db.transactions.push(payTxn);
        applyTransaction(payTxn,db);
        saveDB();
        json(res,{ok:true,status:new_status}); return;
      }
      if(body.edit_fee){
        const t=db.transactions[i];
        if(t.expense_category!=='Cash Fee'){err(res,'Only cash fee transactions can be edited here');return;}
        if(body.date) t.date=body.date;
        if(body.party_id!==undefined) t.party_id=body.party_id?parseInt(body.party_id):null;
        if(body.total_amount!==undefined){
          const a=parseFloat(body.total_amount)||0;
          if(a<=0){err(res,'Amount must be greater than zero');return;}
          t.total_amount=a; t.amount_paid=a;
        }
        if(body.fee_type==='cash_in'||body.fee_type==='cash_out') t.type=body.fee_type;
        if(body.description!==undefined) t.description=body.description;
        rebuildBalances(); saveDB(); json(res,enrichTxn(t,db)); return;
      }
      err(res,'Use record_payment:true for PUT'); return;
    }
    if(method==='DELETE'){
      if(i<0){err(res,'Not found',404);return;}
      reverseTransaction(db.transactions[i],db);
      db.transactions.splice(i,1);
      saveDB(); json(res,{ok:true}); return;
    }
  }

  // ── Split a cash fee across several parties ────────────────────────────────
  const fsm=p.match(/^\/api\/transactions\/(\d+)\/split$/);
  if(fsm&&method==='POST'){
    const id=parseInt(fsm[1]),i=db.transactions.findIndex(x=>parseInt(x.id)===id);
    if(i<0){err(res,'Not found',404);return;}
    const t=db.transactions[i];
    if(t.expense_category!=='Cash Fee'){err(res,'Only cash fee transactions can be allocated');return;}
    const body=await readBody(req);
    const parts=(Array.isArray(body.parts)?body.parts:[]).map(x=>({
      party_id:x.party_id?parseInt(x.party_id):null,
      fee_type:(x.fee_type==='cash_in'||x.fee_type==='cash_out')?x.fee_type:t.type,
      amount:+(parseFloat(x.amount)||0).toFixed(2)})).filter(x=>x.amount>0);
    const same=parts.filter(x=>x.fee_type===t.type);
    if(!same.length){err(res,'Keep at least one row of the original fee type');return;}
    const sum=same.reduce((a,x)=>a+x.amount,0);
    if(Math.abs(sum-(t.total_amount||0))>0.01){err(res,`Rows of the original type add up to R${sum.toFixed(2)}, must equal the fee R${(t.total_amount||0).toFixed(2)}`);return;}
    // first same-type row stays on the original record; everything else becomes new fee records
    const first=same[0];
    t.party_id=first.party_id; t.total_amount=first.amount; t.amount_paid=first.amount;
    const created=[];
    parts.filter(x=>x!==first).forEach(x=>{
      const n={...t,id:nextId(db.transactions),type:x.fee_type,party_id:x.party_id,total_amount:x.amount,amount_paid:x.amount,
        split_from:t.id,created_at:new Date().toISOString()};
      db.transactions.push(n); created.push(n.id);
    });
    rebuildBalances(); saveDB(); json(res,{ok:true,updated:t.id,created}); return;
  }

  // ── Cash ───────────────────────────────────────────────────────────────────
  if(p==='/api/cash'&&method==='GET'){
    const cashTxns=db.transactions
      .filter(t=>((t.type==='cash_in'||t.type==='cash_out')&&t.expense_category!=='Cash Fee')
        ||((t.type==='investor_payment'||t.type==='investor_receipt')&&t.source==='cash'))
      .sort((a,b)=>a.date.localeCompare(b.date)||a.id-b.id)
      .map(t=>enrichTxn(t,db));
    json(res,{balance:db.cash_balance||0,transactions:cashTxns}); return;
  }

  // ── Ledger: party ──────────────────────────────────────────────────────────
  const lpm=p.match(/^\/api\/ledger\/party\/(\d+)$/);
  if(lpm&&method==='GET'){
    const id=parseInt(lpm[1]);
    const party=db.parties.find(x=>x.id===id);
    if(!party){err(res,'Not found',404);return;}
    // Include all transactions where this party is the primary party (not just pool source)
    const txns=db.transactions
      .filter(t=>parseInt(t.party_id)===id)
      .sort((a,b)=>a.date.localeCompare(b.date)||parseInt(a.id)-parseInt(b.id))
      .map(t=>enrichTxn(t,db));
    json(res,{party,transactions:txns}); return;
  }

  // ── Ledger: stock ──────────────────────────────────────────────────────────
  const lsm=p.match(/^\/api\/ledger\/stock\/(\d+)$/);
  if(lsm&&method==='GET'){
    const id=parseInt(lsm[1]);
    const item=db.stock.find(x=>x.id===id);
    if(!item){err(res,'Not found',404);return;}
    const txns=db.transactions
      .filter(t=>t.stock_item_id===id&&(t.type==='buy'||t.type==='sell'))
      .sort((a,b)=>a.date.localeCompare(b.date)||a.id-b.id)
      .map(t=>enrichTxn(t,db));
    json(res,{item,transactions:txns}); return;
  }

  // ── Ledger: company ────────────────────────────────────────────────────────
  const lcm=p.match(/^\/api\/ledger\/company\/(\d+)$/);
  if(lcm&&method==='GET'){
    const id=parseInt(lcm[1]);
    const company=db.companies.find(x=>x.id===id);
    if(!company){err(res,'Not found',404);return;}
    const txns=db.transactions
      .filter(t=>parseInt(t.company_id)===id||parseInt(t.to_company_id)===id)
      .sort((a,b)=>a.date.localeCompare(b.date)||a.id-b.id)
      .map(t=>enrichTxn(t,db));
    json(res,{company,transactions:txns}); return;
  }

  // ── Suspense ───────────────────────────────────────────────────────────────
  if(p==='/api/suspense'){
    if(method==='GET'){
      const nm=(arr,id)=>{ const x=id?arr.find(o=>parseInt(o.id)===parseInt(id)):null; return x?x.name:null; };
      json(res,(db.suspense||[]).map(s=>({
        ...s,
        company_name:nm(db.companies,s.company_id||s.allocated_to_company),
        allocated_company_name:nm(db.companies,s.allocated_to_company),
        allocated_party_name:nm(db.parties,s.allocated_to_party)
      }))); return;
    }
    if(method==='POST'){
      const body=await readBody(req);
      if(!body.total_amount||!body.date){err(res,'date and total_amount required');return;}
      const s={
        id:nextId(db.suspense||[]),
        date:body.date,
        total_amount:Math.abs(parseFloat(body.total_amount)),
        direction:body.direction||'in', // 'in' = money received, 'out' = money paid
        description:body.description||'',
        reference:body.reference||'',
        company_id:body.company_id?parseInt(body.company_id):null,
        allocated:false,
        created_at:new Date().toISOString()
      };
      if(!db.suspense) db.suspense=[];
      db.suspense.push(s); saveDB(); json(res,s,201); return;
    }
  }
  const spm=p.match(/^\/api\/suspense\/(\d+)$/);
  if(spm){
    const id=parseInt(spm[1]);
    if(!db.suspense) db.suspense=[];
    const i=db.suspense.findIndex(x=>parseInt(x.id)===id);
    if(method==='PUT'){
      if(i<0){err(res,'Not found',404);return;}
      const body=await readBody(req);
      const s=db.suspense[i];
      if(body.company_id!==undefined){
        const cid=body.company_id?parseInt(body.company_id):null;
        s.company_id=cid;
        if(s.allocated){
          s.allocated_to_company=cid;
          const t=db.transactions.find(x=>parseInt(x.id)===parseInt(s.allocated_txn_id));
          if(t) t.company_id=cid;
        }
      }
      if(body.reference!==undefined) s.reference=body.reference;
      if(body.description!==undefined) s.description=body.description;
      rebuildBalances(); saveDB(); json(res,s); return;
    }
    if(method==='DELETE'){
      if(i<0){err(res,'Not found',404);return;}
      db.suspense.splice(i,1); saveDB(); json(res,{ok:true}); return;
    }
  }
  const sapm=p.match(/^\/api\/suspense\/(\d+)\/allocate$/);
  if(sapm&&method==='POST'){
    const id=parseInt(sapm[1]);
    if(!db.suspense) db.suspense=[];
    const i=db.suspense.findIndex(x=>parseInt(x.id)===id);
    if(i<0){err(res,'Not found',404);return;}
    const body=await readBody(req);
    const s=db.suspense[i];
    const party_id=body.party_id?parseInt(body.party_id):null;
    const company_id=body.company_id?parseInt(body.company_id):(s.company_id?parseInt(s.company_id):null);
    if(!company_id){err(res,'This suspense entry has no bank set. Set the bank first.');return;}
    // direction 'in' = we received money → receive_payment; 'out' = we paid → pay_supplier
    const txType=s.direction==='in'?'receive_payment':'pay_supplier';
    const t={
      id:nextId(db.transactions),
      type:txType,
      date:body.date||s.date,
      reference:s.reference||('SUSP-'+s.id),
      description:(body.notes||s.description||'')+(body.notes&&s.description?' — ':'')+(s.description&&body.notes?'':s.description||''),
      company_id,party_id,
      stock_item_id:null,quantity:null,unit_price:null,
      total_amount:s.total_amount,
      payment_status:'paid',amount_paid:s.total_amount,
      created_at:new Date().toISOString()
    };
    db.transactions.push(t);
    applyTransaction(t,db);
    // Mark suspense as allocated (keep for audit) and save
    db.suspense[i].allocated=true;
    db.suspense[i].allocated_to_party=party_id;
    db.suspense[i].allocated_to_company=company_id;
    if(!db.suspense[i].company_id) db.suspense[i].company_id=company_id;
    db.suspense[i].allocated_txn_id=t.id;
    db.suspense[i].allocated_at=new Date().toISOString();
    saveDB();
    json(res,{ok:true,transaction:enrichTxn(t,db)}); return;
  }

  // ── Backup ─────────────────────────────────────────────────────────────────
  if(p==='/api/backup/email'&&method==='POST'){
    try{
      const snap=JSON.stringify(db,null,2);
      const dt=new Date().toISOString().slice(0,10);
      await sendEmail(BACKUP_TO,`TradeLedger Backup ${dt}`,`TradeLedger data backup — ${dt}\n\n${snap}`);
      json(res,{ok:true}); return;
    }catch(e){ json(res,{ok:false,error:e.message}); return; }
  }
  if(p==='/api/backup/download'&&method==='GET'){
    if(!fs.existsSync(DATA_FILE)){err(res,'No data file yet');return;}
    const buf=fs.readFileSync(DATA_FILE);
    const dt=new Date().toISOString().slice(0,10);
    res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="tradeled-backup-${dt}.enc"`,'Content-Length':buf.length});
    res.end(buf); return;
  }

  err(res,'Not found',404);
}

// ── Start ─────────────────────────────────────────────────────────────────────
loadDB();
const server=http.createServer(async(req,res)=>{
  try{ await handleRequest(req,res); }
  catch(e){ console.error(e); err(res,'Internal server error',500); }
});
server.listen(PORT,()=>{
  console.log(`TradeLedger running on http://localhost:${PORT}`);
  console.log('Build 2026-11-01b: company-to-company transfers enabled');
  const broken=db.transactions.filter(t=>t.type==='transfer'&&!t.to_company_id);
  if(broken.length) console.log(`WARNING: ${broken.length} transfer(s) have no "To" company (saved by an older server). Delete and re-enter them: `+broken.map(t=>'#'+t.id).join(', '));
});
