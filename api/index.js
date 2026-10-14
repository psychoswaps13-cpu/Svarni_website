// SWARNI backend: one Vercel serverless function. POST /api  { action, ...data }
// Needs env vars: SUPABASE_URL, SUPABASE_SERVICE_KEY, ADMIN_EMAIL, ADMIN_PASSWORD, SESSION_SECRET
const crypto = require('crypto');

const URL_ = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const KEY = process.env.SUPABASE_SERVICE_KEY || '';
const SECRET = process.env.SESSION_SECRET || '';
const BUCKET = 'product-images';

const DEFAULT_CATS = ['Necklaces', 'Earrings', 'Rings', 'Bangles', 'Mangalsutra', 'Bridal'];
const DEFAULT_SHOP = {
  upi: 'YOUR_UPI_ID', name: 'Swarni Jewellery', wa: '910000000000',
  freeShip: true, freeAbove: 999, shipFee: 99,
  phone: '+91 00000 00000', email: 'support@swarni.example', address: 'Pune, Maharashtra, India',
  insta: '', fb: '', yt: '', cod: true
};

/* ---------- Supabase REST helpers ---------- */
// Old-style keys (start with eyJ) also go in Authorization; new sb_secret_ keys only go in apikey.
const AUTHH = () => (KEY.startsWith('eyJ') ? { Authorization: 'Bearer ' + KEY } : {});
const H = (extra) => Object.assign({ apikey: KEY, 'Content-Type': 'application/json' }, AUTHH(), extra || {});
const enc = encodeURIComponent;

async function dbList(col, filter) {
  const r = await fetch(`${URL_}/rest/v1/docs?col=eq.${enc(col)}${filter || ''}&select=id,data&order=created_at.desc&limit=5000`, { headers: H() });
  if (!r.ok) throw new Error('Database error: ' + (await r.text()));
  return (await r.json()).map((x) => Object.assign({}, x.data, { id: x.id }));
}
async function dbGet(col, id) {
  const r = await fetch(`${URL_}/rest/v1/docs?col=eq.${enc(col)}&id=eq.${enc(id)}&select=data`, { headers: H() });
  if (!r.ok) throw new Error('Database error: ' + (await r.text()));
  const a = await r.json();
  return a[0] ? Object.assign({}, a[0].data, { id }) : null;
}
async function dbPut(col, id, data) {
  const body = Object.assign({}, data); delete body.id;
  const r = await fetch(`${URL_}/rest/v1/docs?on_conflict=col,id`, {
    method: 'POST', headers: H({ Prefer: 'resolution=merge-duplicates,return=minimal' }),
    body: JSON.stringify({ col, id, data: body })
  });
  if (!r.ok) throw new Error('Database error: ' + (await r.text()));
}
async function dbDel(col, id) {
  const r = await fetch(`${URL_}/rest/v1/docs?col=eq.${enc(col)}&id=eq.${enc(id)}`, { method: 'DELETE', headers: H() });
  if (!r.ok) throw new Error('Database error: ' + (await r.text()));
}

/* ---------- Sessions (signed tokens) ---------- */
const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const sign = (p) => { const body = b64u(JSON.stringify(p)); return body + '.' + b64u(crypto.createHmac('sha256', SECRET).update(body).digest()); };
function verify(tok) {
  try {
    const [body, sig] = String(tok || '').split('.');
    if (!body || !sig) return null;
    const good = b64u(crypto.createHmac('sha256', SECRET).update(body).digest());
    const a = Buffer.from(sig), b = Buffer.from(good);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const p = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
    return p.exp > Date.now() ? p : null;
  } catch (e) { return null; }
}
const issue = (uid, admin) => sign({ uid, admin: !!admin, exp: Date.now() + 30 * 24 * 3600 * 1000 });

function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 32).toString('hex'); }
function same(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

/* ---------- Helpers ---------- */
class Fail extends Error { constructor(msg, code) { super(msg); this.code = code || 400; } }
const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max || 200);
const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : (d || 0); };
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, addr: u.addr || null, admin: u.admin ? 1 : 0 });

async function getShop() { const s = await dbGet('config', 'shop'); return Object.assign({}, DEFAULT_SHOP, s || {}); }
async function getCats() { const c = await dbGet('config', 'cats'); return c && Array.isArray(c.list) ? c.list : DEFAULT_CATS; }
async function getCatImg() { const c = await dbGet('config', 'catimg'); return c && c.map ? c.map : {}; }

async function uploadImage(dataUrl) {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || '');
  if (!m) throw new Fail('Invalid image');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 1500000) throw new Fail('Image is too large');
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  const name = Date.now() + '-' + crypto.randomBytes(5).toString('hex') + '.' + ext;
  const r = await fetch(`${URL_}/storage/v1/object/${BUCKET}/${name}`, {
    method: 'POST',
    headers: Object.assign({ apikey: KEY, 'Content-Type': 'image/' + m[1], 'x-upsert': 'true' }, AUTHH()),
    body: buf
  });
  if (!r.ok) throw new Fail('Photo upload failed: ' + (await r.text()), 500);
  return `${URL_}/storage/v1/object/public/${BUCKET}/${name}`;
}
async function resolveImage(v) {
  if (typeof v !== 'string') return null;
  if (v.startsWith('data:image/')) return uploadImage(v);
  if (/^https:\/\//.test(v)) return v;
  return null;
}

function cleanProduct(p, old) {
  const out = {
    name: str(p.name, 120), cat: str(p.cat, 60),
    price: Math.max(0, num(p.price)), mrp: Math.max(0, num(p.mrp)),
    stock: Math.max(0, Math.floor(num(p.stock))), weight: Math.max(0, num(p.weight)),
    material: str(p.material, 40), spec: str(p.spec, 160), size: str(p.size, 80),
    occasion: str(p.occasion, 40), collection: str(p.collection, 80), desc: str(p.desc, 2000),
    ship: p.ship === null || p.ship === '' || p.ship === undefined ? null : Math.max(0, num(p.ship)),
    seed: Math.floor(num(p.seed, old ? old.seed : 0)), date: num(p.date, old ? old.date : Date.now())
  };
  if (!out.name) throw new Fail('Product name is required');
  if (!out.price) throw new Fail('Price is required');
  if (!out.mrp || out.mrp < out.price) out.mrp = out.price;
  return out;
}

/* ---------- Order maths (must match the website) ---------- */
function computeTotals(items, products, shop, coupon) {
  const sub = items.reduce((a, it) => a + it.price * it.q, 0);
  const d = String(coupon || '').toUpperCase() === 'SWARNI10' ? Math.round(sub * 0.1) : 0;
  const per = (p) => (p.ship != null && p.ship !== '' ? Number(p.ship) : shop.shipFee);
  let ship = 0;
  if (sub && !(shop.freeShip && sub - d >= shop.freeAbove)) ship = items.reduce((a, it) => a + per(products[it.id]) * it.q, 0);
  return { sub, d, ship, tot: sub - d + ship };
}

/* ---------- Actions ---------- */
const PUBLIC = {
  async public() {
    const [products, cats, catimg, shop, reviews] = await Promise.all([
      dbList('products'), getCats(), getCatImg(), getShop(), dbList('reviews')
    ]);
    const rv = {};
    reviews.forEach((r) => { (rv[r.pid] = rv[r.pid] || []).push({ id: r.id, n: r.n, r: r.r, t: r.t }); });
    return { products, cats, catimg, shop, reviews: rv };
  },
  async register(b) {
    const name = str(b.name, 80) || 'Customer', email = str(b.email, 120).toLowerCase(), pw = String(b.password || '');
    if (!emailOk(email)) throw new Fail('Please enter a valid email');
    if (pw.length < 6) throw new Fail('Password needs at least 6 characters');
    if (process.env.ADMIN_EMAIL && email === String(process.env.ADMIN_EMAIL).toLowerCase()) throw new Fail('This email is already registered. Please log in.');
    const ex = await dbList('users', `&data->>email=eq.${enc(email)}`);
    if (ex.length) throw new Fail('This email is already registered. Please log in.');
    const id = 'u' + Date.now() + crypto.randomBytes(3).toString('hex');
    const salt = crypto.randomBytes(16).toString('hex');
    const u = { name, email, salt, hash: hashPw(pw, salt), addr: null, date: new Date().toISOString() };
    await dbPut('users', id, u);
    return { token: issue(id, false), user: publicUser(Object.assign({ id }, u)) };
  },
  async login(b) {
    const email = str(b.email, 120).toLowerCase(), pw = String(b.password || '');
    if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD &&
        same(email, String(process.env.ADMIN_EMAIL).toLowerCase()) && same(pw, process.env.ADMIN_PASSWORD)) {
      return { token: issue('admin', true), user: { id: 'admin', name: 'Admin', email, admin: 1 } };
    }
    const ex = await dbList('users', `&data->>email=eq.${enc(email)}`);
    const u = ex[0];
    if (!u || !same(hashPw(pw, u.salt), u.hash)) throw new Fail('Email or password is incorrect', 401);
    return { token: issue(u.id, false), user: publicUser(u) };
  }
};

const USER = {
  async me(b, s) {
    if (s.uid === 'admin') return { user: { id: 'admin', name: 'Admin', email: process.env.ADMIN_EMAIL || '', admin: 1 } };
    const u = await dbGet('users', s.uid);
    if (!u) throw new Fail('Please log in again', 401);
    return { user: publicUser(u) };
  },
  async placeOrder(b, s) {
    if (s.uid === 'admin') throw new Fail('Please use a customer account to place orders');
    const u = await dbGet('users', s.uid);
    if (!u) throw new Fail('Please log in again', 401);
    const shop = await getShop();
    const a = b.addr || {};
    const addr = { name: str(a.name, 80), phone: str(a.phone, 10), line: str(a.line, 200), city: str(a.city, 80), state: str(a.state, 80), pin: str(a.pin, 6) };
    if (!addr.name || !addr.line || !addr.city || !addr.state) throw new Fail('Please fill the full address');
    if (!/^[6-9]\d{9}$/.test(addr.phone)) throw new Fail('Enter a valid 10-digit mobile number');
    if (!/^[1-9]\d{5}$/.test(addr.pin)) throw new Fail('Enter a valid 6-digit PIN code');
    const pay = b.pay === 'cod' ? 'cod' : 'upi';
    if (pay === 'cod' && !shop.cod) throw new Fail('Cash on delivery is not available');
    const raw = Array.isArray(b.items) ? b.items.slice(0, 50) : [];
    if (!raw.length) throw new Fail('Your cart is empty');
    const products = {};
    const items = [];
    for (const it of raw) {
      const p = products[it.id] || (products[it.id] = await dbGet('products', String(it.id)));
      const q = Math.floor(num(it.q));
      if (!p || q < 1) throw new Fail('A product in your cart is no longer available');
      items.push({ id: p.id, name: p.name, price: p.price, q });
    }
    // merge duplicate lines, then check stock
    const merged = {};
    items.forEach((i) => { if (merged[i.id]) merged[i.id].q += i.q; else merged[i.id] = Object.assign({}, i); });
    const lines = Object.values(merged);
    for (const l of lines) if (products[l.id].stock < l.q) throw new Fail(`Only ${products[l.id].stock} left of ${l.name}`);
    const t = computeTotals(lines, products, shop, b.coupon);
    const id = 'SW' + Date.now().toString().slice(-8) + Math.floor(Math.random() * 10);
    const order = { uid: s.uid, cust: u.name, items: lines, total: t.tot, ship: t.ship, discount: t.d, addr, pay, paid: false, utr: '', status: 0, date: new Date().toISOString() };
    await dbPut('orders', id, order);
    for (const l of lines) { const p = products[l.id]; p.stock -= l.q; await dbPut('products', p.id, p); }
    await dbPut('users', s.uid, Object.assign({}, u, { addr }));
    return { order: Object.assign({ id }, order) };
  },
  async myOrders(b, s) {
    return { orders: await dbList('orders', `&data->>uid=eq.${enc(s.uid)}`) };
  },
  async setUtr(b, s) {
    const o = await dbGet('orders', str(b.id, 30));
    if (!o || o.uid !== s.uid) throw new Fail('Order not found', 404);
    const utr = str(b.utr, 12);
    if (!/^\d{12}$/.test(utr)) throw new Fail('UTR must be the 12-digit number from GPay');
    if (o.pay !== 'upi') throw new Fail('This order is not a UPI order');
    o.utr = utr; await dbPut('orders', o.id, o);
    return { order: o };
  },
  async addReview(b, s) {
    if (s.uid === 'admin') throw new Fail('Please use a customer account to review');
    const u = await dbGet('users', s.uid);
    const p = await dbGet('products', str(b.pid, 40));
    if (!u || !p) throw new Fail('Product not found', 404);
    const t = str(b.t, 1000); const r = Math.min(5, Math.max(1, Math.round(num(b.r, 5))));
    if (!t) throw new Fail('Write a few words first');
    const id = 'r' + Date.now() + crypto.randomBytes(2).toString('hex');
    await dbPut('reviews', id, { pid: p.id, n: u.name, r, t, uid: s.uid });
    return { review: { id, n: u.name, r, t } };
  }
};

const ADMIN = {
  async adminData() {
    const [orders, users, reviews] = await Promise.all([dbList('orders'), dbList('users'), dbList('reviews')]);
    return { orders, users: users.map((u) => ({ id: u.id, name: u.name, email: u.email, date: u.date })), reviews };
  },
  async saveProduct(b) {
    const inc = b.product || {};
    const id = inc.id ? str(inc.id, 40) : 'p' + Date.now() + crypto.randomBytes(2).toString('hex');
    const old = inc.id ? await dbGet('products', id) : null;
    const p = cleanProduct(inc, old);
    const imgs = [];
    for (const v of (Array.isArray(inc.images) ? inc.images.slice(0, 5) : [])) { const u = await resolveImage(v); if (u) imgs.push(u); }
    p.images = imgs.length ? imgs : null;
    await dbPut('products', id, p);
    return { product: Object.assign({ id }, p) };
  },
  async deleteProduct(b) { await dbDel('products', str(b.id, 40)); return { ok: true }; },
  async saveCats(b) {
    const cats = (Array.isArray(b.cats) ? b.cats : []).map((c) => str(c, 60)).filter(Boolean).slice(0, 60);
    const imgIn = b.catimg && typeof b.catimg === 'object' ? b.catimg : {};
    const map = {};
    for (const c of cats) { if (imgIn[c]) { const u = await resolveImage(imgIn[c]); if (u) map[c] = u; } }
    if (b.rename && b.rename.from && b.rename.to) {
      const ps = await dbList('products');
      for (const p of ps) if (p.cat === b.rename.from) { p.cat = str(b.rename.to, 60); await dbPut('products', p.id, p); }
    }
    await dbPut('config', 'cats', { list: cats });
    await dbPut('config', 'catimg', { map });
    return { cats, catimg: map };
  },
  async saveShop(b) {
    const s = b.shop || {}; const cur = await getShop();
    const url = (v) => { v = str(v, 300); return v && !/^https?:\/\//i.test(v) ? 'https://' + v : v; };
    const out = {
      upi: str(s.upi, 80) || cur.upi, name: str(s.name, 80) || cur.name, wa: str(s.wa, 15).replace(/\D/g, '') || cur.wa,
      freeShip: !!s.freeShip, freeAbove: Math.max(0, num(s.freeAbove)), shipFee: Math.max(0, num(s.shipFee)),
      phone: str(s.phone, 40), email: str(s.email, 120), address: str(s.address, 300),
      insta: url(s.insta), fb: url(s.fb), yt: url(s.yt), cod: !!s.cod
    };
    await dbPut('config', 'shop', out);
    return { shop: out };
  },
  async orderUpdate(b) {
    const o = await dbGet('orders', str(b.id, 30));
    if (!o) throw new Fail('Order not found', 404);
    if (b.status !== undefined) o.status = Math.min(4, Math.max(0, Math.floor(num(b.status))));
    if (b.paid !== undefined) o.paid = !!b.paid;
    await dbPut('orders', o.id, o);
    return { order: o };
  },
  async deleteReview(b) { await dbDel('reviews', str(b.id, 40)); return { ok: true }; }
};

/* ---------- Entry point ---------- */
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const send = (code, obj) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(obj)); };
  try {
    if (req.method !== 'POST') return send(405, { error: 'Use POST' });
    if (!URL_ || !KEY || !SECRET) return send(500, { error: 'Server is not set up yet (missing environment variables).' });
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const action = String(body.action || '');
    if (Object.prototype.hasOwnProperty.call(PUBLIC, action)) return send(200, await PUBLIC[action](body));
    const auth = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const s = verify(auth);
    if (!s) return send(401, { error: 'Please log in' });
    if (Object.prototype.hasOwnProperty.call(USER, action)) return send(200, await USER[action](body, s));
    if (Object.prototype.hasOwnProperty.call(ADMIN, action)) {
      if (!s.admin) return send(403, { error: 'Admin only' });
      return send(200, await ADMIN[action](body, s));
    }
    return send(404, { error: 'Unknown action' });
  } catch (e) {
    if (e instanceof Fail) return send(e.code, { error: e.message });
    console.error(e);
    return send(500, { error: 'Something went wrong. Please try again.' });
  }
};
module.exports.computeTotals = computeTotals;
