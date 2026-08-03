const path = require('path');
const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite'); // built-in, needs Node >= 24

const PORT = process.env.PORT || 3000;
// On Railway: mount a volume and set DB_PATH to a file on it, e.g. /data/shiny.db
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'shiny.db');
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    hash TEXT NOT NULL,
    created TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS collections (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    data TEXT NOT NULL DEFAULT '[]',
    updated TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

try { db.exec('ALTER TABLE users ADD COLUMN share_token TEXT'); } catch (e) { /* column exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN friends TEXT'); } catch (e) { /* column exists */ }

db.exec(`
  CREATE TABLE IF NOT EXISTS tcg_binders (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    data TEXT NOT NULL,
    updated TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS price_history (
    card_id TEXT NOT NULL,
    day TEXT NOT NULL,
    eur REAL,
    usd REAL,
    PRIMARY KEY (card_id, day)
  );
  CREATE TABLE IF NOT EXISTS sets_meta (
    lang TEXT NOT NULL,
    set_id TEXT NOT NULL,
    name TEXT,
    date TEXT,
    official INTEGER,
    PRIMARY KEY (lang, set_id)
  );
  CREATE TABLE IF NOT EXISTS card_hashes (
    card_id TEXT PRIMARY KEY,
    hash BLOB NOT NULL
  );
  CREATE TABLE IF NOT EXISTS tcg_comments (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    author_id INTEGER NOT NULL REFERENCES users(id),
    text TEXT NOT NULL,
    created TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS tcg_snaps (
    code TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const app = express();
app.set('trust proxy', 1); // Railway sits behind a proxy
app.use(express.json({ limit: '512kb' })); // TCG-bindere er større blobs end shiny-samlinger
app.use(cookieSession({
  name: 'shinysession',
  secret: SESSION_SECRET,
  maxAge: 180 * 24 * 60 * 60 * 1000, // 180 days
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  httpOnly: true,
}));

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'not_logged_in' });
  next();
}

app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string'
      || !/^[a-zA-Z0-9æøåÆØÅ_.-]{2,30}$/.test(username) || password.length < 6) {
    return res.status(400).json({ error: 'invalid_input' });
  }
  const hash = bcrypt.hashSync(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (username, hash) VALUES (?, ?)').run(username, hash);
    req.session.userId = info.lastInsertRowid;
    req.session.username = username;
    res.json({ username });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'username_taken' });
    throw e;
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username || ''));
  if (!user || !bcrypt.compareSync(String(password || ''), user.hash)) {
    return res.status(401).json({ error: 'bad_credentials' });
  }
  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ username: user.username });
});

app.post('/api/logout', (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

app.post('/api/change-password', requireLogin, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (typeof newPassword !== 'string' || newPassword.length < 6) {
    return res.status(400).json({ error: 'invalid_input' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user || !bcrypt.compareSync(String(oldPassword || ''), user.hash)) {
    return res.status(401).json({ error: 'bad_credentials' });
  }
  db.prepare('UPDATE users SET hash = ? WHERE id = ?')
    .run(bcrypt.hashSync(newPassword, 10), user.id);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ username: req.session.username || null });
});

app.get('/api/collection', requireLogin, (req, res) => {
  const row = db.prepare('SELECT data FROM collections WHERE user_id = ?').get(req.session.userId);
  res.json({ collected: row ? JSON.parse(row.data) : [] });
});

app.put('/api/collection', requireLogin, (req, res) => {
  const { collected } = req.body || {};
  // items are either dex numbers (shiny binder) or extras keys like "c25_FALL_2019"
  const okItem = v =>
    (Number.isInteger(v) && v > 0 && v < 100000) ||
    (typeof v === 'string' && /^[a-z][0-9]{1,4}(_[A-Z0-9_]{1,40})?$/.test(v));
  if (!Array.isArray(collected) || collected.length > 10000 || !collected.every(okItem)) {
    return res.status(400).json({ error: 'invalid_collection' });
  }
  db.prepare(`INSERT INTO collections (user_id, data, updated) VALUES (?, ?, CURRENT_TIMESTAMP)
              ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated = CURRENT_TIMESTAMP`)
    .run(req.session.userId, JSON.stringify(collected));
  res.json({ ok: true, count: collected.length });
});

// ===== TCG binders (whole store as one JSON blob per user; last write wins) =====
function validTcgStore(st) {
  if (!st || typeof st !== 'object' || !Array.isArray(st.binders)) return false;
  if (st.binders.length < 1 || st.binders.length > 30) return false;
  if (!Number.isInteger(st.active) || st.active < 0 || st.active >= st.binders.length) return false;
  const okCard = c => c === null || (c && typeof c === 'object'
    && typeof c.id === 'string' && c.id.length <= 40
    && typeof c.n === 'string' && c.n.length <= 80
    && (c.img == null || (typeof c.img === 'string' && c.img.length <= 120)));
  return st.binders.every(b => b && typeof b === 'object'
    && typeof b.name === 'string' && b.name.length <= 60
    && [2, 3, 4].includes(b.cols) && [2, 3, 4].includes(b.rows)
    && typeof b.color === 'string' && b.color.length <= 10
    && Array.isArray(b.pages) && b.pages.length <= 100
    && b.pages.every(p => Array.isArray(p) && p.length <= 16 && p.every(okCard)));
}

app.get('/api/tcg', requireLogin, (req, res) => {
  const row = db.prepare('SELECT data FROM tcg_binders WHERE user_id = ?').get(req.session.userId);
  res.json({ store: row ? JSON.parse(row.data) : null });
});

app.put('/api/tcg', requireLogin, (req, res) => {
  const { store } = req.body || {};
  if (!validTcgStore(store)) return res.status(400).json({ error: 'invalid_store' });
  db.prepare(`INSERT INTO tcg_binders (user_id, data, updated) VALUES (?, ?, CURRENT_TIMESTAMP)
              ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated = CURRENT_TIMESTAMP`)
    .run(req.session.userId, JSON.stringify(store));
  res.json({ ok: true });
});

// purchase price/date is private — never leaves the owner's own session
function stripPrivate(store) {
  if (!store) return store;
  const { tray, ...pub } = store; // bakken (parkerede kort) er privat arbejdsflade
  return {
    ...pub,
    binders: (store.binders || []).map(b => ({
      ...b,
      pages: (b.pages || []).map(pg => pg.map(c => {
        if (!c) return null;
        const { pp, pd, note, ...rest } = c; // condition deles (trade-relevant), noter er private
        return rest;
      })),
    })),
  };
}

// public read-only view of a user's TCG binders (same share token as the shiny collection)
app.get('/api/tcg/shared/:token', (req, res) => {
  const user = db.prepare('SELECT id, username FROM users WHERE share_token = ?')
    .get(String(req.params.token));
  if (!user) return res.status(404).json({ error: 'not_found' });
  const row = db.prepare('SELECT data FROM tcg_binders WHERE user_id = ?').get(user.id);
  res.json({ username: user.username, store: row ? stripPrivate(JSON.parse(row.data)) : null });
});

// image proxy for canvas rendering (TCGdex CDN sends no CORS headers, so
// drawing directly would taint the canvas and block PNG export)
app.get('/api/img/*', async (req, res) => {
  const imgPath = req.params[0] || '';
  const isPtcg = imgPath.startsWith('ptcg/'); // fallback-kilde for TCGdex-huller (fx Galarian Gallery)
  const okPath = isPtcg
    ? /^ptcg\/[\w.-]{2,40}\/[\w.-]{1,20}\.png$/.test(imgPath)
    : /^[\w/.-]{5,160}\.webp$/.test(imgPath);
  if (!okPath || imgPath.includes('..')) {
    return res.status(400).end();
  }
  try {
    const url = isPtcg
      ? 'https://images.pokemontcg.io/' + imgPath.slice(5, -4) + '_hires.png'
      : 'https://assets.tcgdex.net/' + imgPath;
    const r = await fetch(url);
    if (!r.ok) return res.status(404).end();
    res.set('Content-Type', isPtcg ? 'image/png' : 'image/webp');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(Buffer.from(await r.arrayBuffer()));
  } catch (e) {
    res.status(502).end();
  }
});

// ===== card scan index (grid perceptual hashes of every EN card image) =====
let sharp = null;
try { sharp = require('sharp'); } catch (e) { console.error('sharp mangler — scan-indeks deaktiveret'); }

const HW = 32, HH = 44; // hash-oploesning, ca. 63:88
// SAMME algoritme er portet 1:1 til klienten i tcg.html — aendringer skal ske begge steder
function hashFromGray(g) {
  const bits = Buffer.alloc(40); // 64 globale bits + 16 celler x 16 bits
  let idx = 0;
  const setBit = on => { if (on) bits[idx >> 3] |= 128 >> (idx & 7); idx++; };
  const mean8 = [];
  for (let cy = 0; cy < 8; cy++) for (let cx = 0; cx < 8; cx++) {
    let sum = 0, n = 0;
    for (let y = Math.floor(cy * HH / 8); y < Math.floor((cy + 1) * HH / 8); y++)
      for (let x = Math.floor(cx * HW / 8); x < Math.floor((cx + 1) * HW / 8); x++) { sum += g[y * HW + x]; n++; }
    mean8.push(sum / n);
  }
  const gm = mean8.reduce((a, b) => a + b, 0) / 64;
  for (const m of mean8) setBit(m > gm);
  for (let gy = 0; gy < 4; gy++) for (let gx = 0; gx < 4; gx++) {
    const x0 = Math.floor(gx * HW / 4), x1 = Math.floor((gx + 1) * HW / 4);
    const y0 = Math.floor(gy * HH / 4), y1 = Math.floor((gy + 1) * HH / 4);
    const sub = [];
    for (let sy = 0; sy < 4; sy++) for (let sx = 0; sx < 4; sx++) {
      let sum = 0, n = 0;
      for (let y = y0 + Math.floor(sy * (y1 - y0) / 4); y < y0 + Math.floor((sy + 1) * (y1 - y0) / 4); y++)
        for (let x = x0 + Math.floor(sx * (x1 - x0) / 4); x < x0 + Math.floor((sx + 1) * (x1 - x0) / 4); x++) { sum += g[y * HW + x]; n++; }
      sub.push(n ? sum / n : 0);
    }
    const cm = sub.reduce((a, b) => a + b, 0) / 16;
    for (const m of sub) setBit(m > cm);
  }
  return bits;
}

function hashFromRGB(rgb) { // 40B bit-hash + 192B celle-farver (8x8 celler x RGB)
  const g = new Uint8Array(HW * HH);
  for (let i = 0; i < g.length; i++) {
    g[i] = (rgb[i * 3] * 0.299 + rgb[i * 3 + 1] * 0.587 + rgb[i * 3 + 2] * 0.114) | 0;
  }
  const bits = hashFromGray(g);
  const colors = Buffer.alloc(192);
  let ci = 0;
  for (let gy = 0; gy < 8; gy++) for (let gx = 0; gx < 8; gx++) {
    const x0 = Math.floor(gx * HW / 8), x1 = Math.floor((gx + 1) * HW / 8);
    const y0 = Math.floor(gy * HH / 8), y1 = Math.floor((gy + 1) * HH / 8);
    let r = 0, gr = 0, b = 0, n = 0;
    for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) {
      const o = (y * HW + x) * 3;
      r += rgb[o]; gr += rgb[o + 1]; b += rgb[o + 2]; n++;
    }
    colors[ci++] = Math.round(r / n);
    colors[ci++] = Math.round(gr / n);
    colors[ci++] = Math.round(b / n);
  }
  return Buffer.concat([bits, colors]);
}

// migration: alt der ikke er v3-format (232B) kasseres og genbygges
try {
  const sample = db.prepare('SELECT hash FROM card_hashes LIMIT 1').get();
  if (sample && sample.hash.length !== 232) {
    db.exec('DELETE FROM card_hashes');
    console.log('scan-indeks: gammelt format kasseret, genbygger v3 (8x8 farver)');
  }
} catch (e) {}

let scanIndexBuilding = false;
async function buildScanIndex() {
  if (!sharp || scanIndexBuilding) return;
  scanIndexBuilding = true;
  try {
    const sets = await fetch('https://api.tcgdex.net/v2/en/sets').then(r => r.json());
    const have = new Set(db.prepare('SELECT card_id FROM card_hashes').all().map(r => r.card_id));
    const ins = db.prepare('INSERT OR REPLACE INTO card_hashes (card_id, hash) VALUES (?, ?)');
    const hashOne = async c => {
      const url = c.image ? c.image + '/low.webp'
        : 'https://images.pokemontcg.io/' + c.id.slice(0, c.id.lastIndexOf('-')).replace('.', 'pt')
          + '/' + c.id.slice(c.id.lastIndexOf('-') + 1) + '.png'; // TCGdex-hul: proev fallback-kilden
      const r = await fetch(url);
      if (!r.ok) throw new Error('no image');
      const buf = Buffer.from(await r.arrayBuffer());
      const rgb = await sharp(buf).resize(HW, HH, { fit: 'fill' }).removeAlpha().raw().toBuffer();
      ins.run(c.id, hashFromRGB(rgb));
      have.add(c.id);
    };
    // prioritetspas: Mew-kort foerst (stoerste del af brugerens fysiske samling)
    try {
      const prio = await fetch('https://api.tcgdex.net/v2/en/cards?name=mew').then(r => r.json());
      for (const c of prio) {
        if (have.has(c.id)) continue;
        try { await hashOne(c); } catch (e) { /* videre */ }
        await new Promise(r => setTimeout(r, 60));
      }
      console.log('scan-indeks prioritet: mew-kort klar');
    } catch (e) { /* prioritet er best effort */ }
    for (const st of sets) {
      let detail = null;
      try {
        const r = await fetch('https://api.tcgdex.net/v2/en/sets/' + encodeURIComponent(st.id));
        if (r.ok) detail = await r.json();
      } catch (e) { /* videre */ }
      if (!detail) continue;
      for (const c of detail.cards || []) {
        if (have.has(c.id)) continue;
        try { await hashOne(c); } catch (e) { /* enkelt kort fejler: videre */ }
        await new Promise(r => setTimeout(r, 60)); // skaansom takt
      }
    }
    console.log('scan-indeks:', db.prepare('SELECT COUNT(*) AS n FROM card_hashes').get().n, 'kort');
  } finally {
    scanIndexBuilding = false;
  }
}
setTimeout(() => buildScanIndex().catch(e => console.error('scan-indeks fejlede:', e)), 2 * 60 * 1000);
setInterval(() => buildScanIndex().catch(() => {}), 24 * 60 * 60 * 1000); // nye kort samles op dagligt

app.get('/api/scan-index-bin', (req, res) => { // binaert: [u8 idLen][id][232B] per kort
  const rows = db.prepare('SELECT card_id, hash FROM card_hashes').all();
  const parts = [Buffer.from('PBS3')];
  const cnt = Buffer.alloc(4);
  cnt.writeUInt32LE(rows.length);
  parts.push(cnt);
  for (const r of rows) {
    const idb = Buffer.from(r.card_id, 'utf8');
    parts.push(Buffer.from([idb.length]), idb, Buffer.from(r.hash));
  }
  res.set('Content-Type', 'application/octet-stream');
  res.set('Cache-Control', 'public, max-age=86400');
  res.send(Buffer.concat(parts));
});

// ===== sets metadata (release dates live only in per-set details; cached here) =====
async function refreshSetsMeta(lang) {
  const list = await fetch('https://api.tcgdex.net/v2/' + lang + '/sets').then(r => r.json());
  const have = new Set(db.prepare('SELECT set_id FROM sets_meta WHERE lang = ?').all(lang).map(r => r.set_id));
  const ins = db.prepare('INSERT OR REPLACE INTO sets_meta (lang, set_id, name, date, official) VALUES (?, ?, ?, ?, ?)');
  for (const sset of list) {
    if (have.has(sset.id)) continue; // saet aendrer ikke udgivelsesdato
    try {
      const r = await fetch('https://api.tcgdex.net/v2/' + lang + '/sets/' + encodeURIComponent(sset.id));
      if (r.ok) {
        const d = await r.json();
        ins.run(lang, sset.id, d.name || sset.id, d.releaseDate || null,
          (d.cardCount && d.cardCount.official) || null);
      }
    } catch (e) { /* enkelt saet fejler: videre */ }
    await new Promise(r => setTimeout(r, 120)); // skaansom takt
  }
}
function maybeRefreshSets() {
  refreshSetsMeta('en').then(() => refreshSetsMeta('ja'))
    .catch(e => console.error('sets meta fejlede:', e));
}
setTimeout(maybeRefreshSets, 20 * 1000);
setInterval(maybeRefreshSets, 24 * 60 * 60 * 1000); // nye saet samles op dagligt

app.get('/api/sets-meta', (req, res) => {
  const lang = req.query.lang === 'ja' ? 'ja' : 'en';
  res.json({
    sets: db.prepare(
      'SELECT set_id AS id, name, date, official FROM sets_meta WHERE lang = ? ORDER BY date DESC').all(lang),
  });
});

// cachet proxy for pokemontcg.io-priser: upstream er langsom og rate-limited, cachen deles af alle
const pxCache = new Map(); // ptcgio-id -> {t, data}
app.get('/api/pxprice/:id', async (req, res) => {
  const id = String(req.params.id);
  if (!/^[\w.-]{3,40}$/.test(id)) return res.status(400).end();
  const hit = pxCache.get(id);
  if (hit && Date.now() - hit.t < 6 * 3600 * 1000) return res.json(hit.data);
  try {
    const r = await fetch('https://api.pokemontcg.io/v2/cards/' + encodeURIComponent(id) + '?select=cardmarket,tcgplayer');
    const data = r.ok ? ((await r.json()).data || null) : null;
    if (data || r.status === 404) pxCache.set(id, { t: Date.now(), data });
    res.set('Cache-Control', 'public, max-age=3600');
    res.json(data);
  } catch (e) { res.status(502).end(); }
});

// ===== admin: lokalt hostede billed-fallbacks + brugerrapporter om manglende billeder =====
const fsMod = require('fs');
const OVR_DIR = path.join(path.dirname(DB_PATH), 'img-overrides'); // paa volumen: overlever deploys
try { fsMod.mkdirSync(OVR_DIR, { recursive: true }); } catch (e) {}
db.exec(`CREATE TABLE IF NOT EXISTS img_missing (
  card_id TEXT PRIMARY KEY,
  name TEXT,
  count INTEGER DEFAULT 1,
  last TEXT
)`);
function isAdmin(req) {
  if (!req.session || !req.session.userId) return false;
  const admins = (process.env.ADMIN_USERS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
  if (!admins.length) return req.session.userId === 1; // ingen env sat: foerste konto er admin
  const u = db.prepare('SELECT username FROM users WHERE id = ?').get(req.session.userId);
  return !!u && admins.includes(u.username.toLowerCase());
}
const okOvrId = id => /^[\w.-]{2,40}$/.test(id) && !id.includes('..');
app.get('/api/img-overrides', (req, res) => {
  let ids = [];
  try { ids = fsMod.readdirSync(OVR_DIR).filter(f => f.endsWith('.webp')).map(f => f.slice(0, -5)); } catch (e) {}
  res.set('Cache-Control', 'public, max-age=300');
  res.json({ ids });
});
app.get('/api/img-override/:id', (req, res) => {
  const id = String(req.params.id);
  if (!okOvrId(id)) return res.status(400).end();
  const f = path.join(OVR_DIR, id + '.webp');
  if (!fsMod.existsSync(f)) return res.status(404).end();
  res.set('Content-Type', 'image/webp');
  res.set('Cache-Control', 'public, max-age=86400');
  res.send(fsMod.readFileSync(f));
});
app.post('/api/img-override/:id', express.raw({ type: ['image/*', 'application/octet-stream'], limit: '8mb' }), async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'admin_only' });
  const id = String(req.params.id);
  if (!okOvrId(id) || !sharp || !req.body || !req.body.length) return res.status(400).json({ error: 'bad_request' });
  try {
    const buf = await sharp(req.body).resize(600, 838, { fit: 'inside' }).webp({ quality: 88 }).toBuffer();
    fsMod.writeFileSync(path.join(OVR_DIR, id + '.webp'), buf);
    db.prepare('DELETE FROM img_missing WHERE card_id = ?').run(id);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: 'bad_image' }); }
});
app.post('/api/img-missing', (req, res) => { // klienter melder billedloese kort ind
  const id = String((req.body || {}).id || '');
  if (!okOvrId(id) || id.startsWith('custom-')) return res.status(400).end();
  db.prepare(`INSERT INTO img_missing (card_id, name, count, last) VALUES (?, ?, 1, CURRENT_TIMESTAMP)
    ON CONFLICT(card_id) DO UPDATE SET count = count + 1, last = CURRENT_TIMESTAMP, name = excluded.name`)
    .run(id, String((req.body || {}).name || '').slice(0, 80));
  res.json({ ok: true });
});
app.get('/api/img-missing', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'admin_only' });
  res.json({ missing: db.prepare('SELECT card_id, name, count, last FROM img_missing ORDER BY count DESC LIMIT 500').all() });
});

// korte delelinks: snapshot gemmes server-side, koden er content-hash (idempotent, ingen auth noedvendig)
app.post('/api/tcg/snap', (req, res) => {
  const data = JSON.stringify(req.body || {});
  if (data.length < 20 || data.length > 400000) return res.status(413).json({ error: 'bad_size' });
  const code = crypto.createHash('sha1').update(data).digest('base64url').slice(0, 10);
  db.prepare('INSERT OR REPLACE INTO tcg_snaps (code, data) VALUES (?, ?)').run(code, data);
  res.json({ code });
});
app.get('/api/tcg/snap/:code', (req, res) => {
  const row = db.prepare('SELECT data FROM tcg_snaps WHERE code = ?').get(String(req.params.code));
  if (!row) return res.status(404).json({ error: 'not_found' });
  res.set('Cache-Control', 'public, max-age=300');
  res.type('application/json').send(row.data);
});

// ===== price history (daily snapshot of cards present in any binder) =====
function cmValue(cm) { // foerste brugbare vaerdi, spike-daempet: lav-volumen promos faar vilde trends (xyp-XY110: trend 549, avg7 102)
  if (!cm) return null;
  let v = null;
  for (const k of ['trend', 'avg30', 'avg', 'trend-holo', 'avg30-holo', 'avg-holo', 'low']) {
    if (typeof cm[k] === 'number' && cm[k] > 0) { v = cm[k]; break; }
  }
  if (v != null && typeof cm.avg7 === 'number' && cm.avg7 > 0 && v > cm.avg7 * 3) v = cm.avg7;
  return v;
}
function saneCM(cm) { // korrupt upstream-data (fx xyp-XY192: low=100000 >> trend) filtreres fra
  if (!cm) return null;
  const ref = ['trend', 'avg30', 'avg'].map(k => cm[k]).find(v => typeof v === 'number' && v > 0);
  if (typeof cm.low === 'number' && ref && cm.low > ref * 5) return null;
  return cm;
}
function extractPrices(d) {
  const blocks = [];
  if (d && d.pricing) blocks.push(d.pricing);
  for (const v of (d && d.variants_detailed) || []) if (v.pricing) blocks.push(v.pricing);
  let eur = null, usd = null;
  for (const b of blocks) {
    if (eur === null) {
      const v = cmValue(saneCM(b && b.cardmarket));
      if (v != null) eur = v;
    }
    const tp = b && b.tcgplayer;
    if (tp && usd === null) {
      for (const k of Object.keys(tp)) {
        if (tp[k] && typeof tp[k].marketPrice === 'number') { usd = tp[k].marketPrice; break; }
      }
    }
  }
  return { eur, usd };
}

db.prepare("DELETE FROM price_history WHERE eur > 20000 OR usd > 20000 OR card_id = 'xyp-XY192'").run(); // gamle junk-snapshots

async function snapshotPrices() {
  const rows = db.prepare('SELECT data FROM tcg_binders').all();
  const ids = new Set();
  for (const r of rows) {
    try {
      for (const b of JSON.parse(r.data).binders || [])
        for (const pg of b.pages || [])
          for (const c of pg)
            if (c && c.id && !(c.img && c.img.startsWith('ja/'))) ids.add(c.id); // JP-print har sjaeldent priser
    } catch (e) { /* korrupt blob: spring over */ }
  }
  const day = new Date().toISOString().slice(0, 10);
  const ins = db.prepare('INSERT OR IGNORE INTO price_history (card_id, day, eur, usd) VALUES (?, ?, ?, ?)');
  for (const id of ids) {
    try {
      const r = await fetch('https://api.tcgdex.net/v2/en/cards/' + encodeURIComponent(id));
      if (r.ok) {
        let { eur, usd } = extractPrices(await r.json());
        if (eur === null && usd === null) { // TCGdex-prishul: proev pokemontcg.io
          try {
            const pr = await fetch('https://api.pokemontcg.io/v2/cards/' + encodeURIComponent(id.replace('.', 'pt')) + '?select=cardmarket,tcgplayer');
            if (pr.ok) {
              const p = (await pr.json()).data || {};
              const cmp = p.cardmarket && p.cardmarket.prices;
              if (cmp && typeof cmp.trendPrice === 'number' && cmp.trendPrice > 0) {
                eur = cmp.trendPrice;
                if (typeof cmp.avg7 === 'number' && cmp.avg7 > 0 && eur > cmp.avg7 * 3) eur = cmp.avg7;
              }
              const tpp = p.tcgplayer && p.tcgplayer.prices;
              if (tpp) for (const k of Object.keys(tpp)) {
                if (tpp[k] && typeof tpp[k].market === 'number' && tpp[k].market > 0) { usd = tpp[k].market; break; }
              }
            }
          } catch (e) { /* best effort */ }
        }
        if (eur !== null || usd !== null) ins.run(id, day, eur, usd);
      }
    } catch (e) { /* enkelt kort fejler: videre */ }
    await new Promise(r => setTimeout(r, 150)); // skaansom takt mod TCGdex
  }
  console.log(`price snapshot ${day}: ${ids.size} kort`);
}

function maybeSnapshotPrices() {
  const day = new Date().toISOString().slice(0, 10);
  const done = db.prepare('SELECT 1 FROM price_history WHERE day = ? LIMIT 1').get(day);
  if (!done) snapshotPrices().catch(e => console.error('price snapshot fejlede:', e));
}
setTimeout(maybeSnapshotPrices, 30 * 1000);          // kort efter boot
setInterval(maybeSnapshotPrices, 6 * 60 * 60 * 1000); // og loebende — koerer kun een gang pr. dag

app.get('/api/prices/:id', (req, res) => {
  const rows = db.prepare(
    'SELECT day, eur, usd FROM price_history WHERE card_id = ? ORDER BY day ASC LIMIT 400')
    .all(String(req.params.id));
  res.json({ history: rows });
});

// ===== comments on a user's binders (guestbook keyed by share token) =====
app.get('/api/tcg/comments/:token', (req, res) => {
  const owner = db.prepare('SELECT id FROM users WHERE share_token = ?').get(String(req.params.token));
  if (!owner) return res.status(404).json({ error: 'not_found' });
  const rows = db.prepare(`
    SELECT c.text, c.created, u.username AS author
    FROM tcg_comments c JOIN users u ON u.id = c.author_id
    WHERE c.owner_id = ? ORDER BY c.id DESC LIMIT 100`).all(owner.id);
  res.json({ comments: rows });
});

app.post('/api/tcg/comments/:token', requireLogin, (req, res) => {
  const owner = db.prepare('SELECT id FROM users WHERE share_token = ?').get(String(req.params.token));
  if (!owner) return res.status(404).json({ error: 'not_found' });
  const text = String((req.body || {}).text || '').trim();
  if (!text || text.length > 300) return res.status(400).json({ error: 'invalid_text' });
  db.prepare('INSERT INTO tcg_comments (owner_id, author_id, text) VALUES (?, ?, ?)')
    .run(owner.id, req.session.userId, text);
  res.json({ ok: true });
});

// ===== admin (enabled only when ADMIN_KEY env is set; key sent as X-Admin-Key header) =====
const crypto = require('crypto');
function requireAdmin(req, res, next) {
  const key = process.env.ADMIN_KEY;
  const given = req.get('x-admin-key') || '';
  const ok = key && given.length === key.length &&
    crypto.timingSafeEqual(Buffer.from(given), Buffer.from(key));
  if (!ok) return res.status(403).json({ error: 'forbidden' });
  next();
}

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.username, u.created, COALESCE(c.data, '[]') AS data, c.updated
    FROM users u LEFT JOIN collections c ON c.user_id = u.id
    ORDER BY u.id`).all();
  res.json(rows.map(r => ({
    id: r.id, username: r.username, created: r.created,
    items: JSON.parse(r.data).length, updated: r.updated || null,
  })));
});

app.post('/api/admin/reset-password', requireAdmin, (req, res) => {
  const { username, password } = req.body || {};
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'invalid_input' });
  }
  const info = db.prepare('UPDATE users SET hash = ? WHERE username = ?')
    .run(bcrypt.hashSync(password, 10), String(username || ''));
  if (!info.changes) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
  const u = db.prepare('SELECT id FROM users WHERE username = ?')
    .get(String((req.body || {}).username || ''));
  if (!u) return res.status(404).json({ error: 'not_found' });
  db.prepare('DELETE FROM collections WHERE user_id = ?').run(u.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(u.id);
  res.json({ ok: true });
});

// friends list (for compare view) follows the account
app.get('/api/friends', requireLogin, (req, res) => {
  const row = db.prepare('SELECT friends FROM users WHERE id = ?').get(req.session.userId);
  res.json({ friends: row.friends ? JSON.parse(row.friends) : [] });
});

app.put('/api/friends', requireLogin, (req, res) => {
  const { friends } = req.body || {};
  const ok = Array.isArray(friends) && friends.length <= 20 && friends.every(f =>
    f && typeof f === 'object' &&
    typeof f.token === 'string' && /^[\w-]{1,40}$/.test(f.token) &&
    typeof f.name === 'string' && f.name.length <= 40 &&
    typeof f.color === 'string' && /^#[0-9a-fA-F]{6}$/.test(f.color));
  if (!ok) return res.status(400).json({ error: 'invalid_friends' });
  const clean = friends.map(f => ({ token: f.token, name: f.name, color: f.color }));
  db.prepare('UPDATE users SET friends = ? WHERE id = ?')
    .run(JSON.stringify(clean), req.session.userId);
  res.json({ ok: true });
});

// get-or-create the caller's share token
app.post('/api/share', requireLogin, (req, res) => {
  let row = db.prepare('SELECT share_token FROM users WHERE id = ?').get(req.session.userId);
  if (!row.share_token) {
    const token = require('crypto').randomBytes(9).toString('base64url');
    db.prepare('UPDATE users SET share_token = ? WHERE id = ?').run(token, req.session.userId);
    row = { share_token: token };
  }
  res.json({ token: row.share_token });
});

// public read-only view of a shared collection
app.get('/api/shared/:token', (req, res) => {
  const user = db.prepare('SELECT id, username FROM users WHERE share_token = ?')
    .get(String(req.params.token));
  if (!user) return res.status(404).json({ error: 'not_found' });
  const row = db.prepare('SELECT data FROM collections WHERE user_id = ?').get(user.id);
  res.json({ username: user.username, collected: row ? JSON.parse(row.data) : [] });
});

// ===== 2v2 pack battle: rooms i hukommelsen (doer ved genstart — et spil varer minutter) =====
const rooms = new Map(); // code -> room
const ROOM_TTL = 2 * 60 * 60 * 1000;
setInterval(() => {
  const cutoff = Date.now() - ROOM_TTL;
  for (const [c, r] of rooms) if (r.touched < cutoff) rooms.delete(c);
}, 10 * 60 * 1000);

function roomCode() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // uden I/O — laesbare koder
  let c;
  do { c = Array.from({ length: 4 }, () => A[Math.floor(Math.random() * A.length)]).join(''); } while (rooms.has(c));
  return c;
}
function roomState(r) { // spillernes view — uden interne felter
  return {
    v: r.v, phase: r.phase, setId: r.setId, setName: r.setName,
    players: r.players.map(p => ({ id: p.id, name: p.name, team: p.team })),
    order: r.order, turn: r.turn, pulls: r.pulls, host: r.players[0] && r.players[0].id,
  };
}
function touchRoom(r) { r.touched = Date.now(); r.v++; }
const okName = n => typeof n === 'string' && n.trim().length >= 1 && n.length <= 14;

app.post('/api/battle', (req, res) => {
  const { name } = req.body || {};
  if (!okName(name)) return res.status(400).json({ error: 'bad_name' });
  if (rooms.size >= 500) return res.status(429).json({ error: 'too_many_rooms' });
  const code = roomCode();
  const playerId = crypto.randomBytes(8).toString('base64url');
  const room = {
    code, v: 0, touched: Date.now(), phase: 'lobby',
    setId: null, setName: null,
    players: [{ id: playerId, name: name.trim(), team: 1 }],
    order: [], turn: 0, pulls: {},
  };
  rooms.set(code, room);
  res.json({ code, playerId, state: roomState(room) });
});

app.post('/api/battle/:code/join', (req, res) => {
  const r = rooms.get(String(req.params.code).toUpperCase());
  if (!r) return res.status(404).json({ error: 'not_found' });
  const { name } = req.body || {};
  if (!okName(name)) return res.status(400).json({ error: 'bad_name' });
  const existing = r.players.find(p => p.name.toLowerCase() === name.trim().toLowerCase());
  if (existing) { touchRoom(r); return res.json({ code: r.code, playerId: existing.id, state: roomState(r) }); } // rejoin
  if (r.players.length >= 6) return res.status(409).json({ error: 'room_full' });
  if (r.phase !== 'lobby') return res.status(409).json({ error: 'already_playing' });
  const playerId = crypto.randomBytes(8).toString('base64url');
  const t1 = r.players.filter(p => p.team === 1).length;
  const t2 = r.players.filter(p => p.team === 2).length;
  r.players.push({ id: playerId, name: name.trim(), team: t1 > t2 ? 2 : 1 }); // balancer 1/2 — hold 3 vaelges manuelt

  touchRoom(r);
  res.json({ code: r.code, playerId, state: roomState(r) });
});

app.get('/api/battle/:code', (req, res) => {
  const r = rooms.get(String(req.params.code).toUpperCase());
  if (!r) return res.status(404).json({ error: 'not_found' });
  res.json({ state: roomState(r) });
});

app.post('/api/battle/:code/act', (req, res) => {
  const r = rooms.get(String(req.params.code).toUpperCase());
  if (!r) return res.status(404).json({ error: 'not_found' });
  const { playerId, type } = req.body || {};
  const me = r.players.find(p => p.id === playerId);
  if (!me) return res.status(403).json({ error: 'not_in_room' });
  const isHost = r.players[0] && r.players[0].id === playerId;
  const myTurn = r.order[r.turn] === playerId;

  if (type === 'team') {
    if (r.phase !== 'lobby') return res.status(409).json({ error: 'already_playing' });
    me.team = me.team % 3 + 1; // cykler 1 -> 2 -> 3 -> 1
  } else if (type === 'set') {
    if (!isHost || r.phase !== 'lobby') return res.status(403).json({ error: 'host_only' });
    const { setId, setName } = req.body;
    if (typeof setId !== 'string' || setId.length > 20 || typeof setName !== 'string' || setName.length > 60) {
      return res.status(400).json({ error: 'bad_set' });
    }
    r.setId = setId;
    r.setName = setName;
  } else if (type === 'start' || type === 'rematch') {
    if (!isHost) return res.status(403).json({ error: 'host_only' });
    if (type === 'start' && r.phase !== 'lobby') return res.status(409).json({ error: 'already_playing' });
    // generelt: mindst 2 hold, alle hold lige store — daekker 1v1, 2v2, 3v3, 2v2v2
    const teamsUsed = [...new Set(r.players.map(p => p.team))].sort();
    const groups = teamsUsed.map(t => r.players.filter(p => p.team === t));
    const equal = groups.every(g => g.length === groups[0].length);
    if (teamsUsed.length < 2 || !equal || !r.setId) return res.status(400).json({ error: 'need_even_teams_and_set' });
    r.firstIdx = type === 'rematch' ? ((r.firstIdx || 0) + 1) % groups.length : (r.firstIdx || 0); // rotér starthold
    const rot = groups.slice(r.firstIdx).concat(groups.slice(0, r.firstIdx));
    r.order = [];
    for (let i = 0; i < rot[0].length; i++) for (const g of rot) r.order.push(g[i].id); // flet holdene
    r.turn = 0;
    r.pulls = {};
    r.phase = 'playing';
  } else if (type === 'reveal') {
    if (r.phase !== 'playing' || !myTurn) return res.status(403).json({ error: 'not_your_turn' });
    const { card } = req.body;
    if (!card || typeof card.n !== 'string' || card.n.length > 80
        || (card.img != null && (typeof card.img !== 'string' || card.img.length > 120))) {
      return res.status(400).json({ error: 'bad_card' });
    }
    const pull = r.pulls[playerId] || (r.pulls[playerId] = { cards: [], value: null });
    if (pull.cards.length >= 10) return res.status(400).json({ error: 'pack_full' });
    pull.cards.push({ n: card.n, img: card.img || null, hit: !!card.hit, rev: !!card.rev });
  } else if (type === 'packDone') {
    if (r.phase !== 'playing' || !myTurn) return res.status(403).json({ error: 'not_your_turn' });
    const { value, best } = req.body;
    const pull = r.pulls[playerId] || (r.pulls[playerId] = { cards: [], value: null });
    pull.value = typeof value === 'number' && isFinite(value) ? Math.max(0, Math.min(99999, value)) : 0;
    if (best && typeof best.n === 'string' && best.n.length <= 80) {
      pull.best = { n: best.n, img: typeof best.img === 'string' && best.img.length <= 120 ? best.img : null,
        p: typeof best.p === 'number' && isFinite(best.p) ? best.p : null };
    }
    r.turn++;
    if (r.turn >= r.order.length) r.phase = 'done';
  } else {
    return res.status(400).json({ error: 'bad_action' });
  }
  touchRoom(r);
  res.json({ state: roomState(r) });
});

// pack-aabneren er sin egen app men deler motor (og konto) med TCG-binderen
app.get('/packs', (req, res) => res.sendFile(path.join(__dirname, 'tcg.html')));
app.get('/go', (req, res) => res.sendFile(path.join(__dirname, 'index.html'))); // shiny paa alle domaener

// pokebinder.dk viser binderen direkte paa roden; shiny bor paa sit eget domaene
app.get('/', (req, res, next) => {
  if ((req.hostname || '').includes('pokebinder')) {
    return res.sendFile(path.join(__dirname, 'tcg.html'));
  }
  next();
});

app.use(express.static(__dirname, { extensions: ['html'] }));

app.listen(PORT, () => console.log(`Shiny-binderen kører på port ${PORT}, db: ${DB_PATH}`));
