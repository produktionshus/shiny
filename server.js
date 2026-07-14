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

// public read-only view of a user's TCG binders (same share token as the shiny collection)
app.get('/api/tcg/shared/:token', (req, res) => {
  const user = db.prepare('SELECT id, username FROM users WHERE share_token = ?')
    .get(String(req.params.token));
  if (!user) return res.status(404).json({ error: 'not_found' });
  const row = db.prepare('SELECT data FROM tcg_binders WHERE user_id = ?').get(user.id);
  res.json({ username: user.username, store: row ? JSON.parse(row.data) : null });
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

// pack-aabneren er sin egen app men deler motor (og konto) med TCG-binderen
app.get('/packs', (req, res) => res.sendFile(path.join(__dirname, 'tcg.html')));

app.use(express.static(__dirname, { extensions: ['html'] }));

app.listen(PORT, () => console.log(`Shiny-binderen kører på port ${PORT}, db: ${DB_PATH}`));
