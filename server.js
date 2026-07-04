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

const app = express();
app.set('trust proxy', 1); // Railway sits behind a proxy
app.use(express.json({ limit: '64kb' }));
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

app.use(express.static(__dirname, { extensions: ['html'] }));

app.listen(PORT, () => console.log(`Shiny-binderen kører på port ${PORT}, db: ${DB_PATH}`));
