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
  if (!Array.isArray(collected) || collected.length > 5000
      || !collected.every(n => Number.isInteger(n) && n > 0 && n < 100000)) {
    return res.status(400).json({ error: 'invalid_collection' });
  }
  db.prepare(`INSERT INTO collections (user_id, data, updated) VALUES (?, ?, CURRENT_TIMESTAMP)
              ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated = CURRENT_TIMESTAMP`)
    .run(req.session.userId, JSON.stringify(collected));
  res.json({ ok: true, count: collected.length });
});

app.use(express.static(__dirname, { extensions: ['html'] }));

app.listen(PORT, () => console.log(`Shiny-binderen kører på port ${PORT}, db: ${DB_PATH}`));
