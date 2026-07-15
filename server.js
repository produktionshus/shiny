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
  if (r.players.length >= 4) return res.status(409).json({ error: 'room_full' });
  if (r.phase !== 'lobby') return res.status(409).json({ error: 'already_playing' });
  const playerId = crypto.randomBytes(8).toString('base64url');
  const t1 = r.players.filter(p => p.team === 1).length;
  r.players.push({ id: playerId, name: name.trim(), team: t1 <= 1 ? 1 : 2 });
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
    me.team = me.team === 1 ? 2 : 1;
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
    const t1 = r.players.filter(p => p.team === 1), t2 = r.players.filter(p => p.team === 2);
    if (t1.length !== 2 || t2.length !== 2 || !r.setId) return res.status(400).json({ error: 'need_2v2_and_set' });
    if (type === 'rematch') { const f = r.firstTeam === 1 ? 2 : 1; r.firstTeam = f; } else r.firstTeam = r.firstTeam || 1;
    const [a, b] = r.firstTeam === 1 ? [t1, t2] : [t2, t1];
    r.order = [a[0].id, b[0].id, a[1].id, b[1].id]; // hold A sp1 -> hold B sp1 -> hold A sp2 -> hold B sp2
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

app.use(express.static(__dirname, { extensions: ['html'] }));

app.listen(PORT, () => console.log(`Shiny-binderen kører på port ${PORT}, db: ${DB_PATH}`));
