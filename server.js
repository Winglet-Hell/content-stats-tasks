'use strict';

const path = require('path');
const fs = require('fs-extra');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 5500;
const USERS_FILE = path.join(__dirname, '.data', 'users.json');
const STORE_FILE = path.join(__dirname, '.data', 'shared.json');

fs.ensureDirSync(path.dirname(USERS_FILE));
if (!fs.existsSync(USERS_FILE)) fs.writeJsonSync(USERS_FILE, { users: [] }, { spaces: 2 });
if (!fs.existsSync(STORE_FILE)) fs.writeJsonSync(STORE_FILE, { bookmarks: [], filters: {}, personal: {} }, { spaces: 2 });

app.use(express.json());
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

function readUsers() {
  try { return fs.readJsonSync(USERS_FILE); } catch { return { users: [] }; }
}
function writeUsers(db) {
  fs.writeJsonSync(USERS_FILE, db, { spaces: 2 });
}
function findUser(db, username) {
  const u = String(username || '').toLowerCase();
  return db.users.find(x => String(x.usernameLower) === u);
}

// Shared store helpers
function readStore() {
  try {
    const s = fs.readJsonSync(STORE_FILE);
    if (!s.bookmarks) s.bookmarks = [];
    if (!s.filters) s.filters = {};
    if (!s.personal) s.personal = {};
    return s;
  } catch {
    return { bookmarks: [], filters: {}, personal: {} };
  }
}
function writeStore(s) { fs.writeJsonSync(STORE_FILE, s, { spaces: 2 }); }

app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).send('username/password required');
  const db = readUsers();
  if (findUser(db, username)) return res.status(409).send('exists');
  const hash = await bcrypt.hash(password, 10);
  db.users.push({ username, usernameLower: String(username).toLowerCase(), hash, createdAt: Date.now() });
  writeUsers(db);
  req.session.user = { username };
  res.json({ ok: true, username });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).send('username/password required');
  const db = readUsers();
  const user = findUser(db, username);
  if (!user) return res.status(401).send('invalid');
  const ok = await bcrypt.compare(password, user.hash);
  if (!ok) return res.status(401).send('invalid');
  req.session.user = { username: user.username };
  res.json({ ok: true, username: user.username });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (req.session?.user?.username) return res.json({ username: req.session.user.username });
  res.status(401).send('unauthorized');
});

// Bookmarks API (shared for all users)
// Shared bookmarks (global)
app.get('/api/bookmarks', (req, res) => {
  const store = readStore();
  res.json({ bookmarks: store.bookmarks || [] });
});
app.get('/api/bookmarks/shared', (req, res) => {
  const store = readStore();
  res.json({ bookmarks: store.bookmarks || [] });
});

app.post('/api/bookmarks', (req, res) => {
  const { name, config } = req.body || {};
  if (!name || !config) return res.status(400).send('name/config required');
  const store = readStore();
  const id = Date.now();
  // de-dup by name (case-insensitive)
  store.bookmarks = (store.bookmarks || []).filter(b => String(b.name || '').toLowerCase() !== String(name).toLowerCase());
  store.bookmarks.unshift({ id, name, config });
  writeStore(store);
  res.json({ ok: true, id });
});
app.post('/api/bookmarks/shared', (req, res) => {
  const { name, config } = req.body || {};
  if (!name || !config) return res.status(400).send('name/config required');
  const store = readStore();
  const id = Date.now();
  store.bookmarks = (store.bookmarks || []).filter(b => String(b.name || '').toLowerCase() !== String(name).toLowerCase());
  store.bookmarks.unshift({ id, name, config });
  writeStore(store);
  res.json({ ok: true, id });
});

app.put('/api/bookmarks/:id', (req, res) => {
  const id = Number(req.params.id);
  const { name, config } = req.body || {};
  const store = readStore();
  const idx = (store.bookmarks || []).findIndex(b => Number(b.id) === id);
  if (idx < 0) return res.status(404).send('not found');
  if (name) store.bookmarks[idx].name = name;
  if (config) store.bookmarks[idx].config = config;
  writeStore(store);
  res.json({ ok: true });
});
app.put('/api/bookmarks/shared/:id', (req, res) => {
  const id = Number(req.params.id);
  const { name, config } = req.body || {};
  const store = readStore();
  const idx = (store.bookmarks || []).findIndex(b => Number(b.id) === id);
  if (idx < 0) return res.status(404).send('not found');
  if (name) store.bookmarks[idx].name = name;
  if (config) store.bookmarks[idx].config = config;
  writeStore(store);
  res.json({ ok: true });
});

app.delete('/api/bookmarks/:id', (req, res) => {
  const id = Number(req.params.id);
  const store = readStore();
  store.bookmarks = (store.bookmarks || []).filter(b => Number(b.id) !== id);
  writeStore(store);
  res.json({ ok: true });
});
app.delete('/api/bookmarks/shared/:id', (req, res) => {
  const id = Number(req.params.id);
  const store = readStore();
  store.bookmarks = (store.bookmarks || []).filter(b => Number(b.id) !== id);
  writeStore(store);
  res.json({ ok: true });
});

// Personal bookmarks (per user)
function requireAuth(req, res, next) {
  if (req.session?.user?.username) return next();
  return res.status(401).send('unauthorized');
}
function usernameKey(req) {
  return String(req.session.user.username).toLowerCase();
}

app.get('/api/bookmarks/personal', requireAuth, (req, res) => {
  const store = readStore();
  const key = usernameKey(req);
  const list = (store.personal && store.personal[key]) || [];
  res.json({ bookmarks: list });
});

app.post('/api/bookmarks/personal', requireAuth, (req, res) => {
  const { name, config } = req.body || {};
  if (!name || !config) return res.status(400).send('name/config required');
  const store = readStore();
  const key = usernameKey(req);
  if (!store.personal) store.personal = {};
  if (!Array.isArray(store.personal[key])) store.personal[key] = [];
  const id = Date.now();
  store.personal[key] = store.personal[key].filter(b => String(b.name || '').toLowerCase() !== String(name).toLowerCase());
  store.personal[key].unshift({ id, name, config });
  writeStore(store);
  res.json({ ok: true, id });
});

app.put('/api/bookmarks/personal/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const { name, config } = req.body || {};
  const store = readStore();
  const key = usernameKey(req);
  const list = (store.personal && store.personal[key]) || [];
  const idx = list.findIndex(b => Number(b.id) === id);
  if (idx < 0) return res.status(404).send('not found');
  if (name) list[idx].name = name;
  if (config) list[idx].config = config;
  store.personal[key] = list;
  writeStore(store);
  res.json({ ok: true });
});

app.delete('/api/bookmarks/personal/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const store = readStore();
  const key = usernameKey(req);
  const list = (store.personal && store.personal[key]) || [];
  store.personal[key] = list.filter(b => Number(b.id) !== id);
  writeStore(store);
  res.json({ ok: true });
});

// Current filters API (shared)
app.get('/api/filters', (req, res) => {
  const store = readStore();
  res.json({ filters: store.filters || {} });
});

app.put('/api/filters', (req, res) => {
  const { filters } = req.body || {};
  if (!filters || typeof filters !== 'object') return res.status(400).send('filters required');
  const store = readStore();
  store.filters = filters;
  writeStore(store);
  res.json({ ok: true });
});

app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});


