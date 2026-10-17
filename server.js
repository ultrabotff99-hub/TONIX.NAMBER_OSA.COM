require('dotenv').config();
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const DB_FILE = './data/database.json';

// ============ DATABASE (JSON) ============
if (!fs.existsSync('./data')) fs.mkdirSync('./data');
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      users: [],
      pendingUsers: [],
      apis: [
        { id: 1, name: 'API-1 Basic',    url: 'https://osint.invalidayushh.workers.dev/num?key=69d&q=',    price: 10, dailyLimit: 1000, usedToday: 0, lastReset: today(), active: true },
        { id: 2, name: 'API-2 Advanced', url: 'https://osint.invalidayushh.workers.dev/numv2?key=69d&q=', price: 10, dailyLimit: 1000, usedToday: 0, lastReset: today(), active: true },
        { id: 3, name: 'API-3 Pakistan', url: 'https://osint.invalidayushh.workers.dev/pak?key=69d&q=',   price: 10, dailyLimit: 1000, usedToday: 0, lastReset: today(), active: true }
      ],
      payments: [],
      searches: [],
      auditLogs: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE));
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function today() { return new Date().toISOString().slice(0,10); }

// ============ UPI CONFIG ============
const UPI_CONFIG = { upiId: 'farispachukk@oksbi', payeeName: 'Cyber Security Tools' };

// ============ MIDDLEWARE ============
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || 'cyber_tool_secret_key_2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', 
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Rate limiters
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts.' } });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Too many registrations.' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, message: { error: 'Slow down.' } });

// Audit logger
function audit(db, action, details, req) {
  db.auditLogs.push({
    id: Date.now(),
    action, details,
    ip: req.ip || req.connection.remoteAddress,
    ua: req.headers['user-agent'] || '',
    user: req.session?.username || req.session?.userId || 'guest',
    timestamp: new Date().toISOString()
  });
  if (db.auditLogs.length > 5000) db.auditLogs = db.auditLogs.slice(-3000);
}

// ============ AUTH HELPERS ============
function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Login required' });
  const db = loadDB();
  const u = db.users.find(x => x.id === req.session.userId);
  if (!u) return res.status(401).json({ error: 'Session invalid' });
  if (u.blocked) return res.status(403).json({ error: 'Account blocked' });
  req.user = u;
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.status(401).json({ error: 'Admin only' });
  next();
}

// ============ USER ROUTES ============
// രജിസ്ട്രേഷൻ (യൂസർനെയിം, പാസ്‌വേഡ്, ഇൻവൈറ്റ് കോഡ്)
app.post('/api/register', registerLimiter, async (req, res) => {
  const { username, password, inviteCode } = req.body;
  if (!username || !password || !inviteCode) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password min 8 characters' });

  const validCodes = (process.env.INVITE_CODES || 'ALPHA2026,BETA2026').split(',').map(c => c.trim());
  if (!validCodes.includes(inviteCode.toUpperCase())) return res.status(403).json({ error: 'Invalid invite code.' });

  const db = loadDB();
  if (db.users.find(u => u.username === username) || db.pendingUsers.find(u => u.username === username))
    return res.status(400).json({ error: 'Username already exists' });

  const pending = {
    id: Date.now(), 
    username, 
    password: await bcrypt.hash(password, 10), 
    inviteCode: inviteCode.toUpperCase(),
    createdAt: new Date().toISOString(), 
    approved: false, 
    blocked: false
  };
  db.pendingUsers.push(pending);
  audit(db, 'REGISTER_REQUEST', { username, inviteCode }, req);
  saveDB(db);
  res.json({ success: true, message: 'Registration submitted. Wait for admin approval.' });
});

// ലോഗിൻ (യൂസർനെയിം, പാസ്‌വേഡ്)
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  
  const pendingUser = db.pendingUsers.find(u => u.username === username);
  if (pendingUser) return res.status(403).json({ error: '⏳ Awaiting admin approval' });

  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  if (user.blocked) return res.status(403).json({ error: 'Account blocked by admin' });
  if (!(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: 'Invalid credentials' });

  req.session.userId = user.id;
  req.session.username = user.username;
  user.lastLogin = new Date().toISOString();
  audit(db, 'LOGIN', { username }, req);
  saveDB(db);
  res.json({ success: true, user: { name: user.username, credits: user.credits } });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', requireUser, (req, res) => {
  res.json({ name: req.user.username, credits: req.user.credits, totalSpent: req.user.totalSpent || 0 });
});

app.post('/api/search', requireUser, apiLimiter, async (req, res) => {
  const { phone, apiId } = req.body;
  if (!/^\d{10}$/.test(phone)) return res.status(400).json({ error: 'Invalid 10-digit number' });

  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  const api = db.apis.find(a => a.id === apiId);
  if (!api || !api.active) return res.status(400).json({ error: 'API unavailable' });

  const cost = api.price || 10;
  if (user.credits < cost) return res.status(402).json({ error: `Need ₹${cost}. Recharge first.` });

  if (api.lastReset !== today()) { api.usedToday = 0; api.lastReset = today(); }
  if (api.usedToday >= api.dailyLimit) return res.status(429).json({ error: 'API daily limit reached' });

  try {
    const response = await axios.get(api.url + phone, { timeout: 20000 });
    user.credits -= cost;
    user.totalSpent = (user.totalSpent || 0) + cost;
    api.usedToday++;

    db.searches.push({ id: Date.now(), userId: user.id, username: user.username, phone, apiId: api.id, apiName: api.name, cost, timestamp: new Date().toISOString() });
    audit(db, 'SEARCH', { phone, apiId, cost }, req);
    saveDB(db);

    res.json({ success: true, charged: cost, remainingCredits: user.credits, data: response.data });
  } catch (err) {
    res.status(500).json({ error: 'API fetch failed' });
  }
});

app.post('/api/public/genqr', requireUser, (req, res) => {
  const amt = Number(req.body.amount);
  if (!amt || amt < 10) return res.status(400).json({ error: 'Minimum ₹10' });

  const txnRef = 'TXN' + Date.now();
  const upiLink = `upi://pay?pa=${encodeURIComponent(UPI_CONFIG.upiId)}&pn=${encodeURIComponent(UPI_CONFIG.payeeName)}&am=${amt}&cu=INR&tn=Recharge&tr=${txnRef}`;
  const qrImage = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(upiLink)}`;
  res.json({ success: true, upiLink, qrImage, txnRef, amount: amt, upiId: UPI_CONFIG.upiId });
});

app.post('/api/recharge', requireUser, (req, res) => {
  const { amount, txnId } = req.body;
  const amt = Number(amount);
  if (!amt || amt < 10) return res.status(400).json({ error: 'Minimum ₹10' });
  if (!txnId || txnId.length < 6) return res.status(400).json({ error: 'Invalid Txn ID' });

  const db = loadDB();
  if (db.payments.find(p => p.txnId === txnId)) return res.status(400).json({ error: 'Txn ID already submitted' });

  db.payments.push({ id: Date.now(), userId: req.user.id, username: req.user.username, amount: amt, method: 'upi', txnId, status: 'pending', timestamp: new Date().toISOString() });
  audit(db, 'PAYMENT_REQUEST', { amount: amt, txnId }, req);
  saveDB(db);
  res.json({ success: true, message: 'Submitted. Admin will verify soon.' });
});

app.get('/api/public/apis', requireUser, (req, res) => {
  const db = loadDB();
  res.json(db.apis.map(a => ({ id: a.id, name: a.name, price: a.price, active: a.active })));
});

// ============ ADMIN DIRECT URL LOGIN ============
app.get('/admin', (req, res) => {
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '3007';

  if (req.query.pass === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    const db = loadDB();
    audit(db, 'ADMIN_LOGIN_URL', { ip: req.ip }, req);
    saveDB(db);
    req.session.save((err) => {
      if (err) return res.status(500).send("Session error");
      res.sendFile(path.join(__dirname, 'public', 'admin.html'));
    });
  } else {
    res.status(401).send(`<body style="background:#0a0e27;color:#fff;text-align:center;padding:50px;font-family:sans-serif;"><h2 style="color:#ff6b6b;">⛔ Unauthorized Access</h2><p>Invalid or missing password in URL.</p></body>`);
  }
});

// ============ ADMIN API ROUTES ============
app.get('/api/admin/check', (req, res) => res.json({ isAdmin: !!req.session.isAdmin }));
app.post('/api/admin/logout', (req, res) => { req.session.isAdmin = false; res.json({ success: true }); });

app.get('/api/admin/pending', requireAdmin, (req, res) => res.json(loadDB().pendingUsers));

app.post('/api/admin/approve-user', requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.pendingUsers.findIndex(p => p.id === req.body.userId);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const p = db.pendingUsers[idx];
  db.users.push({ ...p, approved: true, credits: 0, totalSpent: 0 });
  db.pendingUsers.splice(idx, 1);
  saveDB(db);
  res.json({ success: true });
});

app.post('/api/admin/reject-user', requireAdmin, (req, res) => {
  const db = loadDB();
  db.pendingUsers = db.pendingUsers.filter(p => p.id !== req.body.userId);
  saveDB(db);
  res.json({ success: true });
});

app.get('/api/admin/users', requireAdmin, (req, res) => res.json(loadDB().users));

app.post('/api/admin/user/block', requireAdmin, (req, res) => {
  const db = loadDB();
  const u = db.users.find(x => x.id === req.body.userId);
  if (u) { u.blocked = !!req.body.blocked; saveDB(db); res.json({ success: true }); }
  else res.status(404).json({ error: 'Not found' });
});

app.post('/api/admin/user/credits', requireAdmin, (req, res) => {
  const db = loadDB();
  const u = db.users.find(x => x.id === req.body.userId);
  if (u) { u.credits += Number(req.body.delta); saveDB(db); res.json({ success: true, credits: u.credits }); }
  else res.status(404).json({ error: 'Not found' });
});

app.delete('/api/admin/user/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  db.users = db.users.filter(x => x.id != req.params.id);
  saveDB(db);
  res.json({ success: true });
});

app.get('/api/admin/payments', requireAdmin, (req, res) => res.json(loadDB().payments.sort((a,b) => b.id - a.id)));

app.post('/api/admin/payment/approve', requireAdmin, (req, res) => {
  const db = loadDB();
  const p = db.payments.find(x => x.id === req.body.paymentId);
  if (p && p.status === 'pending') {
    const user = db.users.find(u => u.id === p.userId);
    if (user) user.credits += p.amount;
    p.status = 'approved'; saveDB(db); res.json({ success: true });
  } else res.status(400).json({ error: 'Invalid' });
});

app.post('/api/admin/payment/reject', requireAdmin, (req, res) => {
  const db = loadDB();
  const p = db.payments.find(x => x.id === req.body.paymentId);
  if (p && p.status === 'pending') { p.status = 'rejected'; saveDB(db); res.json({ success: true }); }
  else res.status(400).json({ error: 'Invalid' });
});

app.get('/api/admin/apis', requireAdmin, (req, res) => res.json(loadDB().apis));

app.post('/api/admin/apis', requireAdmin, (req, res) => {
  const db = loadDB();
  db.apis.push({ id: Date.now(), name: req.body.name, url: req.body.url, price: Number(req.body.price) || 10, dailyLimit: Number(req.body.dailyLimit) || 1000, usedToday: 0, lastReset: today(), active: true });
  saveDB(db); res.json({ success: true });
});

app.put('/api/admin/apis/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  const api = db.apis.find(a => a.id == req.params.id);
  if (api) { Object.assign(api, req.body); saveDB(db); res.json({ success: true }); }
  else res.status(404).json({ error: 'Not found' });
});

app.delete('/api/admin/apis/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  db.apis = db.apis.filter(a => a.id != req.params.id);
  saveDB(db); res.json({ success: true });
});

app.get('/api/admin/audit', requireAdmin, (req, res) => res.json(loadDB().auditLogs.slice(-200).reverse()));
app.get('/api/admin/searches', requireAdmin, (req, res) => res.json(loadDB().searches.slice(-200).reverse()));

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({
    totalUsers: db.users.length, pendingUsers: db.pendingUsers.length,
    blockedUsers: db.users.filter(u => u.blocked).length, totalSearches: db.searches.length,
    totalRevenue: db.payments.filter(p => p.status === 'approved').reduce((s,p) => s+p.amount, 0),
    pendingPayments: db.payments.filter(p => p.status === 'pending').length
  });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🔒 Server running on port ${PORT}`));
