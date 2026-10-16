require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
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
      loginAttempts: {},
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
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 2 * 60 * 60 * 1000,  // 2 hours
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
}));

// Rate limiters
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: { error: 'Too many attempts. Wait 15 minutes.' }
});
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: 'Too many registrations from this IP.' }
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Slow down. Max 20 requests/min.' }
});

// Audit logger
function audit(db, action, details, req) {
  db.auditLogs.push({
    id: Date.now(),
    action, details,
    ip: req.ip || req.connection.remoteAddress,
    ua: req.headers['user-agent'] || '',
    user: req.session?.email || req.session?.userId || 'guest',
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
  if (!u.approved) return res.status(403).json({ error: 'Account pending admin approval' });
  req.user = u;
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.status(401).json({ error: 'Admin only' });
  next();
}

// ============ PUBLIC: Register with invite code ============
app.post('/api/register', registerLimiter, async (req, res) => {
  const { name, email, phone, password, inviteCode, purpose } = req.body;
  if (!name || !email || !password || !inviteCode)
    return res.status(400).json({ error: 'All fields required' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password min 8 characters' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Invalid email' });

  // Validate invite code
  const validCodes = (process.env.INVITE_CODES || '').split(',').map(c => c.trim());
  if (!validCodes.includes(inviteCode.toUpperCase()))
    return res.status(403).json({ error: 'Invalid invite code. Contact admin.' });

  const db = loadDB();
  if (db.users.find(u => u.email === email) || db.pendingUsers.find(u => u.email === email))
    return res.status(400).json({ error: 'Email already registered' });

  const pending = {
    id: Date.now(),
    name, email,
    phone: phone || '',
    purpose: purpose || 'Research',
    password: await bcrypt.hash(password, 10),
    inviteCode: inviteCode.toUpperCase(),
    createdAt: new Date().toISOString(),
    approved: false,
    blocked: false
  };
  db.pendingUsers.push(pending);
  audit(db, 'REGISTER_REQUEST', { email, inviteCode }, req);
  saveDB(db);

  res.json({ success: true, message: 'Registration submitted. Wait for admin approval.' });
});

// ============ PUBLIC: Login ============
app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const db = loadDB();

  // Check pending
  const pendingUser = db.pendingUsers.find(u => u.email === email);
  if (pendingUser) return res.status(403).json({ error: '⏳ Awaiting admin approval' });

  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  if (user.blocked) return res.status(403).json({ error: 'Account blocked by admin' });
  if (!(await bcrypt.compare(password, user.password)))
    return res.status(400).json({ error: 'Invalid credentials' });

  req.session.userId = user.id;
  req.session.email = user.email;
  user.lastLogin = new Date().toISOString();
  user.lastIP = req.ip;
  audit(db, 'LOGIN', { email }, req);
  saveDB(db);

  res.json({
    success: true,
    user: {
      name: user.name, email: user.email,
      credits: user.credits, role: user.role || 'analyst'
    }
  });
});

app.post('/api/logout', (req, res) => {
  const db = loadDB();
  audit(db, 'LOGOUT', {}, req);
  saveDB(db);
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', requireUser, (req, res) => {
  const u = req.user;
  res.json({
    name: u.name, email: u.email, credits: u.credits,
    totalSpent: u.totalSpent || 0, role: u.role || 'analyst',
    lastLogin: u.lastLogin
  });
});

// ============ SEARCH (deduct credit + call API) ============
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
  if (api.usedToday >= api.dailyLimit)
    return res.status(429).json({ error: 'API daily limit reached' });

  try {
    const response = await axios.get(api.url + phone, { timeout: 20000 });
    user.credits -= cost;
    user.totalSpent = (user.totalSpent || 0) + cost;
    api.usedToday++;

    db.searches.push({
      id: Date.now(), userId: user.id, userEmail: user.email,
      phone, apiId: api.id, apiName: api.name, cost,
      timestamp: new Date().toISOString()
    });
    audit(db, 'SEARCH', { phone, apiId, cost }, req);
    saveDB(db);

    res.json({
      success: true, charged: cost,
      remainingCredits: user.credits, data: response.data
    });
  } catch (err) {
    res.status(500).json({ error: 'API fetch failed' });
  }
});

// ============ UPI / QR ============
app.get('/api/public/upi', (req, res) => {
  res.json({ upiId: UPI_CONFIG.upiId, payeeName: UPI_CONFIG.payeeName });
});

app.post('/api/public/genqr', requireUser, (req, res) => {
  const amt = Number(req.body.amount);
  if (!amt || amt < 10) return res.status(400).json({ error: 'Minimum ₹10' });

  const txnRef = 'TXN' + Date.now();
  const upiLink = `upi://pay?pa=${encodeURIComponent(UPI_CONFIG.upiId)}` +
                  `&pn=${encodeURIComponent(UPI_CONFIG.payeeName)}` +
                  `&am=${amt}&cu=INR&tn=${encodeURIComponent('Recharge ' + txnRef)}&tr=${txnRef}`;
  const qrImage = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(upiLink)}`;

  res.json({ success: true, upiLink, qrImage, txnRef, amount: amt, upiId: UPI_CONFIG.upiId });
});

app.post('/api/recharge', requireUser, (req, res) => {
  const { amount, txnId, txnRef } = req.body;
  const amt = Number(amount);
  if (!amt || amt < 10) return res.status(400).json({ error: 'Minimum ₹10' });
  if (!txnId || txnId.length < 6) return res.status(400).json({ error: 'Invalid Txn ID' });

  const db = loadDB();
  if (db.payments.find(p => p.txnId === txnId))
    return res.status(400).json({ error: 'Txn ID already submitted' });

  db.payments.push({
    id: Date.now(),
    userId: req.user.id, userEmail: req.user.email, userName: req.user.name,
    amount: amt, method: 'upi', txnId, txnRef: txnRef || '',
    status: 'pending', timestamp: new Date().toISOString(), verifiedAt: null
  });
  audit(db, 'PAYMENT_REQUEST', { amount: amt, txnId }, req);
  saveDB(db);
  res.json({ success: true, message: 'Submitted. Admin will verify soon.' });
});

app.get('/api/my-payments', requireUser, (req, res) => {
  const db = loadDB();
  res.json(db.payments.filter(p => p.userId === req.user.id).reverse());
});

// ============ PUBLIC: APIs list ============
app.get('/api/public/apis', requireUser, (req, res) => {
  const db = loadDB();
  res.json(db.apis.map(a => ({ id: a.id, name: a.name, price: a.price, active: a.active })));
});

// ============ ADMIN LOGIN ============
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    const db = loadDB();
    audit(db, 'ADMIN_LOGIN_FAIL', { email }, req);
    saveDB(db);
    return res.status(401).json({ error: 'Invalid admin credentials' });
  }
  req.session.isAdmin = true;
  req.session.adminEmail = email;
  const db = loadDB();
  audit(db, 'ADMIN_LOGIN', { email }, req);
  saveDB(db);
  res.json({ success: true });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  res.json({ success: true });
});

app.get('/api/admin/check', (req, res) => {
  res.json({ isAdmin: !!req.session.isAdmin });
});

// ============ ADMIN: Pending users ============
app.get('/api/admin/pending', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.pendingUsers.map(p => ({
    id: p.id, name: p.name, email: p.email,
    phone: p.phone, purpose: p.purpose,
    inviteCode: p.inviteCode, createdAt: p.createdAt
  })));
});

app.post('/api/admin/approve-user', requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.pendingUsers.findIndex(p => p.id === req.body.userId);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const p = db.pendingUsers[idx];
  db.users.push({
    id: p.id, name: p.name, email: p.email, phone: p.phone,
    password: p.password, credits: 0, totalSpent: 0,
    role: 'analyst', approved: true, blocked: false,
    createdAt: p.createdAt, approvedAt: new Date().toISOString(),
    approvedBy: req.session.adminEmail
  });
  db.pendingUsers.splice(idx, 1);
  audit(db, 'USER_APPROVED', { email: p.email }, req);
  saveDB(db);
  res.json({ success: true });
});

app.post('/api/admin/reject-user', requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.pendingUsers.findIndex(p => p.id === req.body.userId);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const email = db.pendingUsers[idx].email;
  db.pendingUsers.splice(idx, 1);
  audit(db, 'USER_REJECTED', { email }, req);
  saveDB(db);
  res.json({ success: true });
});

// ============ ADMIN: Users management ============
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.users.map(u => ({
    id: u.id, name: u.name, email: u.email, phone: u.phone,
    credits: u.credits, blocked: u.blocked, role: u.role,
    totalSpent: u.totalSpent, createdAt: u.createdAt, lastLogin: u.lastLogin
  })));
});

app.post('/api/admin/user/block', requireAdmin, (req, res) => {
  const db = loadDB();
  const u = db.users.find(x => x.id === req.body.userId);
  if (!u) return res.status(404).json({ error: 'Not found' });
  u.blocked = !!req.body.blocked;
  audit(db, u.blocked ? 'USER_BLOCKED' : 'USER_UNBLOCKED', { email: u.email }, req);
  saveDB(db);
  res.json({ success: true });
});

app.post('/api/admin/user/credits', requireAdmin, (req, res) => {
  const db = loadDB();
  const u = db.users.find(x => x.id === req.body.userId);
  if (!u) return res.status(404).json({ error: 'Not found' });
  u.credits += Number(req.body.delta || 0);
  audit(db, 'CREDIT_ADJUST', { email: u.email, delta: req.body.delta, newBalance: u.credits }, req);
  saveDB(db);
  res.json({ success: true, credits: u.credits });
});

app.delete('/api/admin/user/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  const u = db.users.find(x => x.id == req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  db.users = db.users.filter(x => x.id != req.params.id);
  audit(db, 'USER_DELETED', { email: u.email }, req);
  saveDB(db);
  res.json({ success: true });
});

// ============ ADMIN: APIs CRUD ============
app.get('/api/admin/apis', requireAdmin, (req, res) => {
  res.json(loadDB().apis);
});

app.post('/api/admin/apis', requireAdmin, (req, res) => {
  const db = loadDB();
  const { name, url, price, dailyLimit, active } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });
  const api = {
    id: Date.now(), name, url,
    price: Number(price) || 10,
    dailyLimit: Number(dailyLimit) || 1000,
    usedToday: 0, lastReset: today(),
    active: active !== false
  };
  db.apis.push(api);
  audit(db, 'API_ADDED', { name, url }, req);
  saveDB(db);
  res.json({ success: true, api });
});

app.put('/api/admin/apis/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  const api = db.apis.find(a => a.id == req.params.id);
  if (!api) return res.status(404).json({ error: 'Not found' });
  Object.assign(api, {
    name: req.body.name ?? api.name,
    url: req.body.url ?? api.url,
    price: req.body.price ?? api.price,
    dailyLimit: req.body.dailyLimit ?? api.dailyLimit,
    active: req.body.active ?? api.active
  });
  audit(db, 'API_UPDATED', { id: api.id }, req);
  saveDB(db);
  res.json({ success: true, api });
});

app.delete('/api/admin/apis/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  db.apis = db.apis.filter(a => a.id != req.params.id);
  audit(db, 'API_DELETED', { id: req.params.id }, req);
  saveDB(db);
  res.json({ success: true });
});

// ============ ADMIN: Payments ============
app.get('/api/admin/payments', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.payments.sort((a,b) => b.id - a.id));
});

app.post('/api/admin/payment/approve', requireAdmin, (req, res) => {
  const db = loadDB();
  const p = db.payments.find(x => x.id === req.body.paymentId);
  if (!p) return res.status(404).json({ error: 'Not found' });
  if (p.status !== 'pending') return res.status(400).json({ error: 'Already processed' });
  const user = db.users.find(u => u.id === p.userId);
  if (!user) return res.status(404).json({ error: 'User gone' });
  user.credits += p.amount;
  p.status = 'approved';
  p.verifiedAt = new Date().toISOString();
  audit(db, 'PAYMENT_APPROVED', { txnId: p.txnId, amount: p.amount, user: user.email }, req);
  saveDB(db);
  res.json({ success: true, credits: user.credits });
});

app.post('/api/admin/payment/reject', requireAdmin, (req, res) => {
  const db = loadDB();
  const p = db.payments.find(x => x.id === req.body.paymentId);
  if (!p) return res.status(404).json({ error: 'Not found' });
  if (p.status !== 'pending') return res.status(400).json({ error: 'Already processed' });
  p.status = 'rejected';
  p.rejectReason = req.body.reason || 'Invalid Txn ID';
  p.verifiedAt = new Date().toISOString();
  audit(db, 'PAYMENT_REJECTED', { txnId: p.txnId, reason: p.rejectReason }, req);
  saveDB(db);
  res.json({ success: true });
});

// ============ ADMIN: Audit logs ============
app.get('/api/admin/audit', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.auditLogs.slice(-300).reverse());
});

app.get('/api/admin/searches', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.searches.slice(-200).reverse());
});

// ============ ADMIN: Stats ============
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const db = loadDB();
  const revenue = db.payments.filter(p => p.status === 'approved').reduce((s,p) => s+p.amount, 0);
  res.json({
    totalUsers: db.users.length,
    pendingUsers: db.pendingUsers.length,
    blockedUsers: db.users.filter(u => u.blocked).length,
    totalSearches: db.searches.length,
    totalRevenue: revenue,
    pendingPayments: db.payments.filter(p => p.status === 'pending').length
  });
});

// ============ Fallback ============
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🔒 Private Cyber Tool running on port ${PORT}`));
