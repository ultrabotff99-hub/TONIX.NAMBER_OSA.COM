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
        // URL-ൽ ?key=69d&q= എന്ന് കൃത്യമായി ഉണ്ടെന്ന് ഉറപ്പാക്കുക
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
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 }
}));

const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, message: { error: 'Slow down.' } });

function audit(db, action, details, req) {
  db.auditLogs.push({ id: Date.now(), action, details, ip: req.ip, user: req.session?.username || 'guest', timestamp: new Date().toISOString() });
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
app.post('/api/user/login', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });

  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  
  if (!user) {
    if (!db.pendingUsers.find(u => u.username === username)) {
      db.pendingUsers.push({ id: Date.now(), username, createdAt: new Date().toISOString() });
      saveDB(db);
    }
    return res.status(403).json({ error: '⏳ Admin approval pending. Please wait.' });
  }
  if (user.blocked) return res.status(403).json({ error: 'Account blocked by admin' });

  req.session.userId = user.id;
  req.session.username = user.username;
  saveDB(db);
  res.json({ success: true, user: { name: user.username, credits: user.credits } });
});

app.post('/api/user/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/me', requireUser, (req, res) => res.json({ name: req.user.username, credits: req.user.credits, totalSpent: req.user.totalSpent || 0 }));

// ============ SMART SEARCH ROUTE (FIXED) ============
app.post('/api/search', requireUser, apiLimiter, async (req, res) => {
  const { phone } = req.body;
  if (!/^\d{10}$/.test(phone)) return res.status(400).json({ error: 'Invalid 10-digit number' });

  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  const activeApis = db.apis.filter(a => a.active);

  const totalCost = activeApis.reduce((sum, api) => sum + (api.price || 10), 0);
  if (user.credits < totalCost) return res.status(402).json({ error: `Need ₹${totalCost} to search all APIs. Recharge first.` });

  let chargedAmount = 0;

  const fetchPromises = activeApis.map(async (api) => {
    try {
      if (api.lastReset !== today()) { api.usedToday = 0; api.lastReset = today(); }
      if (api.usedToday >= api.dailyLimit) return { apiId: api.id, name: api.name, error: 'API daily limit reached' };

      // 👇 API URL കൃത്യമായി ജോഡിച്ചെടുക്കുന്നു (ഇവിടെയാണ് പ്രധാന തിരുത്തൽ)
      const finalUrl = api.url + phone; 

      const response = await axios.get(finalUrl, { 
        timeout: 25000, // 25 സെക്കൻഡ് ടൈംഔട്ട്
        headers: { 
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'application/json, text/plain, */*'
        }
      });
      
      const data = response.data;
      
      // സ്മാർട്ട് ഡാറ്റ ചെക്കിംഗ്
      let hasData = false;
      const innerData = data.Data || data.data || data;
      
      if (innerData && Object.keys(innerData).length > 0) {
        if (innerData.data && Object.keys(innerData.data).length > 0) hasData = true;
        else if (innerData['Main≠Details']?.Details?.length > 0 || innerData['Data-2']?.Details?.length > 0 || innerData['Data-3']?.Details?.length > 0) hasData = true;
        else if (data.success === true && data.developer) hasData = true; // API-1 ഫോർമാറ്റ്
      }

      if (hasData) {
        chargedAmount += (api.price || 10);
        api.usedToday++;
        return { apiId: api.id, name: api.name, data: data };
      } else {
        return { apiId: api.id, name: api.name, error: 'No data found for this number' };
      }
    } catch (err) {
      console.error(`API ${api.name} Error:`, err.message);
      return { apiId: api.id, name: api.name, error: 'API failed or timeout (Check API URL/Server)' };
    }
  });

  const fetchResults = await Promise.all(fetchPromises);

  user.credits -= chargedAmount;
  user.totalSpent = (user.totalSpent || 0) + chargedAmount;
  db.searches.push({ id: Date.now(), userId: user.id, username: user.username, phone, cost: chargedAmount, timestamp: new Date().toISOString() });
  saveDB(db);

  res.json({ success: true, charged: chargedAmount, remainingCredits: user.credits, results: fetchResults });
});

// ============ OTHER USER & ADMIN ROUTES ============
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
  saveDB(db);
  res.json({ success: true, message: 'Submitted. Admin will verify soon.' });
});
app.get('/api/public/apis', requireUser, (req, res) => {
  const db = loadDB();
  res.json(db.apis.filter(a => a.active).map(a => ({ id: a.id, name: a.name, price: a.price })));
});

app.get('/admin', (req, res) => {
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '3007';
  if (req.query.pass === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    req.session.save((err) => { if (err) return res.status(500).send("Session error"); res.sendFile(path.join(__dirname, 'public', 'admin.html')); });
  } else { res.status(401).send(`<body style="background:#0a0e27;color:#fff;text-align:center;padding:50px;font-family:sans-serif;"><h2 style="color:#ff6b6b;">⛔ Unauthorized Access</h2></body>`); }
});
app.get('/api/admin/check', (req, res) => res.json({ isAdmin: !!req.session.isAdmin }));
app.post('/api/admin/logout', (req, res) => { req.session.isAdmin = false; res.json({ success: true }); });
app.get('/api/admin/pending', requireAdmin, (req, res) => res.json(loadDB().pendingUsers));
app.post('/api/admin/approve-user', requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.pendingUsers.findIndex(p => p.id === req.body.userId);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const p = db.pendingUsers[idx];
  db.users.push({ id: p.id, username: p.username, approved: true, blocked: false, credits: 0, totalSpent: 0, createdAt: p.createdAt });
  db.pendingUsers.splice(idx, 1); saveDB(db); res.json({ success: true });
});
app.post('/api/admin/reject-user', requireAdmin, (req, res) => {
  const db = loadDB(); db.pendingUsers = db.pendingUsers.filter(p => p.id !== req.body.userId); saveDB(db); res.json({ success: true });
});
app.get('/api/admin/users', requireAdmin, (req, res) => res.json(loadDB().users));
app.post('/api/admin/user/block', requireAdmin, (req, res) => {
  const db = loadDB(); const u = db.users.find(x => x.id === req.body.userId);
  if (u) { u.blocked = !!req.body.blocked; saveDB(db); res.json({ success: true }); } else res.status(404).json({ error: 'Not found' });
});
app.post('/api/admin/user/credits', requireAdmin, (req, res) => {
  const db = loadDB(); const u = db.users.find(x => x.id === req.body.userId);
  if (u) { u.credits += Number(req.body.delta); saveDB(db); res.json({ success: true, credits: u.credits }); } else res.status(404).json({ error: 'Not found' });
});
app.delete('/api/admin/user/:id', requireAdmin, (req, res) => {
  const db = loadDB(); db.users = db.users.filter(x => x.id != req.params.id); saveDB(db); res.json({ success: true });
});
app.get('/api/admin/payments', requireAdmin, (req, res) => res.json(loadDB().payments.sort((a,b) => b.id - a.id)));
app.post('/api/admin/payment/approve', requireAdmin, (req, res) => {
  const db = loadDB(); const p = db.payments.find(x => x.id === req.body.paymentId);
  if (p && p.status === 'pending') { const user = db.users.find(u => u.id === p.userId); if (user) user.credits += p.amount; p.status = 'approved'; saveDB(db); res.json({ success: true }); } else res.status(400).json({ error: 'Invalid' });
});
app.post('/api/admin/payment/reject', requireAdmin, (req, res) => {
  const db = loadDB(); const p = db.payments.find(x => x.id === req.body.paymentId);
  if (p && p.status === 'pending') { p.status = 'rejected'; saveDB(db); res.json({ success: true }); } else res.status(400).json({ error: 'Invalid' });
});
app.get('/api/admin/apis', requireAdmin, (req, res) => res.json(loadDB().apis));
app.post('/api/admin/apis', requireAdmin, (req, res) => {
  const db = loadDB(); db.apis.push({ id: Date.now(), name: req.body.name, url: req.body.url, price: Number(req.body.price) || 10, dailyLimit: Number(req.body.dailyLimit) || 1000, usedToday: 0, lastReset: today(), active: true }); saveDB(db); res.json({ success: true });
});
app.put('/api/admin/apis/:id', requireAdmin, (req, res) => {
  const db = loadDB(); const api = db.apis.find(a => a.id == req.params.id);
  if (api) { Object.assign(api, req.body); saveDB(db); res.json({ success: true }); } else res.status(404).json({ error: 'Not found' });
});
app.delete('/api/admin/apis/:id', requireAdmin, (req, res) => {
  const db = loadDB(); db.apis = db.apis.filter(a => a.id != req.params.id); saveDB(db); res.json({ success: true });
});
app.get('/api/admin/audit', requireAdmin, (req, res) => res.json(loadDB().auditLogs.slice(-200).reverse()));
app.get('/api/admin/searches', requireAdmin, (req, res) => res.json(loadDB().searches.slice(-200).reverse()));
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({ totalUsers: db.users.length, pendingUsers: db.pendingUsers.length, blockedUsers: db.users.filter(u => u.blocked).length, totalSearches: db.searches.length, totalRevenue: db.payments.filter(p => p.status === 'approved').reduce((s,p) => s+p.amount, 0), pendingPayments: db.payments.filter(p => p.status === 'pending').length });
});
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🔒 Server running on port ${PORT}`));
