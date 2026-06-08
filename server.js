require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

const DB_PATH = process.env.DB_PATH || './data/portal.db';
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// DB Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS buyers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    portal_token TEXT UNIQUE NOT NULL,
    last_visited DATETIME,
    visit_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT DEFAULT 'Residential',
    address TEXT,
    unit_type TEXT,
    level TEXT,
    residence TEXT,
    aspect TEXT,
    beds TEXT,
    baths TEXT,
    cars TEXT,
    sqm TEXT,
    render_url TEXT,
    thumbnail_url TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS buyer_properties (
    buyer_id INTEGER,
    property_id INTEGER,
    PRIMARY KEY (buyer_id, property_id),
    FOREIGN KEY (buyer_id) REFERENCES buyers(id) ON DELETE CASCADE,
    FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER,
    name TEXT NOT NULL,
    file_type TEXT DEFAULT 'document',
    file_url TEXT,
    file_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    buyer_id INTEGER,
    action TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
  CREATE TABLE IF NOT EXISTS magic_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    buyer_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (buyer_id) REFERENCES buyers(id) ON DELETE CASCADE
  );
`);

// Seed default admin
const adminExists = db.prepare('SELECT id FROM admins LIMIT 1').get();
if (!adminExists) {
  const pass = process.env.ADMIN_PASSWORD || 'admin123';
  const hash = bcrypt.hashSync(pass, 10);
  const name = process.env.ADMIN_DISPLAY_NAME || 'Admin';
  db.prepare('INSERT INTO admins (username, password, display_name) VALUES (?,?,?)').run('admin', hash, name);
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'nalu-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// File uploads
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const upload = multer({ dest: uploadsDir, limits: { fileSize: 50 * 1024 * 1024 } });

// JWT helper
const JWT_SECRET = process.env.JWT_SECRET || 'nalu-jwt-2024';
function signAdminToken(admin) { return jwt.sign({ admin_id: admin.id }, JWT_SECRET, { expiresIn: '8h' }); }
function verifyAdminToken(req) {
  const auth = req.headers.authorization;
  const token = (auth && auth.startsWith('Bearer ')) ? auth.slice(7) : req.session.adminToken;
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function requireAdmin(req, res, next) {
  const payload = verifyAdminToken(req);
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  req.adminId = payload.admin_id;
  next();
}

// Email
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

async function sendMagicLink(email, name, link) {
  if (!process.env.SMTP_USER) { console.log('Magic link:', link); return; }
  await transporter.sendMail({
    from: process.env.SMTP_FROM || 'noreply@nalubymonaco.com.au',
    to: email,
    subject: 'Your Nalu by Monaco Portal Access',
    html: '<div style="font-family:Georgia,serif;max-width:500px;margin:0 auto;padding:40px 20px;background:#DFDACB"><h2 style="font-size:24px;font-weight:400;letter-spacing:4px;text-transform:uppercase;color:#282828;margin-bottom:8px">NALU BY MONACO</h2><p style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#7A7A7A;margin-bottom:32px">BUYER PORTAL</p><p style="font-size:15px;color:#282828;margin-bottom:8px">Dear ' + name + ',</p><p style="font-size:14px;color:#3D3D3D;line-height:1.6;margin-bottom:32px">Your secure access link is ready. This link expires in 24 hours.</p><a href="' + link + '" style="display:inline-block;background:#282828;color:#DFDACB;padding:14px 32px;text-decoration:none;font-size:11px;letter-spacing:3px;text-transform:uppercase;border-radius:2px">Access My Portal</a><p style="font-size:11px;color:#A8A8A8;margin-top:32px">buyers.nalubymonaco.com.au</p></div>'
  });
}

// ===== PAGE ROUTES =====
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-login.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/portal/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'portal.html')));

// ===== AUTH ROUTES =====
app.post('/api/request-access', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const buyer = db.prepare('SELECT * FROM buyers WHERE LOWER(email) = LOWER(?)').get(email);
  if (!buyer) return res.status(404).json({ error: 'Email not registered. Please contact your agent.' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO magic_links (buyer_id, token, expires_at) VALUES (?,?,?)').run(buyer.id, token, expires);
  const link = (process.env.SITE_URL || ('http://localhost:' + PORT)) + '/portal/' + buyer.portal_token + '?t=' + token;
  try {
    await sendMagicLink(buyer.email, buyer.name, link);
    res.json({ message: 'Access link sent to ' + buyer.email });
  } catch (e) {
    console.error('Email error:', e.message);
    res.json({ message: 'Access link sent to ' + buyer.email });
  }
});

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
  if (!admin || !bcrypt.compareSync(password, admin.password)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signAdminToken(admin);
  req.session.adminToken = token;
  res.json({ success: true, token, admin: { id: admin.id, display_name: admin.display_name, username: admin.username } });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// ===== PORTAL API =====
app.get('/api/portal/:token', (req, res) => {
  const buyer = db.prepare('SELECT * FROM buyers WHERE portal_token = ?').get(req.params.token);
  if (!buyer) return res.status(404).json({ error: 'Portal not found' });
  const queryToken = req.query.t;
  if (queryToken) {
    const ml = db.prepare('SELECT * FROM magic_links WHERE token = ? AND buyer_id = ? AND used = 0 AND expires_at > datetime("now")').get(queryToken, buyer.id);
    if (ml) db.prepare('UPDATE magic_links SET used = 1 WHERE id = ?').run(ml.id);
  }
  db.prepare('UPDATE buyers SET last_visited = CURRENT_TIMESTAMP, visit_count = visit_count + 1 WHERE id = ?').run(buyer.id);
  db.prepare('INSERT INTO activity (buyer_id, action) VALUES (?, ?)').run(buyer.id, 'portal_view');
  const properties = db.prepare('SELECT p.* FROM properties p INNER JOIN buyer_properties bp ON p.id = bp.property_id WHERE bp.buyer_id = ?').all(buyer.id);
  const propertiesWithFiles = properties.map(p => {
    const files = db.prepare('SELECT * FROM files WHERE property_id = ?').all(p.id);
    return { ...p, files };
  });
  const agentSettings = {};
  const settingRows = db.prepare('SELECT key, value FROM settings WHERE key LIKE ?').all('agent_%');
  settingRows.forEach(r => { agentSettings[r.key.replace('agent_', '')] = r.value; });
  res.json({ buyer, properties: propertiesWithFiles, agent: agentSettings });
});

// ===== ADMIN BUYERS =====
app.get('/api/admin/buyers', requireAdmin, (req, res) => {
  const buyers = db.prepare('SELECT b.*, (SELECT COUNT(*) FROM buyer_properties bp WHERE bp.buyer_id = b.id) as property_count FROM buyers b ORDER BY b.created_at DESC').all();
  res.json(buyers);
});

app.post('/api/admin/buyers', requireAdmin, (req, res) => {
  const { name, email, property_ids } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required' });
  const existing = db.prepare('SELECT id FROM buyers WHERE LOWER(email) = LOWER(?)').get(email);
  if (existing) return res.status(409).json({ error: 'Email already registered' });
  const token = crypto.randomBytes(32).toString('hex');
  const result = db.prepare('INSERT INTO buyers (name, email, portal_token) VALUES (?,?,?)').run(name, email, token);
  if (property_ids && property_ids.length) {
    const insert = db.prepare('INSERT OR IGNORE INTO buyer_properties (buyer_id, property_id) VALUES (?,?)');
    property_ids.forEach(pid => insert.run(result.lastInsertRowid, pid));
  }
  res.json({ id: result.lastInsertRowid, portal_token: token });
});

app.delete('/api/admin/buyers/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM buyers WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ===== ADMIN PROPERTIES =====
app.get('/api/admin/properties', requireAdmin, (req, res) => {
  const props = db.prepare('SELECT p.*, (SELECT COUNT(*) FROM buyer_properties bp WHERE bp.property_id = p.id) as buyer_count FROM properties p ORDER BY p.created_at DESC').all();
  res.json(props);
});

app.post('/api/admin/properties', requireAdmin, (req, res) => {
  const { name, type, address, unit_type, level, residence, aspect, beds, baths, cars, sqm, render_url, thumbnail_url, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const result = db.prepare('INSERT INTO properties (name,type,address,unit_type,level,residence,aspect,beds,baths,cars,sqm,render_url,thumbnail_url,description) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(name,type||'Residential',address||'',unit_type||'',level||'',residence||'',aspect||'',beds||'',baths||'',cars||'',sqm||'',render_url||'',thumbnail_url||'',description||'');
  res.json({ id: result.lastInsertRowid });
});

app.delete('/api/admin/properties/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM properties WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ===== ADMIN FILES =====
app.get('/api/admin/files', requireAdmin, (req, res) => {
  const files = db.prepare('SELECT f.*, p.name as property_name FROM files f LEFT JOIN properties p ON f.property_id = p.id ORDER BY f.created_at DESC').all();
  res.json(files);
});

app.post('/api/admin/files', requireAdmin, (req, res) => {
  const { property_id, name, file_type, file_url } = req.body;
  if (!property_id || !name) return res.status(400).json({ error: 'Property and name required' });
  const result = db.prepare('INSERT INTO files (property_id,name,file_type,file_url) VALUES (?,?,?,?)').run(property_id, name, file_type||'document', file_url||'');
  res.json({ id: result.lastInsertRowid });
});

app.post('/api/admin/files/upload', requireAdmin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const { property_id, name, file_type } = req.body;
  const fileUrl = '/uploads/' + req.file.filename;
  const result = db.prepare('INSERT INTO files (property_id,name,file_type,file_path,file_url) VALUES (?,?,?,?,?)').run(property_id, name||req.file.originalname, file_type||'document', req.file.path, fileUrl);
  res.json({ id: result.lastInsertRowid, file_url: fileUrl });
});

app.delete('/api/admin/files/:id', requireAdmin, (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (file && file.file_path) { try { fs.unlinkSync(file.file_path); } catch {} }
  db.prepare('DELETE FROM files WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ===== ACTIVITY =====
app.get('/api/admin/activity', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT a.*, b.name as buyer_name FROM activity a LEFT JOIN buyers b ON a.buyer_id = b.id ORDER BY a.created_at DESC LIMIT 100').all();
  res.json(rows);
});

// ===== ADMIN SEND LINK =====
app.post('/api/admin/send-link', requireAdmin, async (req, res) => {
  const { buyer_id } = req.body;
  const buyer = db.prepare('SELECT * FROM buyers WHERE id = ?').get(buyer_id);
  if (!buyer) return res.status(404).json({ error: 'Buyer not found' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO magic_links (buyer_id, token, expires_at) VALUES (?,?,?)').run(buyer.id, token, expires);
  const link = (process.env.SITE_URL || ('http://localhost:' + PORT)) + '/portal/' + buyer.portal_token + '?t=' + token;
  try {
    await sendMagicLink(buyer.email, buyer.name, link);
    res.json({ success: true, message: 'Link sent to ' + buyer.email });
  } catch (e) {
    res.status(500).json({ error: 'Failed to send email: ' + e.message });
  }
});

// ===== SETTINGS =====
app.post('/api/admin/settings/agent', requireAdmin, (req, res) => {
  const fields = ['name','title','phone','whatsapp','email','photo_url'];
  const upsert = db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
  fields.forEach(f => { if (req.body[f] !== undefined) upsert.run('agent_' + f, req.body[f]); });
  res.json({ success: true });
});

app.post('/api/admin/admins', requireAdmin, (req, res) => {
  const { username, password, display_name } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const exists = db.prepare('SELECT id FROM admins WHERE username = ?').get(username);
  if (exists) return res.status(409).json({ error: 'Username taken' });
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO admins (username,password,display_name) VALUES (?,?,?)').run(username, hash, display_name||username);
  res.json({ id: result.lastInsertRowid });
});

// Uploads static
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Preview route - serves design preview without auth
app.get('/preview', (req, res) => res.sendFile(path.join(__dirname, 'public', 'preview.html')));
app.get('/preview.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'preview.html')));

// 404
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', '404.html')));

app.listen(PORT, () => console.log('Nalu Buyer Portal running on port ' + PORT));
