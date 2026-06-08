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
const Database = require('better-sqlite3')

const app = express();
const PORT = process.env.PORT || 3000;

const DB_PATH = process.env.DB_PATH || './data/portal.db';
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    phone TEXT,
    whatsapp TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS buyers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    portal_token TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_visited DATETIME
  );
  CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    price TEXT,
    availability TEXT,
    agent_id INTEGER REFERENCES admins(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS buyer_properties (
    buyer_id INTEGER REFERENCES buyers(id),
    property_id INTEGER REFERENCES properties(id),
    PRIMARY KEY (buyer_id, property_id)
  );
  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER REFERENCES properties(id),
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    url TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS magic_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    buyer_id INTEGER REFERENCES buyers(id),
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    buyer_id INTEGER REFERENCES buyers(id),
    action TEXT NOT NULL,
    detail TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const adminCount = db.prepare('SELECT COUNT(*) as c FROM admins').get();
if (adminCount.c === 0) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
  db.prepare('INSERT INTO admins (username, password_hash, display_name, phone, whatsapp) VALUES (?, ?, ?, ?, ?)').run(process.env.ADMIN_USERNAME || 'admin', hash, process.env.ADMIN_DISPLAY_NAME || 'Admin User', process.env.ADMIN_PHONE || '', process.env.ADMIN_WHATSAPP || '');
  console.log('Default admin created');
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'nalu-secret', resave: false, saveUninitialized: false, cookie: { maxAge: 24*60*60*1000 } }));
app.use(express.static(path.join(__dirname, 'public')));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random()*1e9) + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 50*1024*1024 } });
app.use('/uploads', express.static(uploadsDir));

function createTransporter() {
  if (!process.env.SMTP_HOST) return null;
  return nodemailer.createTransport({ host: process.env.SMTP_HOST, port: parseInt(process.env.SMTP_PORT||'587'), secure: process.env.SMTP_SECURE==='true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
}

async function sendMagicLinkEmail(to, name, url) {
  const t = createTransporter();
  const html = '<div style="font-family:Georgia,serif;max-width:600px;margin:0 auto;background:#0a0a0a;color:#fff;padding:40px;"><h1 style="color:#c9a84c;">NALU BY MONACO</h1><p>Hi ' + name + ',</p><p>Click below to access your portal (expires 15 minutes):</p><p><a href="' + url + '" style="background:#c9a84c;color:#000;padding:14px 32px;text-decoration:none;display:inline-block;font-weight:bold;">ACCESS MY PORTAL</a></p></div>';
  if (t) { await t.sendMail({ from: process.env.SMTP_FROM||'noreply@nalubymonaco.com.au', to, subject: 'Your Nalu by Monaco Portal Access', html }); }
  else { console.log('\n=== MAGIC LINK (dev) ===\nTo:', to, '\nURL:', url, '\n========================\n'); }
}

const JWT_SECRET = process.env.JWT_SECRET || 'nalu-jwt-secret';

function adminAuth(req, res, next) {
  const token = req.session.adminToken || (req.headers.authorization||'').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = db.prepare('SELECT * FROM admins WHERE id=?').get(payload.admin_id);
    if (!req.admin) return res.status(401).json({ error: 'Admin not found' });
    next();
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
}

function genToken() { return crypto.randomBytes(32).toString('base64url'); }
function logAct(buyerId, action, detail) { db.prepare('INSERT INTO activity (buyer_id,action,detail) VALUES (?,?,?)').run(buyerId, action, detail); }

app.get('/login', (req, res) => res.sendFile(path.join(__dirname,'public','login.html')));

app.post('/api/request-link', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const buyer = db.prepare('SELECT * FROM buyers WHERE LOWER(email)=LOWER(?)').get(email.trim());
  const msg = 'If that email is registered, you will receive a link.';
  if (!buyer) return res.json({ success: true, message: msg });
  db.prepare('DELETE FROM magic_links WHERE buyer_id=? AND used=0').run(buyer.id);
  const tok = genToken();
  db.prepare('INSERT INTO magic_links (buyer_id,token,expires_at) VALUES (?,?,?)').run(buyer.id, tok, new Date(Date.now()+15*60*1000).toISOString());
  const magicUrl = req.protocol+'://'+req.get('host')+'/auth/magic/'+tok;
  try { await sendMagicLinkEmail(buyer.email,buyer.name,magicUrl); logAct(buyer.id,'magic_link_requested',buyer.email); } catch(e) { console.error(e.message); }
  res.json({ success: true, message: msg });
});

app.get('/auth/magic/:token', (req, res) => {
  const link = db.prepare('SELECT * FROM magic_links WHERE token=? AND used=0').get(req.params.token);
  if (!link || new Date(link.expires_at)<new Date()) return res.redirect('/login?error=expired');
  db.prepare('UPDATE magic_links SET used=1 WHERE id=?').run(link.id);
  db.prepare('UPDATE buyers SET last_visited=CURRENT_TIMESTAMP WHERE id=?').run(link.buyer_id);
  const buyer = db.prepare('SELECT * FROM buyers WHERE id=?').get(link.buyer_id);
  req.session.buyerId = buyer.id;
  logAct(buyer.id,'logged_in','Magic link');
  res.redirect('/portal/'+buyer.portal_token);
});

app.get('/portal/:token', (req, res) => {
    res.sendFile(path.join(__dirname,'public','portal.html'));
});

app.get('/api/portal/:token', (req, res) => {
  const buyer = db.prepare('SELECT * FROM buyers WHERE portal_token=?').get(req.params.token);
  if (!buyer) return res.status(404).json({ error:'Not found' });
  const props = db.prepare('SELECT p.*,a.display_name as agent_name,a.phone as agent_phone,a.whatsapp as agent_whatsapp FROM properties p JOIN buyer_properties bp ON bp.property_id=p.id LEFT JOIN admins a ON a.id=p.agent_id WHERE bp.buyer_id=? ORDER BY p.created_at DESC').all(buyer.id);
  res.json({ buyer:{name:buyer.name,email:buyer.email}, properties:props.map(p=>({...p,files:db.prepare('SELECT * FROM files WHERE property_id=? ORDER BY type,name').all(p.id)})) });
});

app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname,'public','admin-login.html')));

app.post('/api/admin/login', (req, res) => {
  const admin = db.prepare('SELECT * FROM admins WHERE username=?').get(req.body.username);
  if (!admin||!bcrypt.compareSync(req.body.password,admin.password_hash)) return res.status(401).json({error:'Invalid credentials'});
  const token = jwt.sign({admin_id:admin.id},JWT_SECRET,{expiresIn:'8h'});
  req.session.adminToken = token;
  res.json({success:true,token,admin:{id:admin.id,display_name:admin.display_name,username:admin.username}});
});

app.post('/api/admin/logout',(req,res)=>{req.session.destroy();res.json({success:true});});
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/api/admin/me',adminAuth,(req,res)=>{const{password_hash,...a}=req.admin;res.json(a);});

app.get('/api/admin/buyers',adminAuth,(req,res)=>res.json(db.prepare('SELECT b.*,COUNT(a.id) as activity_count FROM buyers b LEFT JOIN activity a ON a.buyer_id=b.id GROUP BY b.id ORDER BY b.created_at DESC').all()));

app.post('/api/admin/buyers',adminAuth,(req,res)=>{
  const{name,email,phone}=req.body;
  if(!name||!email)return res.status(400).json({error:'Name and email required'});
  try{const r=db.prepare('INSERT INTO buyers (name,email,phone,portal_token) VALUES (?,?,?,?)').run(name.trim(),email.trim().toLowerCase(),phone||null,genToken());res.json({success:true,buyer:db.prepare('SELECT * FROM buyers WHERE id=?').get(r.lastInsertRowid)});}
  catch(e){res.status(e.message.includes('UNIQUE')?400:500).json({error:e.message.includes('UNIQUE')?'Email already exists':e.message});}
});

app.put('/api/admin/buyers/:id',adminAuth,(req,res)=>{const{name,email,phone}=req.body;db.prepare('UPDATE buyers SET name=?,email=?,phone=? WHERE id=?').run(name,email.toLowerCase(),phone||null,req.params.id);res.json({success:true});});

app.delete('/api/admin/buyers/:id',adminAuth,(req,res)=>{
  const id=req.params.id;
  ['DELETE FROM activity WHERE buyer_id=?','DELETE FROM magic_links WHERE buyer_id=?','DELETE FROM buyer_properties WHERE buyer_id=?','DELETE FROM buyers WHERE id=?'].forEach(q=>db.prepare(q).run(id));
  res.json({success:true});
});

app.post('/api/admin/buyers/:buyerId/properties/:propertyId',adminAuth,(req,res)=>{try{db.prepare('INSERT OR IGNORE INTO buyer_properties (buyer_id,property_id) VALUES (?,?)').run(req.params.buyerId,req.params.propertyId);res.json({success:true});}catch(e){res.status(500).json({error:e.message});}});
app.delete('/api/admin/buyers/:buyerId/properties/:propertyId',adminAuth,(req,res)=>{db.prepare('DELETE FROM buyer_properties WHERE buyer_id=? AND property_id=?').run(req.params.buyerId,req.params.propertyId);res.json({success:true});});
app.get('/api/admin/buyers/:id/properties',adminAuth,(req,res)=>res.json(db.prepare('SELECT p.id FROM properties p JOIN buyer_properties bp ON bp.property_id=p.id WHERE bp.buyer_id=?').all(req.params.id).map(p=>p.id)));

app.post('/api/admin/buyers/:id/send-link',adminAuth,async(req,res)=>{
  const buyer=db.prepare('SELECT * FROM buyers WHERE id=?').get(req.params.id);
  if(!buyer)return res.status(404).json({error:'Buyer not found'});
  db.prepare('DELETE FROM magic_links WHERE buyer_id=? AND used=0').run(buyer.id);
  const tok=genToken();
  db.prepare('INSERT INTO magic_links (buyer_id,token,expires_at) VALUES (?,?,?)').run(buyer.id,tok,new Date(Date.now()+24*60*60*1000).toISOString());
  const url=req.protocol+'://'+req.get('host')+'/auth/magic/'+tok;
  try{await sendMagicLinkEmail(buyer.email,buyer.name,url);res.json({success:true,message:'Link sent',url});}
  catch(e){res.json({success:true,message:'Email failed but link generated',url});}
});

app.get('/api/admin/buyers/:id/portal-link',adminAuth,(req,res)=>{
  const b=db.prepare('SELECT portal_token FROM buyers WHERE id=?').get(req.params.id);
  if(!b)return res.status(404).json({error:'Not found'});
  res.json({url:req.protocol+'://'+req.get('host')+'/portal/'+b.portal_token,token:b.portal_token});
});

app.get('/api/admin/properties',adminAuth,(req,res)=>res.json(db.prepare('SELECT p.*,a.display_name as agent_name,(SELECT COUNT(*) FROM files f WHERE f.property_id=p.id) as file_count FROM properties p LEFT JOIN admins a ON a.id=p.agent_id ORDER BY p.created_at DESC').all()));

app.post('/api/admin/properties',adminAuth,(req,res)=>{
  const{name,address,price,availability,agent_id}=req.body;
  if(!name||!address)return res.status(400).json({error:'Name and address required'});
  const r=db.prepare('INSERT INTO properties (name,address,price,availability,agent_id) VALUES (?,?,?,?,?)').run(name,address,price||null,availability||null,agent_id||req.admin.id);
  res.json({success:true,property:db.prepare('SELECT * FROM properties WHERE id=?').get(r.lastInsertRowid)});
});

app.put('/api/admin/properties/:id',adminAuth,(req,res)=>{const{name,address,price,availability,agent_id}=req.body;db.prepare('UPDATE properties SET name=?,address=?,price=?,availability=?,agent_id=? WHERE id=?').run(name,address,price||null,availability||null,agent_id||req.admin.id,req.params.id);res.json({success:true});});

app.delete('/api/admin/properties/:id',adminAuth,(req,res)=>{
  const id=req.params.id;
  ['DELETE FROM buyer_properties WHERE property_id=?','DELETE FROM files WHERE property_id=?','DELETE FROM properties WHERE id=?'].forEach(q=>db.prepare(q).run(id));
  res.json({success:true});
});

app.get('/api/admin/properties/:id/files',adminAuth,(req,res)=>res.json(db.prepare('SELECT * FROM files WHERE property_id=? ORDER BY type,name').all(req.params.id)));

app.post('/api/admin/files',adminAuth,(req,res)=>{
  const{property_id,name,type,url}=req.body;
  if(!property_id||!name||!url)return res.status(400).json({error:'property_id, name, url required'});
  const ft=type||(url.match(/\.(jpg|jpeg|png|gif|webp)$/i)?'image':'document');
  const r=db.prepare('INSERT INTO files (property_id,name,type,url) VALUES (?,?,?,?)').run(property_id,name,ft,url);
  res.json({success:true,file:db.prepare('SELECT * FROM files WHERE id=?').get(r.lastInsertRowid)});
});

app.post('/api/admin/files/upload',adminAuth,upload.single('file'),(req,res)=>{
  if(!req.file)return res.status(400).json({error:'No file uploaded'});
  if(!req.body.property_id)return res.status(400).json({error:'property_id required'});
  const url='/uploads/'+req.file.filename;
  const ft=req.body.type||(req.file.mimetype.startsWith('image/')?'image':'document');
  const r=db.prepare('INSERT INTO files (property_id,name,type,url) VALUES (?,?,?,?)').run(req.body.property_id,req.body.name||req.file.originalname,ft,url);
  res.json({success:true,file:db.prepare('SELECT * FROM files WHERE id=?').get(r.lastInsertRowid)});
});

app.delete('/api/admin/files/:id',adminAuth,(req,res)=>{
  const f=db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if(f&&f.url.startsWith('/uploads/')){const p=path.join(__dirname,f.url);if(fs.existsSync(p))fs.unlinkSync(p);}
  db.prepare('DELETE FROM files WHERE id=?').run(req.params.id);
  res.json({success:true});
});

app.get('/api/admin/admins',adminAuth,(req,res)=>res.json(db.prepare('SELECT id,username,display_name,phone,whatsapp,created_at FROM admins').all()));

app.post('/api/admin/admins',adminAuth,(req,res)=>{
  const{username,password,display_name,phone,whatsapp}=req.body;
  if(!username||!password||!display_name)return res.status(400).json({error:'username, password, display_name required'});
  try{const r=db.prepare('INSERT INTO admins (username,password_hash,display_name,phone,whatsapp) VALUES (?,?,?,?,?)').run(username,bcrypt.hashSync(password,10),display_name,phone||null,whatsapp||null);res.json({success:true,id:r.lastInsertRowid});}
  catch(e){res.status(e.message.includes('UNIQUE')?400:500).json({error:e.message.includes('UNIQUE')?'Username exists':e.message});}
});

app.get('/api/admin/activity',adminAuth,(req,res)=>{
  const{buyer_id}=req.query;
  if(buyer_id){res.json(db.prepare('SELECT * FROM activity WHERE buyer_id=? ORDER BY created_at DESC LIMIT 100').all(buyer_id));}
  else{res.json(db.prepare('SELECT a.*,b.name as buyer_name,b.email as buyer_email FROM activity a JOIN buyers b ON b.id=a.buyer_id ORDER BY a.created_at DESC LIMIT 200').all());}
});

app.get('/',(req,res)=>res.sendFile(path.join(__dirname,'public','portal.html')));
app.use((req,res)=>res.status(404).sendFile(path.join(__dirname,'public','404.html')));
app.listen(PORT,()=>console.log('Nalu Buyer Portal running on port '+PORT));
