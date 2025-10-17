import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'better-sqlite3-session-store';
import bodyParser from 'body-parser';
import morgan from 'morgan';
import helmet from 'helmet';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import nodemailer from 'nodemailer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Security & logging
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(morgan('dev'));

// Body parsing (increase limits for editor)
app.use(bodyParser.urlencoded({ extended: true, limit: '2mb' }));
app.use(bodyParser.json({ limit: '2mb' }));

// DB setup
const dbPath = path.join(__dirname, 'data', 'app.db');
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const db = new Database(dbPath);

// Create tables
// submissions: id, name, phone, email, services (csv), message, customer_number, submission_date, created_at
// visits: id, ip, ua, path, ts
// admins: username, password (plain for demo; do NOT use in prod)
db.exec(`
CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  phone TEXT,
  email TEXT,
  services TEXT,
  message TEXT,
  customer_number TEXT,
  submission_date TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT,
  ua TEXT,
  path TEXT,
  ts TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS admins (
  username TEXT PRIMARY KEY,
  password TEXT NOT NULL
);
`);

// Seed admin user with provided password
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'erfan9028@';
const adminStmt = db.prepare('INSERT OR REPLACE INTO admins (username, password) VALUES (?, ?)');
adminStmt.run(ADMIN_USERNAME, ADMIN_PASSWORD);

// Session store
const SQLiteStore = SQLiteStoreFactory(session);
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change_this_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 4 },
    store: new SQLiteStore({
      client: db,
      expired: { clear: true, intervalMs: 900000 },
      table: 'sessions'
    }),
  })
);

// Email transporter (optional - configure via env)
const smtpHost = process.env.SMTP_HOST;
const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
const smtpSecure = (process.env.SMTP_SECURE || 'false') === 'true';
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const CONTACT_TO = process.env.CONTACT_TO || process.env.SMTP_TO || '';

let mailer = null;
if (smtpHost && smtpUser && smtpPass) {
  mailer = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: { user: smtpUser, pass: smtpPass },
  });
  // Verify in background
  mailer.verify().then(() => {
    console.log('SMTP ready');
  }).catch((e) => {
    console.warn('SMTP verify failed:', e.message);
  });
}

// Track visits middleware (before static to capture / requests)
app.use((req, res, next) => {
  if (req.path.startsWith('/admin') || req.path.startsWith('/api')) return next();
  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0] || req.socket.remoteAddress || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';
  const pathStr = req.path || '/';
  db.prepare('INSERT INTO visits (ip, ua, path) VALUES (?, ?, ?)').run(ip, ua, pathStr);
  next();
});

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Views (simple server-side templates)
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Auth helpers
function requireAuth(req, res, next) {
  if (req.session?.user === ADMIN_USERNAME) return next();
  return res.redirect('/admin/login');
}

// Admin routes
app.get('/admin/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  const row = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
  if (row && row.password === password) {
    req.session.user = ADMIN_USERNAME;
    return res.redirect('/admin');
  }
  return res.status(401).render('login', { error: 'نام کاربری یا رمز عبور نادرست است' });
});

app.post('/admin/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.redirect('/admin/login');
  });
});

app.get('/admin', requireAuth, (req, res) => {
  const totalVisits = db.prepare('SELECT COUNT(*) as c FROM visits').get().c;
  const todayVisits = db.prepare("SELECT COUNT(*) as c FROM visits WHERE date(ts)=date('now')").get().c;
  const totalSubmissions = db.prepare('SELECT COUNT(*) as c FROM submissions').get().c;
  const last10 = db.prepare('SELECT * FROM submissions ORDER BY id DESC LIMIT 10').all();
  res.render('dashboard', { totalVisits, todayVisits, totalSubmissions, last10 });
});

app.get('/admin/submissions', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM submissions ORDER BY id DESC').all();
  res.render('submissions', { rows });
});

app.get('/admin/visits', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM visits ORDER BY id DESC LIMIT 1000').all();
  res.render('visits', { rows });
});

// Simple site editor: edit public/landing.html
app.get('/admin/editor', requireAuth, (req, res) => {
  const filePath = path.join(__dirname, 'public', 'landing.html');
  let content = '';
  try { content = fs.readFileSync(filePath, 'utf8'); } catch (e) {}
  res.render('editor', { content });
});

app.post('/admin/editor', requireAuth, (req, res) => {
  const { content } = req.body;
  const filePath = path.join(__dirname, 'public', 'landing.html');
  fs.writeFileSync(filePath, content, 'utf8');
  res.redirect('/admin/editor');
});

// API: form submission endpoint (replaces FormSubmit)
app.post('/api/submit', (req, res) => {
  const { name, phone, email, message } = req.body;
  // services can be multiple; support array or comma-separated
  let services = req.body.services || [];
  if (typeof services === 'string') {
    services = [services];
  }
  const servicesCsv = services.join(', ');

  const customerNumber = 'JN' + Date.now().toString().slice(-6);
  const submissionDate = new Date().toLocaleString('fa-IR');

  db.prepare(`INSERT INTO submissions (name, phone, email, services, message, customer_number, submission_date) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(name || '', phone || '', email || '', servicesCsv, message || '', customerNumber, submissionDate);

  // send notification email asynchronously (if configured)
  try {
    if (mailer && CONTACT_TO) {
      const fromAddr = process.env.SMTP_FROM || smtpUser;
      const subject = `New contact (#${customerNumber}) - ${name || ''}`.trim();
      const text = `Name: ${name || ''}\nPhone: ${phone || ''}\nEmail: ${email || ''}\nServices: ${servicesCsv || '-'}\nMessage:\n${message || ''}\n\nCustomer No: ${customerNumber}\nDate: ${submissionDate}`;
      const html = `
        <h3>New Contact</h3>
        <p><strong>Name:</strong> ${name || ''}</p>
        <p><strong>Phone:</strong> ${phone || ''}</p>
        <p><strong>Email:</strong> ${email || ''}</p>
        <p><strong>Services:</strong> ${servicesCsv || '-'}</p>
        <p><strong>Message:</strong><br>${(message || '').replace(/\n/g, '<br>')}</p>
        <hr>
        <p>Customer No: <strong>${customerNumber}</strong></p>
        <p>Date: ${submissionDate}</p>
      `;
      // Fire and forget
      mailer.sendMail({ from: fromAddr, to: CONTACT_TO, subject, text, html }).catch((e) => {
        console.warn('Email send failed:', e.message);
      });
    }
  } catch (e) {
    console.warn('Email error:', e.message);
  }

  res.json({ ok: true, customerNumber, submissionDate });
});

// API: stats
app.get('/api/stats', requireAuth, (req, res) => {
  const byDay = db.prepare("SELECT date(ts) as day, COUNT(*) as visits FROM visits GROUP BY date(ts) ORDER BY day DESC LIMIT 30").all();
  const byPath = db.prepare('SELECT path, COUNT(*) as visits FROM visits GROUP BY path ORDER BY visits DESC').all();
  const today = db.prepare("SELECT COUNT(*) as c FROM visits WHERE date(ts)=date('now')").get().c;
  const total = db.prepare('SELECT COUNT(*) as c FROM visits').get().c;
  res.json({ total, today, byDay, byPath });
});

// Fallback to index.html for root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
