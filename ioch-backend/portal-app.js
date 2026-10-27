require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const PARTNER_COST = 20000;
const STAFF_ROLES = ['Sales', 'Tutor', 'Accountant', 'Admin'];
const UPLOAD_VIEW_ROLES = ['SuperAdmin', 'Admin', 'Tutor', 'Accountant'];

// ================= SECURITY CONFIG =================
let SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
    console.warn('⚠️  SESSION_SECRET set nahi hai. Random secret use ho raha hai. .env mein SESSION_SECRET zaroor lagayein.');
}
if (!process.env.ADMIN_PASSWORD) {
    console.warn('⚠️  ADMIN_PASSWORD set nahi hai. Naya Super Admin "admin123" password se banega - foran badal dein.');
}

// ================= UPLOADS =================
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const ALLOWED_EXT = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.doc', '.docx', '.csv', '.txt'];
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + crypto.randomBytes(6).toString('hex') + path.extname(file.originalname).toLowerCase())
});
const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ok = ALLOWED_EXT.includes(path.extname(file.originalname).toLowerCase());
        cb(ok ? null : new Error('File type not allowed'), ok);
    }
});

// ================= MIDDLEWARE =================
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 8,
        secure: process.env.NODE_ENV === 'production'
    }
}));

// Uploads protected
app.use('/uploads', async (req, res, next) => {
    const u = req.session.user;
    if (!u) return res.status(403).send('Access Denied');
    if (UPLOAD_VIEW_ROLES.includes(u.role)) return next();
    if (u.role !== 'Student') return res.status(403).send('Access Denied');
    try {
        const name = path.basename(decodeURIComponent(req.path));
        const st = await dbGet("SELECT photo FROM students WHERE id = ?", [u.id]);
        const cfg = await getSettings();
        if ((st && st.photo === name) || Object.values(cfg).includes(name)) return next();
    } catch (e) { /* fall through */ }
    res.status(403).send('Access Denied');
}, express.static(uploadDir));
app.use(express.static(path.join(__dirname, 'public')));

// ================= LOGIN RATE LIMIT =================
const LOGIN_MAX = 10, LOGIN_WINDOW = 15 * 60 * 1000;
const loginAttempts = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of loginAttempts) if (v.reset < now) loginAttempts.delete(k); }, 10 * 60 * 1000).unref();
function loginLimiter(req, res, next) {
    const key = req.ip || 'unknown';
    const now = Date.now();
    let e = loginAttempts.get(key);
    if (!e || e.reset < now) { e = { count: 0, reset: now + LOGIN_WINDOW }; loginAttempts.set(key, e); }
    if (e.count >= LOGIN_MAX) return res.status(429).send("<h3 style='text-align:center; margin-top:50px; color:#b91c1c;'>Bohat zyada login attempts. 15 minute baad dobara koshish karein.</h3>");
    e.count++;
    next();
}
const clearLoginAttempts = req => loginAttempts.delete(req.ip || 'unknown');
const startSession = (req, data) => new Promise((resolve, reject) => {
    req.session.regenerate(err => {
        if (err) return reject(err);
        Object.assign(req.session, data);
        resolve();
    });
});

// ================= DB =================
const db = new sqlite3.Database(path.join(__dirname, 'crm.db'));
const dbGet = (sql, p = []) => new Promise((res, rej) => db.get(sql, p, (e, r) => e ? rej(e) : res(r)));
const dbAll = (sql, p = []) => new Promise((res, rej) => db.all(sql, p, (e, r) => e ? rej(e) : res(r)));
const dbRun = (sql, p = []) => new Promise((res, rej) => db.run(sql, p, function (e) { e ? rej(e) : res(this); }));

db.serialize(() => {
db.run(`ALTER TABLE students ADD COLUMN is_validated INTEGER DEFAULT 0`, () => { });
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, official_whatsapp TEXT,
        personal_phone TEXT, cnic TEXT, cnic_front TEXT, cnic_back TEXT, agreement_doc TEXT,
        username TEXT UNIQUE, password TEXT, role TEXT, branch TEXT, status TEXT DEFAULT 'Pending',
        join_date TEXT, agreement_status TEXT DEFAULT 'Pending', agreement_notes TEXT, ip_address TEXT, device_info TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP, account_status TEXT DEFAULT 'Active', salary TEXT DEFAULT '0'
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT, surname TEXT, gender TEXT, dob TEXT, contact TEXT, email TEXT,
        address TEXT, city TEXT, postal_code TEXT, country TEXT, id_type TEXT, id_number TEXT, nationality TEXT, qualification TEXT, qualification_upload TEXT,
        course TEXT, fee_amount TEXT, fee_slip_upload TEXT, source TEXT, other_source TEXT, chat_upload TEXT,
        mode_of_learning TEXT DEFAULT 'Online', branch TEXT, assigned_tutor TEXT, status TEXT DEFAULT 'Pending',
        photo TEXT, id_front TEXT, id_back TEXT, declaration TEXT, declaration_date TEXT, terms_accepted TEXT, password TEXT, temp_password TEXT, course_status TEXT DEFAULT 'Assigned',
        ip_address TEXT, device_info TEXT, resit_details TEXT, resit_result_upload TEXT, custom_password TEXT, last_login TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT, student_name TEXT, phone TEXT, email TEXT, course_interested TEXT,
        status TEXT DEFAULT 'New', branch TEXT, assigned_to TEXT, enrolled_date TEXT, enrolled_time TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS whatsapp_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, number TEXT UNIQUE, name TEXT, api_status TEXT DEFAULT 'Connected', assigned_to TEXT, access_status TEXT DEFAULT 'Active', role TEXT, location TEXT, fb_token TEXT, phone_id TEXT, waba_id TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT, wa_number TEXT, student_phone TEXT, sender TEXT, message TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, file_path TEXT, due_date TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, assignment_id INTEGER, student_name TEXT, student_email TEXT, file_path TEXT, submitted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, category TEXT, amount REAL, date TEXT, description TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS branches (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT, student_name TEXT, course_name TEXT, duration TEXT, issue_date TEXT, cert_number TEXT UNIQUE, instructor_name TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // Safe ALTER TABLE (sirf tab jab column na ho)
    db.all("PRAGMA table_info(students)", (err, cols) => {
        if (err || !cols) return;
        const names = cols.map(c => c.name);
        if (!names.includes('card_no')) db.run(`ALTER TABLE students ADD COLUMN card_no TEXT`);
	db.run(`ALTER TABLE students ADD COLUMN is_validated INTEGER DEFAULT 0`, () => { });
        if (!names.includes('card_issued')) db.run(`ALTER TABLE students ADD COLUMN card_issued TEXT`);
    });
});

// Default Super Admin
db.get("SELECT * FROM users WHERE role = 'SuperAdmin'", [], async (err, row) => {
    if (!row) {
        const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 10);
        db.run(`INSERT INTO users (name, email, official_whatsapp, personal_phone, cnic, username, password, role, branch, status, join_date, agreement_status, account_status) VALUES ('Super Admin', 'ioch.institute@gmail.com', '03051116660', '03051116660', '12345-6789012-3', 'ioch.institute@gmail.com', ?, 'SuperAdmin', 'Head Office', 'Active', '2024-01-01', 'Signed', 'Active')`, [hashedPassword]);
    }
});
db.get("SELECT COUNT(*) as c FROM branches", [], (err, row) => {
    if (row && row.c === 0) db.run(`INSERT INTO branches (name) VALUES ('Rawalpindi'), ('Islamabad'), ('Lahore'), ('Karachi')`);
});

// ================= HELPERS =================
const IMG_EXT = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
const isImg = f => IMG_EXT.includes(path.extname(String(f || '')).toLowerCase());
const safeUnlink = f => { if (f) fs.unlink(path.join(uploadDir, path.basename(f)), () => { }); };
async function getSettings() {
    const rows = await dbAll("SELECT key, value FROM settings");
    const o = {}; rows.forEach(r => { o[r.key] = r.value; });
    return o;
}
const esc = v => String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const requireLogin = (req, res, next) => req.session.user ? next() : res.redirect('/login');
const requireRole = (...roles) => (req, res, next) => {
    const u = req.session.user;
    if (!u) return res.redirect('/login');
    if (!roles.includes(u.role)) return res.status(403).send('Access Denied');
    next();
};
const notStudent = (req, res, next) => {
    const u = req.session.user;
    if (!u) return res.redirect('/login');
    if (u.role === 'Student') return res.status(403).send('Access Denied');
    next();
};
function getIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }
const pad = n => String(n).padStart(2, '0');
function nowStr() {
    const d = new Date();
    return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}, ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
const MONTH_EXPR = "(substr(declaration_date,7,4) || '-' || substr(declaration_date,4,2))";
const validMonth = m => /^\d{4}-\d{2}$/.test(m || '') ? m : new Date().toISOString().slice(0, 7);
const csvCell = v => {
    let s = String(v == null ? '' : v);
    if (/^[=+\-@]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
};
const cleanPipe = v => String(v == null ? '' : v).replace(/\|/g, '/').trim();
function parseExtra(str) {
    const m = {};
    (str || '').split('|').forEach(p => {
        const i = p.indexOf(':');
        if (i > 0) m[p.slice(0, i).trim()] = p.slice(i + 1).trim();
    });
    return m;
}
const postBtn = (action, label, cls = 'btn-danger', confirmMsg = '') =>
    `<form action="${action}" method="POST" style="display:inline;"${confirmMsg ? ` onsubmit="return confirm('${esc(confirmMsg)}')"` : ''}><button type="submit" class="btn ${cls}" style="font-size:12px;">${label}</button></form>`;

async function getFinance(month) {
    const first = month + '-01', last = month + '-31';
    const fees = await dbGet(`SELECT COALESCE(SUM(CAST(fee_amount AS REAL)),0) AS t, COUNT(*) AS c FROM students WHERE status = 'Active' AND ${MONTH_EXPR} = ?`, [month]);
    const exp = await dbGet("SELECT COALESCE(SUM(amount),0) AS t FROM expenses WHERE date >= ? AND date <= ?", [first, last]);
    const sal = await dbGet("SELECT COALESCE(SUM(CAST(salary AS REAL)),0) AS t FROM users WHERE role != 'SuperAdmin'");
    const partnerCost = fees.c * PARTNER_COST;
    return { totalFees: fees.t, learners: fees.c, totalExpenses: exp.t, totalSalaries: sal.t, partnerCost, net: fees.t - (exp.t + sal.t + partnerCost) };
}

const money = n => 'PKR ' + Number(n || 0).toLocaleString();
const IMG = f => '/uploads/' + encodeURIComponent(f);

// ================= STUDENT CARD RENDER (moved up so both routes can use) =================
async function ensureCard(s) {
    if (s.card_no) return;
    s.card_no = 'IOCH-' + new Date().getFullYear() + '-' + String(s.id).padStart(4, '0');
    s.card_issued = nowStr().split(',')[0];
    await dbRun("UPDATE students SET card_no = ?, card_issued = ? WHERE id = ?", [s.card_no, s.card_issued, s.id]);
}

function renderCard(s, cfg) {
    const x = parseExtra(s.device_info);
    const bg = cfg.card_bg ? `background:url('${IMG(cfg.card_bg)}') center/cover no-repeat;` : 'background:linear-gradient(135deg,#ecfdf5,#ffffff);';
    const chip = (f, alt) => f ? `<img src="${IMG(f)}" alt="${alt}" style="height:24px; background:white; padding:2px 4px; border-radius:4px; object-fit:contain;">` : '';
    const photo = s.photo
        ? `<img src="${IMG(s.photo)}" style="width:72px; height:90px; object-fit:cover; border-radius:6px; border:2px solid #047857; background:white;">`
        : `<div style="width:72px; height:90px; border-radius:6px; border:2px solid #047857; background:#d1fae5; color:#047857; font-size:30px; font-weight:bold; display:flex; align-items:center; justify-content:center;">${esc((s.first_name || '?').charAt(0))}</div>`;
    const line = (k, v) => `<div style="font-size:9px; color:#475569; line-height:1.25;">${k}</div><div style="font-size:11px; font-weight:bold; color:#0f172a; line-height:1.25; margin-bottom:3px; word-break:break-word;">${esc(v || 'N/A')}</div>`;
    return `
    <div id="stuCard" style="width:340px; height:214px; border-radius:14px; border:1px solid #94a3b8; overflow:hidden; position:relative; margin:0 auto; text-align:left; font-family:Arial,sans-serif; box-shadow:0 6px 18px rgba(0,0,0,0.15); ${bg} -webkit-print-color-adjust:exact; print-color-adjust:exact;">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(6,78,59,0.95); height:38px;">
            <img src="/Ioch-wb.png" alt="IOCH" style="height:24px; background:white; padding:2px 4px; border-radius:4px;">
            <div style="color:white; font-size:10px; font-weight:bold; letter-spacing:1px;">LEARNER CARD</div>
            <div style="display:flex; gap:4px;">${chip(cfg.logo_nebosh, 'NEBOSH')}${chip(cfg.logo_partner, 'Learner Partner')}</div>
        </div>
        <div style="display:flex; gap:10px; padding:10px; background:rgba(255,255,255,0.82); height:150px; overflow:hidden;">
            ${photo}
            <div style="flex:1; min-width:0;">
                ${line('NAME', s.first_name + ' ' + s.surname)}
                ${line('COURSE', s.course)}
                ${line('EXAM DATE', x['CourseDate'])}
                ${line('MODE', x['Mode'] || s.mode_of_learning)}
            </div>
        </div>
        <div style="position:absolute; bottom:0; left:0; right:0; display:flex; justify-content:space-between; padding:5px 10px; background:rgba(6,78,59,0.95); color:white; font-size:9px;">
            <span>Card No: <b>${esc(s.card_no || 'Pending')}</b></span><span>Issued: ${esc(s.card_issued || 'N/A')}</span><span>${esc(cfg.card_footer || 'ioch.org.pk')}</span>
        </div>
    </div>
    <script>
        function printCard() {
            var el = document.getElementById('stuCard');
            var w = window.open('', '_blank', 'width=460,height=340');
            w.document.write('<html><body style="margin:20px;">' + el.outerHTML + '</body></html>');
            w.document.close();
            setTimeout(function () { w.focus(); w.print(); }, 600);
        }
    </script>`;
}

// ================= PROFESSIONAL UI CSS =================
const commonCSS = `
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
        :root { --bg-body: #f8fafc; --primary: #059669; --primary-hover: #047857; --text-main: #1e293b; --text-muted: #64748b; --border: #cbd5e1; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { background-color: var(--bg-body); color: var(--text-main); display: flex; flex-direction: column; min-height: 100vh; }
        img { max-width: 100%; height: auto; }
        .top-info-bar { background: #0f172a; color: #94a3b8; font-size: 13px; padding: 10px 5%; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; border-bottom: 1px solid #1e293b; position: sticky; top: 0; z-index: 1001; }
        .top-info-bar span { display: flex; align-items: center; gap: 8px; }
        .top-info-bar a { color: #cbd5e1; text-decoration: none; }
        .main-navbar { background: white; padding: 20px 5%; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 20px rgba(0,0,0,0.05); position: sticky; top: 40px; z-index: 1000; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; gap: 15px; width: 100%; transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); }
       .main-navbar.scrolled { 
            padding: 10px 5%; 
            margin: 15px auto 0 auto; 
            width: 90%; 
            border-radius: 50px; 
            box-shadow: 0 4px 15px rgba(0,0,0,0.08); /* Shadow halki ki hai */
            border: 1px solid #e2e8f0; 
            top: 0; 
            background: #ffffff !important; /* Solid background taake peechay ka text nazar na aaye */
        }
        .nav-logos img { height: 60px; object-fit: contain; transition: all 0.4s ease; }
        .main-navbar.scrolled .nav-logos img { height: 40px; }
        .nav-menu { display: flex; align-items: center; gap: 25px; flex-wrap: wrap; }
        .nav-menu a { color: #1e293b; text-decoration: none; font-size: 14px; font-weight: 700; text-transform: uppercase; }
        .nav-menu a:hover { color: var(--primary); }
        .nav-buttons { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .btn { padding: 10px 20px; border-radius: 30px; font-size: 15px; font-weight: 600; cursor: pointer; border: none; transition: 0.2s; text-decoration: none; display: inline-block; text-align: center; }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover { background: var(--primary-hover); }
        .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text-main); }
        .btn-danger { background: #ef4444; color: white; padding: 6px 12px; font-size: 13px; border-radius: 6px; }
        .btn-warning { background: #f59e0b; color: white; padding: 6px 12px; font-size: 13px; border-radius: 6px; }
        .btn-info { background: #3b82f6; color: white; padding: 6px 12px; font-size: 13px; border-radius: 6px; }
        .btn-success { background: #10b981; color: white; padding: 6px 12px; font-size: 13px; border-radius: 6px; }
        .hero { background: linear-gradient(135deg, #064e3b 0%, #047857 100%); color: white; padding: 8vh 5%; text-align: center; flex: 1; display: flex; flex-direction: column; justify-content: center; align-items: center; }
        .hero img { max-height: 35vh; margin-bottom: 30px; filter: brightness(0) invert(1); }
        .hero h1 { font-size: clamp(2rem, 5vw, 3.5rem); font-weight: 800; margin-bottom: 20px; }
        .features-section { padding: 8vh 5%; text-align: center; }
        .features-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 30px; max-width: 1200px; margin: 40px auto 0 auto; }
        .feature-card { background: white; padding: 40px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.03); border: 1px solid #e2e8f0; }
        .feature-icon { width: 60px; height: 60px; background: #d1fae5; color: var(--primary); border-radius: 12px; display: flex; justify-content: center; align-items: center; font-size: 24px; margin: 0 auto 20px auto; }
        .footer { background: #0f172a; color: #94a3b8; padding: 60px 1% 20px 1%; border-top: 4px solid var(--primary); width: 100%; }
        .footer-container { max-width: 100%; margin: 0; display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 30px; padding-bottom: 20px; }
        .footer-left { display: flex; flex-direction: column; align-items: flex-start; text-align: left; max-width: 400px; margin-left: -10px; margin-bottom: -20px; }
        .footer-logo-row img { height: 90px; background: white; padding: 10px; border-radius: 8px; margin-bottom: 15px; }
        .footer-association-text { font-size: 14px; color: #cbd5e1; line-height: 1.6; font-weight: 500; }
        .footer-association-text strong { color: white; font-weight: 700; }
        .footer-right { text-align: right; max-width: 400px; margin-right: -10px; margin-bottom: -20px; }
        .footer h4 { color: white; font-size: 1.2rem; margin-bottom: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; }
        .footer p { margin-bottom: 10px; font-size: 0.95rem; line-height: 1.6; }
        .footer a { color: #cbd5e1; text-decoration: none; }
        .footer a:hover { color: white; }
        .footer-bottom { text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid #1e293b; font-size: 0.9rem; color: #64748b; }
        .dash-layout { display: flex; min-height: 100vh; width: 100%; background: #f1f5f9; }
        .sidebar { width: 260px; background: white; display: flex; flex-direction: column; padding: 20px 0; flex-shrink: 0; border-right: 1px solid #e2e8f0; }
        .sidebar .logo-area { padding: 0 20px 20px 20px; border-bottom: 1px solid #e2e8f0; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
        .sidebar .logo-area img { height: 40px; }
        .sidebar a { color: var(--text-muted); padding: 14px 20px; text-decoration: none; font-size: 0.95rem; display: block; transition: 0.2s; border-left: 4px solid transparent; }
        .sidebar a:hover, .sidebar a.active { background: #ecfdf5; color: var(--primary); border-left-color: var(--primary); font-weight: bold; }
        .main-panel { flex: 1; display: flex; flex-direction: column; min-width: 0; }
        .top-bar { background: white; height: 70px; display: flex; justify-content: space-between; align-items: center; padding: 0 30px; border-bottom: 1px solid #e2e8f0; }
        .stats-grid-lms { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card-lms { background: white; border-radius: 16px; padding: 25px; border: 1px solid #e2e8f0; }
        .stat-icon { width: 45px; height: 45px; border-radius: 50%; display: flex; justify-content: center; align-items: center; font-size: 20px; margin-bottom: 15px; }
        .stat-title { font-size: 0.85rem; color: var(--text-muted); font-weight: 700; text-transform: uppercase; }
        .stat-value { font-size: 2.2rem; font-weight: 800; color: var(--text-main); }
        .bg-blue-light { background: #e0e7ff; color: #3b82f6; }
        .bg-green-light { background: #d1fae5; color: #059669; }
        .bg-yellow-light { background: #fef3c7; color: #f59e0b; }
        .bg-purple-light { background: #f3e8ff; color: #8b5cf6; }
        .bg-red-light { background: #fee2e2; color: #ef4444; }
        .content-area { padding: 30px; }
        .lms-welcome { background: linear-gradient(135deg, #064e3b 0%, #047857 100%); color: white; padding: 30px; border-radius: 16px; margin-bottom: 20px; }
        .card { background: white; border-radius: 12px; border: 1px solid #e2e8f0; margin-bottom: 20px; overflow: hidden; }
        .card-header { padding: 20px; border-bottom: 1px solid #e2e8f0; font-weight: 700; font-size: 1.1rem; background: #f8fafc; display: flex; justify-content: space-between; align-items: center; }
        .card-body { padding: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 0.95rem; }
        th { background: #f8fafc; font-weight: 600; color: #64748b; text-transform: uppercase; font-size: 0.8rem; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-weight: 600; margin-bottom: 8px; color: var(--text-main); font-size: 0.9rem; }
        input, select, textarea { width: 100%; padding: 14px 15px; border: 1px solid var(--border); border-radius: 10px; font-size: 1rem; background: #f8fafc; }
        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .file-upload-box { border: 2px dashed #cbd5e1; padding: 25px; border-radius: 12px; text-align: center; background: #f8fafc; position: relative; height: 100%; }
        .file-upload-box input[type="file"] { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
        .file-upload-box label { font-size: 1rem; font-weight: 700; }
        .chat-messages { flex: 1; padding: 20px; overflow-y: auto; background: #efeae2; }
        .msg { padding: 10px 15px; border-radius: 8px; margin-bottom: 10px; max-width: 80%; font-size: 0.95rem; }
        .msg-received { background: white; }
        .msg-sent { background: #d9fdd3; margin-left: auto; }
        .chat-input { display: flex; padding: 10px; background: white; border-top: 1px solid #e2e8f0; }
        .chat-input input { flex: 1; margin-right: 10px; }
        @media (max-width: 768px) {
            .dash-layout { flex-direction: column; }
            .sidebar { width: 100%; }
            .footer-container { flex-direction: column; align-items: center; text-align: center; }
            .footer-left { align-items: center; text-align: center; margin-left: 0; margin-bottom: 20px; }
            .footer-right { text-align: center; margin-right: 0; margin-bottom: 20px; }
        }
        @media print {
            .no-print, .sidebar, .top-bar { display: none !important; }
            .dash-layout, .main-panel, .content-area { margin: 0 !important; padding: 0 !important; display: block !important; }
            .card { border: 1px solid #94a3b8 !important; page-break-inside: avoid; margin-bottom: 15px !important; box-shadow: none !important; }
            .id-card { box-shadow: none !important; border: 2px solid #064e3b !important; page-break-inside: avoid; }
        }
    </style>`;

const publicHeaderFooter = (contentHTML) => {
    return "<!DOCTYPE html>" +
    "<html>" +
    "<head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>IOCH - Institution of Occupational Career Hub</title>" + commonCSS + "</head>" +
    "<body>" +
    "<div class='top-info-bar' id='topInfoBar'>" +
    "<div><span>📍 Property No 1056, 1st Floor, Sayed Pur Road, Satellite Town, Commercial Market, Rawalpindi - 46000</span></div>" +
    "<div style='display:flex; gap:15px; flex-wrap:wrap; justify-content:center;'>" +
    "<span>✉️ <a href='mailto:info@ioch.org.pk'>info@ioch.org.pk</a></span>" +
    "<span>📞 +92 305 1116660</span>" +
    "<span>📱 +92 305 1111855</span>" +
    "</div>" +
    "</div>" +
    "<div class='main-navbar' id='mainNavbar'>" +
    "<div class='nav-logos'><img src='/Ioch-wb.png' alt='IOCH Logo'></div>" +
    "<div class='nav-menu'>" +
    "<a href='/' class='active'>Home</a>" +
    "<a href='#'>About Us</a>" +
    "<a href='#'>International Trainings</a>" +
    "<a href='#'>Gulf Trainings</a>" +
    "<a href='#'>Consultancy</a>" +
    "<a href='/verify'>Verification</a>" +
    "</div>" +
    "<div class='nav-buttons'>" +
    "<a href='/login' class='btn btn-outline'>Login</a>" +
    "<a href='/student-register' class='btn btn-primary'>Register</a>" +
    "</div>" +
    "</div>" +
    contentHTML +
    "<div class='footer'>" +
    "<div class='footer-container'>" +
    "<div class='footer-left'>" +
    "<div class='footer-logo-row'><img src='/peerless.png' alt='Peerless Logo'></div>" +
    "<div class='footer-association-text'><strong>IOCH</strong> is under association with<br><strong>Peerless Training &amp; Development</strong><br>(1818) for NEBOSH course.</div>" +
    "</div>" +
    "<div class='footer-right'>" +
    "<h4>Contact Us</h4>" +
    "<p>Property No 1056, 1st Floor, Sayed Pur Road,<br>Satellite Town, Commercial Market,<br>Rawalpindi - Postal Code: 46000</p>" +
    "<p>Phone: <a href='tel:03051116660'>+92 305 1116660</a></p>" +
    "<p>Email: <a href='mailto:info@ioch.org.pk'>info@ioch.org.pk</a></p>" +
    "</div>" +
    "</div>" +
    "<div class='footer-bottom'>&copy; " + new Date().getFullYear() + " IOCH. All Rights Reserved.</div>" +
    "</div>" +
    "<script>" +
    "const navbar = document.getElementById('mainNavbar');" +
    "const topInfoBar = document.getElementById('topInfoBar');" +
    "if (navbar && topInfoBar) {" +
    "window.addEventListener('scroll', () => {" +
    "if (window.scrollY > 50) { navbar.classList.add('scrolled'); topInfoBar.style.display = 'none'; }" +
    "else { navbar.classList.remove('scrolled'); topInfoBar.style.display = 'flex'; }" +
    "});" +
    "}" +
    "</script>" +
    "</body>" +
    "</html>";
};

const renderDashboard = (user, contentHTML, activeMenu = 'dashboard') => {
    const is = (...roles) => roles.includes(user.role);
    const link = (href, key, label) => `<a href="${href}" class="${activeMenu === key ? 'active' : ''}">${label}</a>`;
    const menu = user.role === 'Student' ? `
        ${link('/dashboard', 'dashboard', '🏠 Overview')}
        ${link('/lms', 'lms', '📚 My Courses')}
        ${link('/courses', 'courses', '📖 Course Library')}
        ${link('/my-card', 'mycard', '🆔 My Student Card')}
        ${link('/my-grades', 'grades', '🏆 My Grades')}
        ${link('/change-password', 'password', '🔒 Change Password')}
    ` : `
        ${link('/dashboard', 'dashboard', '📊 Dashboard')}
        ${is('SuperAdmin', 'Admin', 'Tutor') ? link('/students', 'students', '🎓 Students Details') : ''}
        ${is('SuperAdmin', 'Admin') ? link('/manage-users', 'users', '👥 Employees') : ''}
        ${is('SuperAdmin', 'Admin') ? link('/certificates', 'certificates', '🏆 Certificates') : ''}
        ${is('SuperAdmin', 'Admin', 'Sales') ? link('/leads', 'leads', '🎯 Leads & CRM') : ''}
        ${is('SuperAdmin', 'Tutor') ? link('/lms', 'lms', '🎓 LMS & Assignments') : ''}
        ${is('SuperAdmin', 'Accountant') ? link('/finance', 'accounts', '💰 Accounts') : ''}
        ${is('SuperAdmin') ? link('/card-settings', 'cardset', '🆔 Card Settings') : ''}
        ${link('/live-chat', 'livechat', '💬 Live Chat')}
        ${is('SuperAdmin') ? link('/reports', 'reports', '📊 Reports') : ''}
        ${is('SuperAdmin') ? link('/whatsapp-setup', 'wa_setup', '⚙️ WhatsApp Setup') : ''}
        ${link('/chats', 'chats', '💬 WhatsApp Inbox')}
        ${is('SuperAdmin', 'Admin', 'Tutor') ? link('/courses', 'courses', '📖 Courses (LMS)') + link('/grading', 'grading', '📝 Grading') : ''}
    `;
    return `
    <!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>IOCH ERP Dashboard</title>${commonCSS}</head><body>
        <div class="dash-layout">
            <div class="sidebar">
                <div class="logo-area">
                    <img src="/Ioch-wb.png" alt="Logo">
                    <span style="font-weight:700; font-size:1.1rem; color:#1e293b;">IOCH Portal</span>
                </div>
                ${menu}
                <a href="/logout" style="margin-top:auto; color:#ef4444;">🚪 Logout</a>
            </div>
            <div class="main-panel">
                <div class="top-bar">
                    <div style="font-weight:600; font-size:1.1rem;">${esc(activeMenu.toUpperCase())}</div>
                    <div style="display:flex; align-items:center; gap:15px;">
                        <div style="text-align:right;">
                            <div style="font-weight:600;">${esc(user.name)}</div>
                            <div style="font-size:0.8rem; color:#64748b;">${esc(user.role)} | ${esc(user.branch)}</div>
                        </div>
                        <div style="width:40px; height:40px; background:#d1fae5; color:#047857; border-radius:50%; display:flex; justify-content:center; align-items:center; font-weight:bold;">${esc((user.name || '?').charAt(0))}</div>
                    </div>
                </div>
                <div class="content-area">
                    ${contentHTML}
                </div>
            </div>
        </div>
    </body></html>`;
};

// ================= TERMS & CONDITIONS =================
const TERMS_HTML = `
<h5 style="color:#1e293b; margin-bottom:10px; font-weight:700;">Course Registration, Attendance and Refund Policy</h5>
<p style="font-weight:bold; margin-bottom:15px;">Institution of Occupational Career Hub (IOCH)</p>
<p style="margin-bottom:15px;">All learners must read this policy carefully before completing their registration. In this policy, "IOCH" refers to the Institution of Occupational Career Hub. "Working days" means Monday to Friday, excluding official public holidays in Pakistan. All other references to days mean calendar days.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">1. Registration</h6>
<p style="margin-bottom:15px;">Early registration is recommended, as seats are limited. Registration is confirmed only after IOCH receives the required documents and agreed payment. Learners must complete the Course Registration Form and provide valid identification, as required for course or examination registration. Learners are responsible for ensuring that their name, identification details, contact information and other registration details are accurate. Names must match the identification required by the relevant awarding body. Any third-party correction or reissue fees resulting from incorrect information supplied by the learner shall be payable by the learner, subject to prior notification. The registration confirmation or quotation shall specify the course, agreed fees, delivery method, scheduled dates and included services.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">2. Attendance and Examination Eligibility</h6>
<p style="margin-bottom:15px;">IOCH requires learners to attend at least 90% of the scheduled training hours, together with any additional mandatory requirements specified for the course or by the awarding body. Absence exceeding 10% of the scheduled training hours, or a lower absence limit expressly specified for the course, will make the learner ineligible to sit the examination through IOCH for that intake until the attendance requirements are fulfilled. Fees paid will not be refundable where examination ineligibility results from the learner's failure to meet the attendance requirements, subject to applicable law. Attendance is calculated by training hours. Late arrival and early departure may be recorded as missed time. Learners arriving more than 15 minutes late may be marked absent for the session, as explained in the course attendance instructions. Learners must attend on time, participate actively and complete required coursework and assessments. Accessing recordings does not replace mandatory attendance unless expressly approved. Any approved make-up sessions, repeat training or examination re-registration may incur additional fees, which will be disclosed before confirmation. Documented exceptional circumstances may be considered individually, subject to applicable law and awarding-body requirements.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">3. Cancellation and Refunds</h6>
<p style="margin-bottom:15px;">Cancellation requests must be submitted in writing to Support@ioch.org.pk or through another official written communication channel stated in the registration confirmation. A telephone call alone does not constitute a cancellation request. The cancellation date is the date the written request is received through an official channel. For learner-requested cancellations received more than 7 calendar days before the scheduled course commencement date, and before registration with the relevant awarding body, a 50% refund of the agreed course fee may be issued, subject to the third-party fee provisions below. The refund shall not exceed the amount actually paid. No refund will be issued for learner-requested cancellations received 7 calendar days or less before the scheduled course commencement date, on the commencement date, or after the course has started. Following registration with the relevant awarding body, learner-requested cancellations are non-refundable, except for any recoverable third-party amounts or refunds required by applicable law. Non-attendance, withdrawal, failure to complete the course or failure to pass an assessment does not create an entitlement to a refund. Fees are not automatically transferable to another learner, course or intake. Any transfer requires written approval from IOCH and, where applicable, the awarding body. These cancellation restrictions do not override mandatory statutory cancellation or refund rights, including any applicable rights relating to online purchases. Refunds arising from cancellation by IOCH are governed by Section 5.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">4. Third-Party Fees and Refund Processing</h6>
<p style="margin-bottom:15px;">Third-party charges may include awarding-body registration, examination bookings, externally supplied learning resources, activated software licences, payment-provider charges and courier services. Where legally permitted, actual third-party costs incurred for the learner that cannot be recovered shall be borne by the learner and may be deducted from an otherwise eligible refund. Such charges must have been disclosed before the learner committed to the relevant purchase. IOCH will provide an itemised explanation of deductions. No cost shall be deducted twice or charged again if it is already covered by an amount retained under the cancellation policy. Any amount recovered from a third party on the learner's behalf shall be included in the refund calculation or passed on to the learner, as applicable. IOCH is not required to advance a refund that remains subject to a third party's approval and payment, unless applicable law requires otherwise. Refunds payable by IOCH will be processed within 14 calendar days after entitlement is established and the necessary payment details are available, or within any shorter period required by law. Refunds will normally be returned through the original payment method. Instalment and buy-now-pay-later transactions will be adjusted through the relevant provider's process. No additional refund-processing charge will be imposed where prohibited by law. This section does not limit refunds owed because IOCH cancels or fails to provide the contracted service.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">5. Course Rescheduling and Cancellation by IOCH</h6>
<p style="margin-bottom:15px;">IOCH reserves the right to postpone the course commencement date by up to 10 working days from the originally confirmed commencement date due to operational requirements, trainer availability, minimum enrolment requirements or circumstances beyond its reasonable control. Learners will be notified through their registered contact details as soon as reasonably practicable. The 10-working-day limit is cumulative and cannot be restarted through successive postponements. A postponement within this period does not, by itself, create a contractual entitlement to a refund, without prejudice to any applicable statutory rights. IOCH may appoint a suitably qualified replacement trainer while maintaining the agreed course scope and training hours. A material change to the delivery method or location requires the learner's agreement. If IOCH cancels the course without delivering it, the learner may choose an available alternative course or receive a full refund of the fees paid for the cancelled course. If postponement exceeds 10 working days, the learner may accept the revised schedule or cancel and receive a refund for the undelivered course. The learner-cancellation penalties will not apply. Where only part of a course has been delivered, any refund will reflect the undelivered services and applicable legal rights.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">6. Discontinuation, Absence and Deferral</h6>
<p style="margin-bottom:15px;">A learner who needs to discontinue training must notify IOCH promptly in writing. IOCH may approve a one-time deferral of up to 2 months from the original course commencement date, subject to seat availability, course scheduling and awarding-body deadlines. A deferral is valid only when confirmed in writing. It does not automatically extend an examination registration, assessment deadline or awarding-body registration period. Additional third-party fees or fees for repeat training may apply and will be disclosed before the deferral is accepted. If the learner fails to resume within the approved period despite an appropriate intake being available, the course credit will expire and a new registration at the applicable course fee will be required. Where IOCH cannot offer an appropriate intake within the approved period, a revised arrangement will be agreed with the learner.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">7. Payments</h6>
<p style="margin-bottom:15px;">Learners must pay the full agreed course fee at least 20 calendar days before the examination registration deadline notified by IOCH, unless a different payment arrangement is agreed in writing. Learners who fail to complete the required payment by the notified deadline will not be registered for the examination. Payments must be made only through bank accounts, payment links or other payment methods officially approved by IOCH. Learners must not transfer funds to employees' or other individuals' personal accounts. IOCH does not authorise such payments. Learners must retain their payment receipts and provide them when requested for reconciliation. Examination resits, repeat training, optional services and other exclusions are payable separately unless expressly included in the written quotation. All additional charges and applicable taxes must be disclosed before the learner agrees to the relevant service.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">8. Course Materials and Printed Books</h6>
<p style="margin-bottom:15px;">Included learning materials will be supplied in the format specified in the course quotation or registration confirmation. Printed textbooks, workbooks and other physical learning materials are subject to additional charges unless expressly included in the course fee. Printing, purchase and delivery charges must be paid before the materials are ordered or dispatched. Materials are owned by IOCH, the relevant awarding body, publisher or other rights holder, as applicable. Learners may use the materials for their personal studies only. Unauthorised reproduction, resale, distribution or sharing is prohibited, subject to any permissions granted by the relevant rights holder. Learning-platform credentials are personal and must not be shared.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">9. Certificates and Delivery Charges</h6>
<p style="margin-bottom:15px;">Certificates are issued only after the relevant attendance, assessment and awarding-body requirements have been satisfied. Certificate format and availability depend on the course and issuing body. A printed certificate is not available for every qualification. Where a learner requests a physical certificate, any applicable printing or issuing charges, together with shipping and courier charges, shall be payable by the learner unless expressly included in the course fee. These charges will be disclosed and agreed before the order or dispatch. Learners must provide an accurate delivery address and contact number. Additional delivery costs resulting from incorrect details supplied by the learner or a failed delivery attributable to the learner shall be payable by the learner. Replacement certificates and corrections resulting from learner-supplied errors may incur the issuing body's applicable charges. IOCH will assist with delivery enquiries. Any responsibility for loss, damage or delay will be determined in accordance with the relevant service terms and applicable law.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">10. NEBOSH Enquiries About Results — EAR</h6>
<p style="margin-bottom:15px;">This section applies to NEBOSH learners only. Learners may submit an Enquiry About Results directly to NEBOSH or request assistance from IOCH, in accordance with the current NEBOSH procedures. Applications and payments must be completed before the applicable NEBOSH deadline. Learners requesting assistance must also meet the submission deadline communicated by IOCH. EAR eligibility, fees, outcomes and refunds are governed by the current NEBOSH EAR policy. Where an EAR is successful under NEBOSH's policy, the applicable EAR fee will be refunded in accordance with that policy. An unsuccessful EAR does not normally qualify for a fee refund. If IOCH receives an EAR refund on behalf of the learner, it will pass the amount received to the learner without an additional deduction. IOCH does not guarantee an improved result or a particular processing time by NEBOSH.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">11. Assessment Integrity, Plagiarism and Collusion</h6>
<p style="margin-bottom:15px;">All assessment work submitted must be the learner's own and must comply with the relevant awarding body's assessment instructions. Learners must not share answers, collude with others, impersonate another candidate, purchase assessment answers or submit another person's work as their own. Artificial intelligence and other assistance may be used only to the extent expressly permitted by the relevant assessment instructions and awarding-body policy. Suspected malpractice will be reported to the relevant awarding body for investigation. Penalties, invalidated results and any future assessment eligibility will be determined under the relevant awarding body's procedures. Where misconduct is established through the applicable process, it does not itself entitle the learner to a refund. Any permitted resit or re-registration may require additional payment.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">12. NEBOSH Closing Interviews</h6>
<p style="margin-bottom:15px;">This section applies where the relevant NEBOSH assessment requires a closing interview. Learners must attend the mandatory closing interview following submission of the relevant assessment, including GIC1 or the applicable equivalent unit. IOCH will communicate the interview arrangements and identity-verification requirements. The closing interview is an authenticity check and is not a separately graded examination. Failure to attend or complete the required interview may prevent release of the learner's result under NEBOSH procedures. Suspected malpractice identified during the interview will be referred to NEBOSH for investigation.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">13. Training Conduct and Learner Responsibilities</h6>
<p style="margin-bottom:15px;">Learners must behave professionally, respect trainers and other learners, and follow health, safety and venue requirements. Disruptive, abusive or unsafe behaviour may result in removal from a session or suspension, subject to a documented review. Learners must bring the materials advised by the trainer and complete required activities and assessments. For online training, learners are responsible for providing a suitable device, stable internet connection and the necessary access arrangements communicated before registration. Recording or distributing training sessions without permission is prohibited. Course attendance or payment does not guarantee an examination pass, qualification, employment or professional licence.</p>
<h6 style="color:#1e293b; margin-top:15px; margin-bottom:5px; font-weight:bold;">14. Communications, Complaints and Applicable Terms</h6>
<p style="margin-bottom:15px;">Learners must keep their registered contact details up to date and monitor official course communications. All enquiries, complaints and refund requests must be submitted in writing to Support@ioch.org.pk, including the learner's name, course name and relevant details. Learners may request a review of attendance records, fee calculations or administrative decisions and provide supporting evidence. Personal information will be handled in accordance with applicable data-protection requirements and the IOCH privacy notice. This policy is subject to the applicable laws and regulatory requirements of Pakistan. Mandatory legal rights prevail over any conflicting provision. Any agreed exception must be recorded in writing by an authorised IOCH representative. Changes to this policy will not retrospectively reduce the rights of learners already registered.</p>
`;

// ================= PUBLIC ROUTES =================
app.get('/', (req, res) => {
    res.send(publicHeaderFooter(`
        <div class="hero">
            <img src="/Ioch-wb.png" alt="IOCH Logo">
            <h1>Institution of Occupational Career Hub</h1>
            <p>Empowering Careers through Quality Education &amp; International Training. Join us to build a brighter future with globally recognized certifications.</p>
        </div>
        <div class="features-section">
            <h2>Why Choose IOCH?</h2>
            <p>We provide top-tier international training and consultancy services.</p>
            <div class="features-grid">
                <div class="feature-card"><div class="feature-icon">🌐</div><h3>International Trainings</h3><p>Get certified with globally recognized courses like NEBOSH, IOSH.</p></div>
                <div class="feature-card"><div class="feature-icon">🏝️</div><h3>Gulf Trainings</h3><p>Specialized training for the Gulf region's safety standards.</p></div>
                <div class="feature-card"><div class="feature-icon">📈</div><h3>Consultancy Services</h3><p>Expert consultation for businesses to ensure occupational safety.</p></div>
             </div>
        </div>`));
});

app.get('/verify', wrap(async (req, res) => {
    const num = (req.query.cert || '').trim();
    let result = '';
    if (num) {
        const c = await dbGet("SELECT * FROM certificates WHERE cert_number = ?", [num]);
        result = c
            ? `<div style="background:#ecfdf5; border:2px solid #10b981; padding:20px; border-radius:12px; margin-top:20px; text-align:left;"><h3 style="color:#047857;">✔️ Valid Certificate</h3><p><b>Name:</b> ${esc(c.student_name)}</p><p><b>Course:</b> ${esc(c.course_name)}</p><p><b>Duration:</b> ${esc(c.duration)}</p><p><b>Issue Date:</b> ${esc(c.issue_date)}</p><p><b>Instructor:</b> ${esc(c.instructor_name)}</p></div>`
            : `<div style="background:#fee2e2; border:2px solid #ef4444; padding:20px; border-radius:12px; margin-top:20px; color:#b91c1c;">❌ Certificate not found.</div>`;
    }
    res.send(publicHeaderFooter(`
        <div style="display:flex; justify-content:center; padding:60px 20px; background:#f1f5f9;">
            <div style="background:white; padding:40px; border-radius:20px; width:100%; max-width:550px; text-align:center; box-shadow:0 10px 30px rgba(0,0,0,0.08);">
                <h2 style="margin-bottom:20px;">Certificate Verification</h2>
                <form action="/verify" method="GET"><div class="form-group"><input type="text" name="cert" value="${esc(num)}" placeholder="Enter certificate number" required></div><button type="submit" class="btn btn-primary" style="width:100%;">Verify</button></form>
                ${result}
            </div>
        </div>`));
}));

// ================= LOGIN =================
app.get('/verify-document', wrap(async (req, res) => {
    const docNo = req.query.doc || '';
    let isValid = false, s = null, msg = 'Invalid Document Number.';

    if (docNo.startsWith('IOCH-')) {
        const parts = docNo.split('-');
        if (parts.length >= 2) {
            const studentId = Number(parts[1]); // String ko Number mein convert kiya
            s = await dbGet("SELECT first_name, surname, course, status, is_validated FROM students WHERE id = ?", [studentId]);
            
            if (s) {
                if (s.status === 'Active' && s.is_validated == 1) {
                    isValid = true;
                } else {
                    msg = 'This document is currently not validated or the student is suspended. Please contact IOCH Admin.';
                }
            }
        }
    }

    res.send(publicHeaderFooter(`
        <div style="display:flex; justify-content:center; align-items:center; min-height:70vh; background:#f1f5f9; padding:20px;">
            <div style="background:white; padding:40px; border-radius:20px; width:100%; max-width:500px; text-align:center;">
                <img src="/Ioch-wb.png" style="height:70px; margin-bottom:20px;">
                <h2 style="margin-bottom:10px; color:#0f172a;">Document Verification</h2>
                ${isValid ? `
                    <div style="background:#ecfdf5; border:2px solid #10b981; border-radius:12px; padding:25px; text-align:left;">
                        <div style="font-size:40px; text-align:center; margin-bottom:15px;">✅</div>
                        <h3 style="color:#047857; text-align:center; margin-bottom:15px;">Document is Valid</h3>
                        <div style="border-top:1px dashed #cbd5e1; padding-top:15px;">
                            <div style="margin-bottom:8px;"><b>Name:</b> ${esc(s.first_name)} ${esc(s.surname)}</div>
                            <div style="margin-bottom:8px;"><b>Course:</b> ${esc(s.course)}</div>
                            <div style="margin-top:15px; font-size:12px; color:#059669; font-weight:bold; text-align:center;">Issued & Validated by IOCH</div>
                        </div>
                    </div>
                ` : `
                    <div style="background:#fee2e2; border:2px solid #ef4444; border-radius:12px; padding:30px;">
                        <div style="font-size:40px; margin-bottom:15px;">❌</div>
                        <h3 style="color:#b91c1c; margin:0;">Verification Failed</h3>
                        <p style="color:#991b1b; margin-top:10px; font-size:14px;">${msg}</p>
                    </div>
                `}
            </div>
        </div>
    `));
}));
// ================= DASHBOARD =================
app.get('/dashboard', requireLogin, wrap(async (req, res) => {
    const user = req.session.user;

    if (user.role === 'Student') {
        return res.send(renderDashboard(user, `
            <div class="lms-welcome"><h1>Welcome, ${esc(user.name)}! 👋</h1><p>Continue your learning journey.</p></div>
            <div class="card"><div class="card-body" style="display:flex; justify-content:space-between; align-items:center;"><h3>Check your Assignments</h3><a href="/lms" class="btn btn-primary">Go to LMS</a></div></div>`, 'dashboard'));
    }

    if (!['SuperAdmin', 'Admin'].includes(user.role)) {
        return res.send(renderDashboard(user, `<div class="card"><div class="card-body">Welcome ${esc(user.name)}</div></div>`, 'dashboard'));
    }

    const isSuper = user.role === 'SuperAdmin';
    const month = validMonth(req.query.month);
    const theme = ['purple', 'green', 'blue'].includes(req.query.theme) ? req.query.theme : 'purple';

    const fin = await getFinance(month);
    const totalUsers = (await dbGet("SELECT COUNT(*) AS c FROM users")).c;
    const totalStudents = (await dbGet("SELECT COUNT(*) AS c FROM students")).c;
    const pendingStudents = (await dbGet("SELECT COUNT(*) AS c FROM students WHERE status = 'Pending'")).c;
    const totalSalaries = fin.totalSalaries;

    const branches = await dbAll("SELECT * FROM branches");
    const admins = await dbAll("SELECT * FROM users WHERE role = 'Admin'");
    const branchOptions = branches.map(b => `<option value="${esc(b.name)}">${esc(b.name)}</option>`).join('');
    const adminRows = admins.map(a => `<tr><td>${esc(a.name)}</td><td>${esc(a.email)}</td><td><span class="badge">${esc(a.branch)}</span></td></tr>`).join('');
    const branchRows = branches.map(b => `<tr><td><form action="/edit-branch/${b.id}" method="POST" style="display:flex; gap:5px;"><input type="text" name="new_branch_name" value="${esc(b.name)}" required style="padding:6px; font-size:13px;"><button type="submit" class="btn btn-info" style="padding:6px 10px; font-size:12px;">Update</button></form></td><td style="text-align:right;">${postBtn('/delete-branch/' + b.id, 'Delete', 'btn-danger', 'Kya aap waqai is branch ko delete karna chahte hain?')}</td></tr>`).join('');

    const trend = [];
    for (let i = 5; i >= 0; i--) {
        const d = new Date(); d.setDate(1); d.setMonth(d.getMonth() - i);
        const m = `${d.getFullYear()}-${pad(d.getMonth() + 1)}`;
        const tf = await getFinance(m);
        trend.push({ label: d.toLocaleString('en-GB', { month: 'short' }), inc: tf.totalFees, out: tf.totalExpenses + tf.totalSalaries + tf.partnerCost });
    }
    const maxVal = Math.max(1, ...trend.flatMap(t => [t.inc, t.out]));
    const graphHtml = trend.map(t => `
        <div class="graph-bar-group">
            <div style="display:flex; gap:2px; align-items:flex-end; height:100%;">
                <div class="graph-bar" style="height:${Math.round(t.inc / maxVal * 100)}%;" title="Income: PKR ${t.inc.toLocaleString()}"></div>
                <div class="graph-bar expense" style="height:${Math.round(t.out / maxVal * 100)}%;" title="Expense: PKR ${t.out.toLocaleString()}"></div>
            </div>
            <div class="graph-label">${esc(t.label)}</div>
        </div>`).join('');

    const hr = new Date().getHours();
    const greet = hr < 12 ? 'Good morning' : hr < 17 ? 'Good afternoon' : 'Good evening';

    const themes = {
        purple: { bg: 'linear-gradient(135deg, #3b0764 0%, #6b21a8 100%)', icon: '#9333ea', bgLight: '#f3e8ff', text: '#6b21a8' },
        green: { bg: 'linear-gradient(135deg, #064e3b 0%, #059669 100%)', icon: '#10b981', bgLight: '#d1fae5', text: '#047857' },
        blue: { bg: 'linear-gradient(135deg, #172554 0%, #2563eb 100%)', icon: '#3b82f6', bgLight: '#dbeafe', text: '#1e40af' }
    };
    const currentTheme = themes[theme];

    const superCards = isSuper ? `
        <div class="grid-2" style="margin-top:30px; align-items:start;">
            <div class="card"><div class="card-header">🌐 Add New Branch</div><div class="card-body"><form action="/add-branch" method="POST" style="display:flex; gap:10px;"><input type="text" name="branch_name" placeholder="e.g. Faisalabad" required style="flex:1;"><button type="submit" class="btn btn-primary">Add Branch</button></form></div></div>
            <div class="card"><div class="card-header">👁️ Assign Branch Admin</div><div class="card-body"><form action="/assign-branch-admin" method="POST" style="display:flex; flex-direction:column; gap:15px;"><div class="form-group" style="margin:0;"><label>Select Branch</label><select name="branch_name" required><option value="">-- Select Branch --</option>${branchOptions}</select></div><div class="form-group" style="margin:0;"><label>Admin Details</label><div class="grid-2"><input type="text" name="admin_name" placeholder="Full Name" required><input type="email" name="admin_email" placeholder="Email (Username)" autocomplete="off" required><input type="text" name="admin_whatsapp" placeholder="WhatsApp No" required><input type="password" name="admin_pass" placeholder="Password (min 6)" minlength="6" autocomplete="new-password" required></div></div><button type="submit" class="btn btn-success">Create &amp; Assign Admin</button></form></div></div>
        </div>
        <div class="card" style="margin-top:20px;"><div class="card-header">🌐 Manage Branches (Edit / Delete)</div><table><tr><th>Branch Name</th><th style="text-align:right;">Action</th></tr>${branchRows || "<tr><td colspan='2' style='text-align:center;'>No branches found.</td></tr>"}</table></div>
        <div class="card" style="margin-top:20px;"><div class="card-header">Current Branch Admins</div><table><tr><th>Name</th><th>Email</th><th>Branch Assigned</th></tr>${adminRows}</table></div>` : '';

    const superActions = isSuper ? `<a href="/finance" class="qa-btn"><div class="icon">💼</div> Collect Fee</a>` : '';
    const superActions2 = isSuper ? `<a href="/lms" class="qa-btn"><div class="icon">📎</div> Assignments</a>` : '';
    const superActions3 = isSuper ? `<a href="/whatsapp-setup" class="qa-btn"><div class="icon">💬</div> WhatsApp</a>` : '';

    const content = `
        <style>
            .dash-hero { background: ${currentTheme.bg}; border-radius: 20px; padding: 30px; color: white; margin-bottom: 25px; position: relative; overflow: hidden; }
            .dash-hero h1 { font-size: 28px; font-weight: 700; margin-bottom: 5px; }
            .dash-hero p { font-size: 14px; opacity: 0.9; }
            .hero-stats { display: flex; gap: 15px; margin-top: 25px; flex-wrap: wrap; }
            .hero-stat-box { background: rgba(255,255,255,0.15); backdrop-filter: blur(5px); padding: 15px 20px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.2); flex: 1; min-width: 150px; display: flex; align-items: center; gap: 15px; }
            .hero-stat-box .icon { font-size: 24px; }
            .hero-stat-box .val { font-size: 22px; font-weight: 700; line-height: 1.2; }
            .hero-stat-box .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.8; }
            .quick-actions { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 15px; margin-bottom: 25px; }
            .qa-btn { background: white; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; text-align: center; text-decoration: none; color: #1e293b; font-size: 13px; font-weight: 600; transition: all 0.2s; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; }
            .qa-btn:hover { border-color: ${currentTheme.icon}; box-shadow: 0 4px 12px ${currentTheme.bgLight}; transform: translateY(-2px); }
            .qa-btn .icon { font-size: 22px; background: ${currentTheme.bgLight}; color: ${currentTheme.text}; width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
            .stats-grid-modern { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 25px; }
            .stat-card-modern { background: white; border-radius: 16px; padding: 20px; border: 1px solid #e2e8f0; }
            .stat-card-modern .top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
            .stat-card-modern .icon-box { width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 18px; background: ${currentTheme.bgLight}; color: ${currentTheme.text}; }
            .stat-card-modern .line { width: 40px; height: 3px; background: ${currentTheme.icon}; border-radius: 2px; }
            .stat-card-modern .title { font-size: 12px; color: #64748b; font-weight: 700; text-transform: uppercase; margin-bottom: 5px; }
            .stat-card-modern .value { font-size: 26px; font-weight: 800; color: #0f172a; margin-bottom: 10px; }
            .stat-card-modern .sub { font-size: 12px; color: ${currentTheme.text}; font-weight: 600; display: flex; align-items: center; gap: 5px; }
            .graph-container { background: white; border-radius: 16px; padding: 20px; border: 1px solid #e2e8f0; margin-bottom: 25px; }
            .graph-bars { display: flex; align-items: flex-end; gap: 15px; height: 200px; margin-top: 20px; padding-top: 20px; border-top: 1px dashed #cbd5e1; }
            .graph-bar-group { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; gap: 5px; height: 100%; }
            .graph-bar { width: 30px; background: ${currentTheme.icon}; border-radius: 4px 4px 0 0; transition: height 0.5s ease; min-height: 2px; position: relative; }
            .graph-bar.expense { background: #ef4444; }
            .graph-label { font-size: 11px; color: #64748b; margin-top: 10px; text-transform: uppercase; }
            .theme-switch { display: flex; gap: 10px; margin-bottom: 20px; justify-content: flex-end; }
            .theme-btn { width: 30px; height: 30px; border-radius: 50%; border: 2px solid transparent; cursor: pointer; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
            .theme-btn.active { border-color: #1e293b; }
            .theme-purple { background: #6b21a8; }
            .theme-green { background: #059669; }
            .theme-blue { background: #2563eb; }
            .badge { background: #e0f2fe; color: #0284c7; padding: 4px 8px; border-radius: 4px; font-size: 11px; }
        </style>

        <div class="theme-switch no-print">
            <a href="?month=${esc(month)}&theme=purple" class="theme-btn theme-purple ${theme === 'purple' ? 'active' : ''}" title="Purple Theme"></a>
            <a href="?month=${esc(month)}&theme=green" class="theme-btn theme-green ${theme === 'green' ? 'active' : ''}" title="Green Theme"></a>
            <a href="?month=${esc(month)}&theme=blue" class="theme-btn theme-blue ${theme === 'blue' ? 'active' : ''}" title="Blue Theme"></a>
        </div>

        <div class="dash-hero">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:20px;">
                <div>
                    <h1>${greet}, ${esc(user.name)}</h1>
                    <p>Here is what's happening at your institute today.</p>
                </div>
                <div style="display:flex; gap:10px; align-items:center;">
                    <form action="/dashboard" method="GET" style="margin:0; display:flex; gap:10px;">
                        <input type="hidden" name="theme" value="${esc(theme)}">
                        <input type="month" name="month" value="${esc(month)}" style="padding:8px 12px; border-radius:8px; border:none; background:rgba(255,255,255,0.2); color:white; font-weight:bold;">
                        <button type="submit" style="padding:8px 15px; border-radius:8px; border:none; background:white; color:${currentTheme.text}; font-weight:bold; cursor:pointer;">Filter</button>
                    </form>
                    <a href="/export-financial-report?month=${esc(month)}" style="padding:8px 15px; border-radius:8px; border:none; background:rgba(255,255,255,0.2); color:white; font-weight:bold; text-decoration:none;">📜 Export</a>
                </div>
            </div>

            <div class="hero-stats">
                <div class="hero-stat-box">
                    <div class="icon">👨‍🎓</div>
                    <div><div class="val">${totalStudents}</div><div class="lbl">Total Students</div></div>
                </div>
                <div class="hero-stat-box">
                    <div class="icon">👥</div>
                    <div><div class="val">${totalUsers}</div><div class="lbl">Staff Members</div></div>
                </div>
                <div class="hero-stat-box">
                    <div class="icon">💼</div>
                    <div><div class="val">PKR ${fin.totalFees.toLocaleString()}</div><div class="lbl">Fees (${esc(month)})</div></div>
                </div>
                <div class="hero-stat-box">
                    <div class="icon">📲</div>
                    <div><div class="val">PKR ${(fin.totalExpenses + fin.totalSalaries + fin.partnerCost).toLocaleString()}</div><div class="lbl">Expenses (${esc(month)})</div></div>
                </div>
            </div>
        </div>

        <div class="quick-actions no-print">
            <a href="/student-register" class="qa-btn"><div class="icon">👨‍🎓</div> Add Student</a>${superActions}
            <a href="/manage-users" class="qa-btn"><div class="icon">👥</div> Add Staff</a>${superActions2}
            <a href="/certificates" class="qa-btn"><div class="icon">🏆</div> Certificates</a>${superActions3}
        </div>

        <div class="stats-grid-modern">
            <div class="stat-card-modern">
                <div class="top"><div class="icon-box">🎓</div><div class="line"></div></div>
                <div class="title">Enrolled Students</div>
                <div class="value">${totalStudents}</div>
                <div class="sub"><span style="color:#ef4444;">${pendingStudents} pending</span> approvals</div>
            </div>
            <div class="stat-card-modern">
                <div class="top"><div class="icon-box">👥</div><div class="line"></div></div>
                <div class="title">Total Staff</div>
                <div class="value">${totalUsers}</div>
                <div class="sub">Across all branches</div>
            </div>
            <div class="stat-card-modern">
                <div class="top"><div class="icon-box">📈</div><div class="line"></div></div>
                <div class="title">Staff Salaries</div>
                <div class="value">PKR ${totalSalaries.toLocaleString()}</div>
                <div class="sub">Monthly fixed</div>
            </div>
            <div class="stat-card-modern" style="border:2px solid ${currentTheme.icon}; background:${currentTheme.bgLight};">
                <div class="top"><div class="icon-box" style="background:white;">📊</div><div class="line"></div></div>
                <div class="title" style="color:${currentTheme.text};">Net Profit / Loss</div>
                <div class="value" style="color:${fin.net >= 0 ? '#047857' : '#b91c1c'};">PKR ${fin.net.toLocaleString()}</div>
                <div class="sub" style="color:${currentTheme.text};">For ${esc(month)}</div>
            </div>
        </div>

        <div class="graph-container no-print">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h3 style="margin:0;">📉 Income vs Expense (Last 6 Months)</h3>
                <span style="font-size:12px; color:#64748b;"><span style="color:${currentTheme.icon};">◉</span> Income &nbsp; <span style="color:#ef4444;">◉</span> Expense</span>
            </div>
            <div class="graph-bars">
                ${graphHtml}
            </div>
        </div>
        ${superCards}
    `;

    res.send(renderDashboard(user, content, 'dashboard'));
}));
app.get('/login', (req, res) => {
    res.send(publicHeaderFooter(`
        <div style="display:flex; justify-content:center; align-items:center; min-height:80vh; background:#f1f5f9; padding:40px;">
            <div style="background:white; padding:40px; border-radius:20px; box-shadow:0 10px 30px rgba(0,0,0,0.08); width:100%; max-width:450px; text-align:center;">
                <img src="/Ioch-wb.png" style="height:80px; margin-bottom:20px;" alt="IOCH Logo">
                <h2 style="margin-bottom:20px;">Portal Login</h2>
                <form action="/login" method="POST">
                    <div class="form-group"><label>Email / Username</label><input type="text" name="username" required></div>
                    <div class="form-group"><label>Password</label><input type="password" name="password" required></div>
                    <button type="submit" class="btn btn-primary" style="width:100%; border-radius:10px; padding:15px; font-size:1.1rem;">Log in</button>
                </form>
                <div style="margin-top:20px; font-size:0.9rem; color:#64748b;">Student? <a href="/student-register" style="color:var(--primary); font-weight:bold;">Create an account here</a></div>
            </div>
        </div>`));
});

const loginFail = (msg) => `<h3 style='text-align:center; margin-top:50px;'>${msg} <a href='/login'>Try again</a></h3>`;

app.post('/login', loginLimiter, wrap(async (req, res) => {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const ip = getIp(req);
    const device = req.headers['user-agent'];

    const user = await dbGet("SELECT * FROM users WHERE lower(username) = lower(?) OR lower(email) = lower(?)", [username, username]);
    if (!user) return studentLogin(req, res, username, password);

    if (!user.password || !(await bcrypt.compare(password, user.password))) return res.send(loginFail('Wrong Password!'));
    if (user.account_status === 'Suspended') return res.send("<h3 style='text-align:center; margin-top:50px; color:red;'>Account suspended. Contact admin.</h3>");

    if (!user.ip_address) await dbRun(`UPDATE users SET ip_address = ?, device_info = ? WHERE id = ?`, [ip, device, user.id]);

    if (user.role !== 'SuperAdmin' && user.status === 'Pending') {
        clearLoginAttempts(req);
        await startSession(req, { pendingUserId: user.id });
        return res.redirect(`/complete-profile/${user.id}`);
    }
    if (user.role !== 'SuperAdmin' && user.status === 'Pending Review') {
        return res.send("<h3 style='text-align:center; margin-top:50px; color:#f59e0b;'>Aapka profile admin review mein hai. Approval ke baad login kar sakenge.</h3>");
    }
    clearLoginAttempts(req);
    await startSession(req, { user: { id: user.id, name: user.name, email: user.email, role: user.role, branch: user.branch } });
    res.redirect('/dashboard');
}));
async function studentLogin(req, res, username, password) {
    const notFound = loginFail('User not found!');
    const st = await dbGet("SELECT * FROM students WHERE lower(email) = lower(?)", [username]);
    if (!st) return res.send(notFound);

    const hash = st.custom_password || st.password;
    const ok = hash ? await bcrypt.compare(password, hash) : false;
    if (!ok) return res.send(notFound);
    
    // Status Checks (Pending aur Suspended)
    if (st.status === 'Pending') {
        return res.send("<h3 style='text-align:center; margin-top:50px; color:#f59e0b;'>Aapka account abhi admin approval ka intezar kar raha hai.</h3>");
    }
    
    if (st.status === 'Suspended') {
        return res.send("<h3 style='text-align:center; margin-top:50px; color:#ef4444;'>Aapka account suspend kar diya gaya hai. Baraye meharbani admin se rabta karein.</h3>");
    }

    await dbRun(`UPDATE students SET last_login = ? WHERE id = ?`, [`${nowStr()} (IP: ${getIp(req)})`, st.id]);
    clearLoginAttempts(req);
    await startSession(req, { user: { id: st.id, name: st.first_name + ' ' + st.surname, email: st.email, role: 'Student', branch: st.branch || 'Online' } });
    res.redirect('/dashboard');
}
async function studentLogin(req, res, username, password) {
    const notFound = loginFail('User not found!');
    const st = await dbGet("SELECT * FROM students WHERE lower(email) = lower(?)", [username]);
    if (!st) return res.send(notFound);

    const hash = st.custom_password || st.password;
    const ok = hash ? await bcrypt.compare(password, hash) : false;
    if (!ok) return res.send(notFound);
    async function studentLogin(req, res, username, password) {
    const notFound = loginFail('User not found!');
    const st = await dbGet("SELECT * FROM students WHERE lower(email) = lower(?)", [username]);
    if (!st) return res.send(notFound);

    const hash = st.custom_password || st.password;
    const ok = hash ? await bcrypt.compare(password, hash) : false;
    if (!ok) return res.send(notFound);
    
    // 👇 YAHAN CHECK LAGAYA HAI 👇
    if (st.status === 'Pending') return res.send("<h3 style='text-align:center; margin-top:50px; color:#f59e0b;'>Aapka account abhi admin approval ka intezar kar raha hai.</h3>");
    if (st.status === 'Suspended') return res.send("<h3 style='text-align:center; margin-top:50px; color:#ef4444;'>Aapka account suspend kar diya gaya hai. Baraye meharbani admin se rabta karein.</h3>");
    // 👆 YAHAN TAK 👆

    await dbRun(`UPDATE students SET last_login = ? WHERE id = ?`, [`${nowStr()} (IP: ${getIp(req)})`, st.id]);
    clearLoginAttempts(req);
    await startSession(req, { user: { id: st.id, name: st.first_name + ' ' + st.surname, email: st.email, role: 'Student', branch: st.branch || 'Online' } });
    res.redirect('/dashboard');
}
if (st.status === 'Suspended') return res.send("<h3 style='text-align:center; margin-top:50px; color:#ef4444;'>Aapka account suspend kar diya gaya hai. Baraye meharbani admin se rabta karein.</h3>");

    await dbRun(`UPDATE students SET last_login = ? WHERE id = ?`, [`${nowStr()} (IP: ${getIp(req)})`, st.id]);
    clearLoginAttempts(req);
    await startSession(req, { user: { id: st.id, name: st.first_name + ' ' + st.surname, email: st.email, role: 'Student', branch: st.branch || 'Online' } });
    res.redirect('/dashboard');
}

app.get('/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });

// ================= COMPLETE PROFILE (staff) =================
const ownsPendingProfile = (req, res, next) => {
    if (!req.session.pendingUserId || String(req.session.pendingUserId) !== String(req.params.id)) return res.redirect('/login');
    next();
};

app.get('/complete-profile/:id', ownsPendingProfile, wrap(async (req, res) => {
    const user = await dbGet("SELECT * FROM users WHERE id = ?", [req.params.id]);
    if (!user) return res.redirect('/login');
    res.send(publicHeaderFooter(`
        <div class="card" style="max-width: 800px; margin: 40px auto; width:95%;">
            <div class="card-header" style="background:#fef3c7; color:#92400e;">Action Required: Complete Profile</div>
            <div class="card-body">
                <form action="/complete-profile/${user.id}" method="POST" enctype="multipart/form-data">
                    <div class="form-group"><label>CNIC Number</label><input type="text" name="cnic" value="${esc(user.cnic || '')}" required></div>
                    <div class="grid-3">
                        <div class="file-upload-box"><input type="file" name="cnic_front" required><label>📫 CNIC Front</label></div>
                        <div class="file-upload-box"><input type="file" name="cnic_back" required><label>📫 CNIC Back</label></div>
                        <div class="file-upload-box"><input type="file" name="agreement_doc" required><label>✍️ Agreement</label></div>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width:100%; margin-top:30px;">Submit</button>
                </form>
            </div>
        </div>`));
}));

app.post('/complete-profile/:id', ownsPendingProfile, upload.fields([{ name: 'cnic_front', maxCount: 1 }, { name: 'cnic_back', maxCount: 1 }, { name: 'agreement_doc', maxCount: 1 }]), wrap(async (req, res) => {
    const files = req.files || {};
    const fn = k => files[k] ? files[k][0].filename : null;
    await dbRun(`UPDATE users SET cnic=?, cnic_front=?, cnic_back=?, agreement_doc=?, status='Pending Review' WHERE id=?`,
        [req.body.cnic, fn('cnic_front'), fn('cnic_back'), fn('agreement_doc'), req.params.id]);
    delete req.session.pendingUserId;
    res.send(`<div style="text-align:center; padding:50px;"><h2>✔️ Submitted!</h2><p>Pending admin approval.</p><a href="/login">Login</a></div>`);
}));

// ================= STUDENT REGISTRATION =================
const EDIT_FILES = ['photo', 'id_front', 'id_back', 'qualification_upload', 'fee_slip_upload'];
const editUpload = upload.fields(EDIT_FILES.map(name => ({ name, maxCount: 1 })));
// ======================= STUDENTS LIST =======================
const monthOfStudent = s => { const m = /^(\d{2})\/(\d{2})\/(\d{4})/.exec(s.declaration_date || ''); return m ? `${m[3]}-${m[2]}` : 'Unknown'; };
const monthLabel = m => { const p = m.split('-'); return p.length === 2 && p[0] !== 'Unknown' ? new Date(Number(p[0]), Number(p[1]) - 1, 1).toLocaleString('en-GB', { month: 'long', year: 'numeric' }) : m; };

app.get('/students', requireRole('SuperAdmin', 'Admin', 'Tutor'), wrap(async (req, res) => {
    const user = req.session.user;
    let query = "SELECT * FROM students", params = [];
    if (user.role === 'Admin') { query += " WHERE branch = ? OR branch IS NULL"; params.push(user.branch); }
    if (user.role === 'Tutor') { query += " WHERE assigned_tutor = ?"; params.push(user.name); }
    query += " ORDER BY id DESC";
    const all = await dbAll(query, params);

    const counts = {};
    all.forEach(s => { const m = monthOfStudent(s); counts[m] = (counts[m] || 0) + 1; });
    const months = Object.keys(counts).sort().reverse();
    const sel = req.query.month && counts[req.query.month] ? req.query.month : 'all';
    const students = sel === 'all' ? all : all.filter(s => monthOfStudent(s) === sel);

    const chips = [`<a href="/students?month=all" class="btn ${sel === 'all' ? 'btn-primary' : 'btn-outline'}" style="margin:0 6px 6px 0;">All (${all.length})</a>`]
        .concat(months.map(m => `<a href="/students?month=${encodeURIComponent(m)}" class="btn ${sel === m ? 'btn-primary' : 'btn-outline'}" style="margin:0 6px 6px 0;">${esc(monthLabel(m))} (${counts[m]})</a>`)).join('');

    const rows = students.map(s => {
        const dateStr = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: '2-digit' }).replace(/\//g, '');
        const docNo = `IOCH-${String(s.id).padStart(2, '0')}-${dateStr}`;
        
        let statusColor = '#fef3c7'; // Pending
        let statusTextColor = '#92400e';
        let statusDot = '#f59e0b';
        if (s.status === 'Active') { statusColor = '#ecfdf5'; statusTextColor = '#047857'; statusDot = '#10b981'; }
        if (s.status === 'Suspended') { statusColor = '#fef2f2'; statusTextColor = '#b91c1c'; statusDot = '#ef4444'; }

        let suspendBtn = '';
        if (s.status !== 'Pending' && user.role === 'SuperAdmin') {
            const btnText = s.status === 'Suspended' ? 'Activate' : 'Suspend';
            const btnIcon = s.status === 'Suspended' ? '🔄' : '🚫';
            const btnColor = s.status === 'Suspended' ? '#10b981' : '#ef4444';
            const confirmMsg = s.status === 'Suspended' ? 'Student ko wapas active karna hai?' : 'Student ko suspend karna hai? Uska login band ho jayega.';
            suspendBtn = `<form action="/toggle-suspend/${s.id}" method="POST" style="display:inline;" onsubmit="return confirm('${confirmMsg}')"><button type="submit" style="background:${btnColor}15; color:${btnColor}; border:1px solid ${btnColor}40; padding:6px 12px; border-radius:6px; font-size:12px; font-weight:600; cursor:pointer; transition:0.2s;">${btnIcon} ${btnText}</button></form>`;
        }

        return `
        <tr style="border-bottom:1px solid #f1f5f9; transition:background 0.2s;" onmouseover="this.style.background='#f8fafc'" onmouseout="this.style.background='transparent'">
            <td style="padding:16px 20px;">
                <div style="display:flex; align-items:center; gap:14px;">
                    ${s.photo ? `<img src="${IMG(s.photo)}" style="width:44px; height:44px; border-radius:10px; object-fit:cover; box-shadow:0 2px 5px rgba(0,0,0,0.1);">` : `<div style="width:44px; height:44px; border-radius:10px; background:#e2e8f0; color:#64748b; font-size:20px; display:flex; align-items:center; justify-content:center;">👤</div>`}
                    <div>
                        <div style="font-weight:700; color:#0f172a; font-size:14px;">${esc(s.first_name)} ${esc(s.surname)}</div>
                        <div style="font-size:11px; color:#64748b; margin-top:2px; font-family:monospace;">${docNo}</div>
                    </div>
                </div>
            </td>
            <td style="padding:16px 20px; font-size:13px; color:#475569; font-weight:500;">${esc(monthLabel(monthOfStudent(s)))}</td>
            <td style="padding:16px 20px;"><div style="font-size:13px; color:#334155; max-width:200px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${esc(s.course)}">${esc(s.course || '-')}</div></td>
            <td style="padding:16px 20px; font-size:13px; color:#475569; font-weight:500;">${esc(s.contact || '-')}</td>
            <td style="padding:16px 20px;">
                <span style="display:inline-flex; align-items:center; gap:6px; background:${statusColor}; color:${statusTextColor}; padding:4px 10px; border-radius:20px; font-size:11px; font-weight:700; letter-spacing:0.5px;">
                    <span style="width:6px; height:6px; border-radius:50%; background:${statusDot};"></span>
                    ${esc(s.status || 'Pending').toUpperCase()}
                </span>
            </td>
            <td style="padding:16px 20px;">
                               <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
                    <a href="/student/${s.id}" style="background:#eff6ff; color:#3b82f6; border:1px solid #bfdbfe; padding:6px 12px; border-radius:6px; font-size:12px; font-weight:600; text-decoration:none; transition:0.2s;" onmouseover="this.style.background='#dbeafe'" onmouseout="this.style.background='#eff6ff'">👁️ View</a>
                    
                    <!-- NAYA BUTTON YAHAN ADD HUA HAI -->
                    <a href="/student/${s.id}/documents" style="background:#ecfdf5; color:#059669; border:1px solid #10b981; padding:6px 12px; border-radius:6px; font-size:12px; font-weight:600; text-decoration:none; transition:0.2s;" onmouseover="this.style.background='#d1fae5'" onmouseout="this.style.background='#ecfdf5'">📂 Docs</a>
                    <!-- NAYA BUTTON KHATAM -->
                    
                    ${user.role === 'SuperAdmin' ? `
                        <a href="/student/${s.id}/edit" style="background:#fffbeb; color:#d97706; border:1px solid #fde68a; padding:6px 12px; border-radius:6px; font-size:12px; font-weight:600; text-decoration:none; transition:0.2s;" onmouseover="this.style.background='#fef3c7'" onmouseout="this.style.background='#fffbeb'">✏️ Edit</a>
                        
                        ${suspendBtn}
                        
                        <form action="/delete-student/${s.id}" method="POST" style="display:inline;" onsubmit="return confirm('Student ka poora record delete ho jayega. Pakka?')">
                            <button type="submit" style="background:#fef2f2; color:#ef4444; border:1px solid #fecaca; padding:6px 12px; border-radius:6px; font-size:12px; font-weight:600; cursor:pointer; transition:0.2s;" onmouseover="this.style.background='#fee2e2'" onmouseout="this.style.background='#fef2f2'">🗑️ Delete</button>
                        </form>
                    ` : ''}
                </div>
            </td>
        </tr>`;
    }).join('');

    const topBox = ['SuperAdmin', 'Admin'].includes(user.role) ? `
        <div style="display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px;">
            <a href="/export-students" style="background:white; border:1px solid #cbd5e1; color:#0f172a; padding:10px 20px; border-radius:8px; font-size:14px; font-weight:600; text-decoration:none; display:inline-flex; align-items:center; gap:8px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">📤 Export CSV</a>
            ${user.role === 'SuperAdmin' ? '<a href="/card-settings" style="background:white; border:1px solid #cbd5e1; color:#0f172a; padding:10px 20px; border-radius:8px; font-size:14px; font-weight:600; text-decoration:none; display:inline-flex; align-items:center; gap:8px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">🆔 Card Settings</a>' : ''}
        </div>` : '';

    res.send(renderDashboard(user, `
        ${topBox}
        
        <div style="background:white; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.03); border:1px solid #e2e8f0; margin-bottom:20px; padding:20px;">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:15px; flex-wrap:wrap; gap:10px;">
                <h3 style="margin:0; font-size:16px; color:#0f172a; display:flex; align-items:center; gap:8px;"><span style="font-size:20px;">📅</span> Filter by Month</h3>
            </div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">${chips}</div>
        </div>

        <div style="background:white; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.03); border:1px solid #e2e8f0; overflow:hidden;">
            <div style="padding:20px; border-bottom:1px solid #e2e8f0; display:flex; justify-content:space-between; align-items:center;">
                <h3 style="margin:0; font-size:16px; color:#0f172a; display:flex; align-items:center; gap:8px;"><span style="font-size:20px;">🎓</span> Students List ${sel === 'all' ? '(All)' : ' - ' + esc(monthLabel(sel))}</h3>
                <span style="background:#f1f5f9; color:#475569; padding:4px 12px; border-radius:20px; font-size:12px; font-weight:700;">Total: ${students.length}</span>
            </div>
            <div style="overflow-x:auto;">
                <table style="width:100%; border-collapse:collapse; text-align:left;">
                    <thead style="background:#f8fafc; border-bottom:2px solid #e2e8f0;">
                        <tr>
                            <th style="padding:14px 20px; font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:0.5px;">Student</th>
                            <th style="padding:14px 20px; font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:0.5px;">Month</th>
                            <th style="padding:14px 20px; font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:0.5px;">Course</th>
                            <th style="padding:14px 20px; font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:0.5px;">Contact</th>
                            <th style="padding:14px 20px; font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:0.5px;">Status</th>
                            <th style="padding:14px 20px; font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:0.5px;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows || "<tr><td colspan='6' style='text-align:center; padding:40px; color:#64748b;'>No students found.</td></tr>"}
                    </tbody>
                </table>
            </div>
        </div>
    `, 'students'));
}));
// Card Render Function (Jo neechay diya gaya hai)
// ======================= STUDENT DETAILS & EXPORT =======================
app.post('/toggle-suspend/:id', requireRole('SuperAdmin', 'Admin'), wrap(async (req, res) => {
    const s = await dbGet("SELECT status FROM students WHERE id = ?", [req.params.id]);
    if (s) {
        const newStatus = s.status === 'Suspended' ? 'Active' : 'Suspended';
        await dbRun("UPDATE students SET status = ? WHERE id = ?", [newStatus, req.params.id]);
    }
    res.redirect('/student/' + req.params.id);
}));

app.post('/validate-student/:id', requireRole('SuperAdmin', 'Admin'), wrap(async (req, res) => {
    const s = await dbGet("SELECT is_validated FROM students WHERE id = ?", [req.params.id]);
    if (s) {
        const newVal = s.is_validated ? 0 : 1;
        await dbRun("UPDATE students SET is_validated = ? WHERE id = ?", [newVal, req.params.id]);
    }
    res.redirect('/student/' + req.params.id);
}));

app.post('/approve-student/:id', requireRole('SuperAdmin', 'Admin'), wrap(async (req, res) => {
    const st = await dbGet("SELECT * FROM students WHERE id = ?", [req.params.id]);
    if (!st) return res.send("Student not found.");
    if (!canManageStudent(req.session.user, st)) return res.status(403).send('Access Denied');
    
    if (st.status === 'Pending') {
        const tempPass = 'Ioch@' + crypto.randomInt(100000, 1000000);
        const hashed = await bcrypt.hash(tempPass, 10);
        
        // Tutor name agar select kiya gaya hai
        const tutorName = req.body.tutor_name || null;
        
        await dbRun(`UPDATE students SET status = 'Active', password = ?, temp_password = ?, assigned_tutor = ? WHERE id = ?`, [hashed, tempPass, tutorName, st.id]);
        
        console.log(`\n📧 Student approved: ${st.email} | Temp Password: ${tempPass}\n`);
    }
    res.redirect('/student/' + st.id);
}));
app.post('/toggle-suspend/:id', requireRole('SuperAdmin', 'Admin'), wrap(async (req, res) => {
    const s = await dbGet("SELECT status FROM students WHERE id = ?", [req.params.id]);
    if (s) {
        const newStatus = s.status === 'Suspended' ? 'Active' : 'Suspended';
        await dbRun("UPDATE students SET status = ? WHERE id = ?", [newStatus, req.params.id]);
    }
    res.redirect('/student/' + req.params.id);
}));

app.post('/validate-student/:id', requireRole('SuperAdmin', 'Admin'), wrap(async (req, res) => {
    const s = await dbGet("SELECT is_validated FROM students WHERE id = ?", [req.params.id]);
    if (s) {
        const newVal = s.is_validated ? 0 : 1;
        await dbRun("UPDATE students SET is_validated = ? WHERE id = ?", [newVal, req.params.id]);
    }
    res.redirect('/student/' + req.params.id);
}));

app.post('/approve-student/:id', requireRole('SuperAdmin', 'Admin'), wrap(async (req, res) => {
    const st = await dbGet("SELECT * FROM students WHERE id = ?", [req.params.id]);
    if (!st) return res.send("Student not found.");
    if (!canManageStudent(req.session.user, st)) return res.status(403).send('Access Denied');
    
    if (st.status === 'Pending') {
        const tempPass = 'Ioch@' + crypto.randomInt(100000, 1000000);
        const hashed = await bcrypt.hash(tempPass, 10);
        
        // Tutor name agar select kiya gaya hai
        const tutorName = req.body.tutor_name || null;
        
        await dbRun(`UPDATE students SET status = 'Active', password = ?, temp_password = ?, assigned_tutor = ? WHERE id = ?`, [hashed, tempPass, tutorName, st.id]);
        
        console.log(`\n📧 Student approved: ${st.email} | Temp Password: ${tempPass}\n`);
    }
    res.redirect('/student/' + st.id);
}));
const canAccessStudent = (user, s) =>
    user.role === 'SuperAdmin' ||
    (user.role === 'Admin' && (!s.branch || s.branch === user.branch)) ||
    (user.role === 'Tutor' && s.assigned_tutor === user.name);
const canManageStudent = (user, s) => user.role === 'SuperAdmin' || (user.role === 'Admin' && (!s.branch || s.branch === user.branch));

// ======================= HELPER FUNCTION (Card Render) =======================
function renderCardInline(s, cfg) {
    const bg = cfg.card_bg ? `background:url('${IMG(cfg.card_bg)}') center/cover no-repeat;` : 'background:linear-gradient(135deg,#ecfdf5,#ffffff);';
    const chip = (f, alt) => f ? `<img src="${IMG(f)}" alt="${alt}" style="height:24px; background:white; padding:2px 4px; border-radius:4px; object-fit:contain;">` : '';
    const photo = s.photo
        ? `<img src="${IMG(s.photo)}" style="width:80px; height:100px; object-fit:cover; border-radius:6px; border:2px solid #047857; background:white;">`
        : `<div style="width:80px; height:100px; border-radius:6px; border:2px solid #047857; background:#d1fae5; color:#047857; font-size:30px; font-weight:bold; display:flex; align-items:center; justify-content:center;">${esc((s.first_name || '?').charAt(0))}</div>`;
    
    return `
    <div style="width:380px; height:240px; border-radius:14px; border:1px solid #94a3b8; overflow:hidden; position:relative; margin:0 auto; text-align:left; font-family:Arial,sans-serif; box-shadow:0 6px 18px rgba(0,0,0,0.15); ${bg} -webkit-print-color-adjust:exact; print-color-adjust:exact;">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(6,78,59,0.95); height:40px;">
            <img src="/Ioch-wb.png" alt="IOCH" style="height:26px; background:white; padding:2px 4px; border-radius:4px;">
            <div style="color:white; font-size:11px; font-weight:bold; letter-spacing:1px;">LEARNER CARD</div>
            <div style="display:flex; gap:4px;">${chip(cfg.logo_nebosh, 'NEBOSH')}${chip(cfg.logo_partner, 'Learner Partner')}</div>
        </div>
        <div style="display:flex; gap:12px; padding:12px; background:rgba(255,255,255,0.85); height:170px; overflow:hidden;">
            ${photo}
            <div style="flex:1; min-width:0; line-height:1.3;">
                <div style="font-size:9px; color:#475569; font-weight:bold;">NAME</div>
                <div style="font-size:12px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.first_name + ' ' + s.surname)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">COURSE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.course)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">PHONE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.contact)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">EMAIL</div>
                <div style="font-size:10px; font-weight:bold; color:#0f172a; word-break:break-word;">${esc(s.email)}</div>
            </div>
        </div>
        <div style="position:absolute; bottom:0; left:0; right:0; display:flex; justify-content:space-between; padding:6px 10px; background:rgba(6,78,59,0.95); color:white; font-size:10px;">
            <span>Card No: <b>${esc(s.card_no || 'Pending')}</b></span><span>Issued: ${esc(s.card_issued || 'N/A')}</span><span>${esc(cfg.card_footer || 'ioch.org.pk')}</span>
        </div>
    </div>`;
}
// Helper to render card
function renderCardInline(s, cfg) {
    const bg = cfg.card_bg ? `background:url('${IMG(cfg.card_bg)}') center/cover no-repeat;` : 'background:linear-gradient(135deg,#ecfdf5,#ffffff);';
    const chip = (f, alt) => f ? `<img src="${IMG(f)}" alt="${alt}" style="height:24px; background:white; padding:2px 4px; border-radius:4px; object-fit:contain;">` : '';
    const photo = s.photo
        ? `<img src="${IMG(s.photo)}" style="width:80px; height:100px; object-fit:cover; border-radius:6px; border:2px solid #047857; background:white;">`
        : `<div style="width:80px; height:100px; border-radius:6px; border:2px solid #047857; background:#d1fae5; color:#047857; font-size:30px; font-weight:bold; display:flex; align-items:center; justify-content:center;">${esc((s.first_name || '?').charAt(0))}</div>`;
    
    return `
    <div style="width:380px; height:240px; border-radius:14px; border:1px solid #94a3b8; overflow:hidden; position:relative; margin:0 auto; text-align:left; font-family:Arial,sans-serif; box-shadow:0 6px 18px rgba(0,0,0,0.15); ${bg} -webkit-print-color-adjust:exact; print-color-adjust:exact;">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(6,78,59,0.95); height:40px;">
            <img src="/Ioch-wb.png" alt="IOCH" style="height:26px; background:white; padding:2px 4px; border-radius:4px;">
            <div style="color:white; font-size:11px; font-weight:bold; letter-spacing:1px;">LEARNER CARD</div>
            <div style="display:flex; gap:4px;">${chip(cfg.logo_nebosh, 'NEBOSH')}${chip(cfg.logo_partner, 'Learner Partner')}</div>
        </div>
        <div style="display:flex; gap:12px; padding:12px; background:rgba(255,255,255,0.85); height:170px; overflow:hidden;">
            ${photo}
            <div style="flex:1; min-width:0; line-height:1.3;">
                <div style="font-size:9px; color:#475569; font-weight:bold;">NAME</div>
                <div style="font-size:12px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.first_name + ' ' + s.surname)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">COURSE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.course)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">PHONE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.contact)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">EMAIL</div>
                <div style="font-size:10px; font-weight:bold; color:#0f172a; word-break:break-word;">${esc(s.email)}</div>
            </div>
        </div>
        <div style="position:absolute; bottom:0; left:0; right:0; display:flex; justify-content:space-between; padding:6px 10px; background:rgba(6,78,59,0.95); color:white; font-size:10px;">
            <span>Card No: <b>${esc(s.card_no || 'Pending')}</b></span><span>Issued: ${esc(s.card_issued || 'N/A')}</span><span>${esc(cfg.card_footer || 'ioch.org.pk')}</span>
        </div>
    </div>`;
}app.post('/student/:id/edit', requireRole('SuperAdmin'), editUpload, wrap(async (req, res) => {
    const s = await dbGet("SELECT * FROM students WHERE id = ?", [req.params.id]);
    const f = req.files || {};
    const discard = () => Object.values(f).forEach(a => safeUnlink(a[0].filename));
    if (!s) { discard(); return res.send('Student not found.'); }
    const b = req.body;
    b.email = String(b.email || '').trim().toLowerCase();
    const dup = await dbGet("SELECT id FROM students WHERE lower(email) = lower(?) AND id != ?", [b.email, s.id]);
    if (dup) { discard(); return res.send("Yeh email kisi aur student ke paas hai. <a href='javascript:history.back()'>Back</a>"); }
    if (f.photo && !isImg(f.photo[0].filename)) { discard(); return res.send("Photo sirf JPG / PNG / WEBP honi chahiye. <a href='javascript:history.back()'>Back</a>"); }

    const x = parseExtra(s.device_info);
    const info = `Location: ${cleanPipe(x['Location'] || 'Unknown')} | Device: ${cleanPipe(x['Device'] || '')} | Title: ${cleanPipe(b.title)} | Reason: ${cleanPipe(b.course_reason)} | Mode: ${cleanPipe(b.mode_of_learning)} | Paid By: ${cleanPipe(b.paid_by)} | Bank: ${cleanPipe(b.bank_selected)} | English: ${cleanPipe(b.english_level)} | CourseDate: ${cleanPipe(b.course_date)} | DeclName: ${cleanPipe(b.declaration_name)}`;

    const cols = ['first_name', 'surname', 'gender', 'dob', 'nationality', 'contact', 'email', 'address', 'city', 'postal_code', 'country', 'course', 'fee_amount', 'qualification', 'id_type', 'id_number', 'mode_of_learning'];
    const vals = cols.map(c => b[c] == null ? null : b[c]);
    cols.push('branch'); vals.push(b.branch || null);
    cols.push('device_info'); vals.push(info);
    EDIT_FILES.forEach(n => { if (f[n]) { cols.push(n); vals.push(f[n][0].filename); safeUnlink(s[n]); } });
    await dbRun(`UPDATE students SET ${cols.map(c => c + ' = ?').join(', ')} WHERE id = ?`, [...vals, s.id]);
    res.redirect('/student/' + s.id);
}));

// ================= DELETE STUDENT =================
app.post('/delete-student/:id', requireRole('SuperAdmin'), wrap(async (req, res) => {
    const s = await dbGet("SELECT * FROM students WHERE id = ?", [req.params.id]);
    if (s) {
        ['photo', 'id_front', 'id_back', 'qualification_upload', 'fee_slip_upload', 'chat_upload', 'resit_result_upload'].forEach(k => safeUnlink(s[k]));
        await dbRun("DELETE FROM students WHERE id = ?", [s.id]);
    }
    res.redirect('/students');
}));
// ================= STUDENT DETAILS & REGISTRATION (FINAL) =================

// 1. Student Details & Export
function renderCardInline(s, cfg) {
    const bg = cfg.card_bg ? `background:url('${IMG(cfg.card_bg)}') center/cover no-repeat;` : 'background:linear-gradient(135deg,#ecfdf5,#ffffff);';
    const chip = (f, alt) => f ? `<img src="${IMG(f)}" alt="${alt}" style="height:24px; background:white; padding:2px 4px; border-radius:4px; object-fit:contain;">` : '';
    const photo = s.photo
        ? `<img src="${IMG(s.photo)}" style="width:80px; height:100px; object-fit:cover; border-radius:6px; border:2px solid #047857; background:white;">`
        : `<div style="width:80px; height:100px; border-radius:6px; border:2px solid #047857; background:#d1fae5; color:#047857; font-size:30px; font-weight:bold; display:flex; align-items:center; justify-content:center;">${esc((s.first_name || '?').charAt(0))}</div>`;
    
    return `
    <div style="width:380px; height:240px; border-radius:14px; border:1px solid #94a3b8; overflow:hidden; position:relative; margin:0 auto; text-align:left; font-family:Arial,sans-serif; box-shadow:0 6px 18px rgba(0,0,0,0.15); ${bg} -webkit-print-color-adjust:exact; print-color-adjust:exact;">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(6,78,59,0.95); height:40px;">
            <img src="/Ioch-wb.png" alt="IOCH" style="height:26px; background:white; padding:2px 4px; border-radius:4px;">
            <div style="color:white; font-size:11px; font-weight:bold; letter-spacing:1px;">LEARNER CARD</div>
            <div style="display:flex; gap:4px;">${chip(cfg.logo_nebosh, 'NEBOSH')}${chip(cfg.logo_partner, 'Learner Partner')}</div>
        </div>
        <div style="display:flex; gap:12px; padding:12px; background:rgba(255,255,255,0.85); height:170px; overflow:hidden;">
            ${photo}
            <div style="flex:1; min-width:0; line-height:1.3;">
                <div style="font-size:9px; color:#475569; font-weight:bold;">NAME</div>
                <div style="font-size:12px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.first_name + ' ' + s.surname)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">COURSE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.course)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">PHONE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.contact)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">EMAIL</div>
                <div style="font-size:10px; font-weight:bold; color:#0f172a; word-break:break-word;">${esc(s.email)}</div>
            </div>
        </div>
        <div style="position:absolute; bottom:0; left:0; right:0; display:flex; justify-content:space-between; padding:6px 10px; background:rgba(6,78,59,0.95); color:white; font-size:10px;">
            <span>Card No: <b>${esc(s.card_no || 'Pending')}</b></span><span>Issued: ${esc(s.card_issued || 'N/A')}</span><span>${esc(cfg.card_footer || 'ioch.org.pk')}</span>
        </div>
    </div>`;
}

// 2. Registration Form (GET)
app.get('/student-register', (req, res) => {
    const realTime = nowStr();
    const regContent = `
        <div style="max-width: 900px; margin: 40px auto; background: white; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.08); overflow: hidden; border: 1px solid #e2e8f0;">
            <div style="background: linear-gradient(135deg, #064e3b 0%, #047857 100%); padding: 30px; color: white; text-align: center;">
                <h2 style="font-size: 1.8rem; font-weight: 800; margin-bottom: 5px;">Online Registration</h2>
            </div>
            <div style="padding: 40px;">
                <form action="/student-register" method="POST" enctype="multipart/form-data" id="regForm" onsubmit="return validateForm()">

                    <h4 style="color:var(--primary); margin-bottom:15px; border-bottom:2px solid #eee; padding-bottom:5px;">Step 1: Personal Details</h4>
                    <div class="grid-3">
                        <div class="form-group"><label>Title</label><select name="title"><option>Mr</option><option>Mrs</option><option>Ms</option><option>Dr</option></select></div>
                        <div class="form-group"><label>First Name</label><input type="text" name="first_name" required></div>
                        <div class="form-group"><label>Surname</label><input type="text" name="surname" required></div>
                    </div>
                    <div class="grid-3">
                        <div class="form-group"><label>Gender</label><select name="gender"><option>Male</option><option>Female</option></select></div>
                        <div class="form-group"><label>Date of Birth</label><input type="date" name="dob" required></div>
                        <div class="form-group"><label>Nationality</label><input type="text" name="nationality" required placeholder="e.g. Pakistani"></div>
                    </div>

                    <h4 style="color:var(--primary); margin:30px 0 15px 0; border-bottom:2px solid #eee; padding-bottom:5px;">Step 2: Mailing Address &amp; Contact</h4>
                    <div class="form-group"><label>Address</label><input type="text" name="address" required></div>
                    <div class="grid-3">
                        <div class="form-group"><label>City</label><input type="text" name="city" required></div>
                        <div class="form-group"><label>Postal Code</label><input type="text" name="postal_code" required></div>
                        <div class="form-group"><label>Country</label><input type="text" name="country" required></div>
                    </div>
                    <div class="grid-2">
                        <div class="form-group"><label>Mobile Number</label><input type="text" name="contact" required></div>
                        <div class="form-group"><label>Email Address</label><input type="email" name="email" required></div>
                    </div>

                    <h4 style="color:var(--primary); margin:30px 0 15px 0; border-bottom:2px solid #eee; padding-bottom:5px;">Step 3: Courses</h4>
                    <div class="grid-2">
                        <div class="form-group"><label>Select Course</label><input type="text" name="course" required placeholder="e.g. NEBOSH IGC"></div>
                        <div class="form-group"><label>Reason for taking this Course</label><input type="text" name="course_reason" required></div>
                    </div>
                    <div class="grid-3">
                        <div class="form-group"><label>Exam Date</label><input type="date" name="course_date" required></div>
                        <div class="form-group"><label>Mode of Study</label><select name="mode_of_learning"><option>Virtual Learning on Zoom Meeting</option><option>Classroom</option></select></div>
                        <div class="form-group"><label>Are you a Resit Student?</label><select name="resit" id="resit" onchange="toggleResit()"><option>No</option><option>Yes</option></select></div>
                    </div>

                    <div id="resit_fields" style="display:none; background:#f8fafc; padding:15px; border-radius:8px; border:1px solid #e2e8f0; margin-bottom:20px;">
                        <h5 style="color:var(--primary); margin-bottom:15px;">Resit Details</h5>
                        <div class="grid-2">
                            <div class="form-group"><label>Learner Number</label><input type="text" name="learner_number"></div>
                            <div class="form-group"><label>Institute Name</label><input type="text" name="institute_name"></div>
                        </div>
                        <div class="file-upload-box" style="height:80px;">
                            <input type="file" name="resit_result_upload">
                            <label>📫 Upload Old Result Card</label>
                        </div>
                    </div>

                    <h4 style="color:var(--primary); margin:30px 0 15px 0; border-bottom:2px solid #eee; padding-bottom:5px;">Step 4: Education &amp; Documents</h4>
                    <div class="grid-2">
                        <div class="form-group"><label>Highest Qualification</label><input type="text" name="qualification" required></div>
                        <div class="form-group"><label>English Language Proficiency</label><select name="english_level"><option>Beginner</option><option>Intermediate</option><option>Advanced</option></select></div>
                    </div>
                    <div class="file-upload-box" style="height:100px; display:flex; flex-direction:column; justify-content:center;">
                        <input type="file" name="qualification_upload" required>
                        <label>📐 Upload Last Degree / Certificate</label>
                    </div>

                    <h4 style="color:var(--primary); margin:30px 0 15px 0; border-bottom:2px solid #eee; padding-bottom:5px;">Step 5: Identification Documents</h4>
                    <div class="form-group">
                        <label>Select ID Document Type</label>
                        <select name="id_type" id="id_type" onchange="toggleIdFields()" required style="border-color:var(--primary);">
                            <option value="">Select...</option>
                            <option value="Passport">Passport</option>
                            <option value="National Identification Card">National Identification Card</option>
                        </select>
                    </div>

                    <div id="photo_box" class="file-upload-box" style="display:none; height:100px; flex-direction:column; justify-content:center; margin-bottom:15px;">
                        <input type="file" name="photo" id="photo_input" accept="image/*">
                        <label>📳 Recent Passport-size Photo (Student Card ke liye)</label>
                    </div>

                    <div id="passport_fields" style="display:none; background:#f8fafc; padding:15px; border-radius:8px; border:1px solid #e2e8f0;">
                        <div class="form-group"><label>Passport Number</label><input type="text" name="passport_no"></div>
                        <div class="grid-2" style="margin-top:15px;">
                            <div class="file-upload-box" style="height:100px; display:flex; flex-direction:column; justify-content:center;">
                                <input type="file" name="passport_front">
                                <label>🛂 Passport First Page</label>
                            </div>
                            <div class="file-upload-box" style="height:100px; display:flex; flex-direction:column; justify-content:center;">
                                <input type="file" name="passport_back">
                                <label>🛂 Passport Second Page</label>
                            </div>
                        </div>
                    </div>

                    <div id="cnic_fields" style="display:none; background:#f8fafc; padding:15px; border-radius:8px; border:1px solid #e2e8f0;">
                        <div class="form-group"><label>National Identification Card Number</label><input type="text" name="cnic_no"></div>
                        <div class="grid-2" style="margin-top:15px;">
                            <div class="file-upload-box" style="height:100px; display:flex; flex-direction:column; justify-content:center;">
                                <input type="file" name="cnic_front">
                                <label>🪪 National ID Card Front Side</label>
                            </div>
                            <div class="file-upload-box" style="height:100px; display:flex; flex-direction:column; justify-content:center;">
                                <input type="file" name="cnic_back">
                                <label>🪪 National ID Card Back Side</label>
                            </div>
                        </div>
                    </div>

                    <h4 style="color:var(--primary); margin:30px 0 15px 0; border-bottom:2px solid #eee; padding-bottom:5px;">Step 6: Payment Proof</h4>

                    <div style="background:#f8fafc; padding:20px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:20px;">
                        <h5 style="color:#1e293b; margin-bottom:15px; font-weight:700;">Bank Account Details</h5>
                        <div style="display:flex; gap:10px; margin-bottom:15px;">
                            <button type="button" onclick="showBank('pakistan')" id="btn_pakistan" style="padding:8px 15px; border-radius:6px; border:1px solid var(--primary); background:var(--primary); color:white; cursor:pointer; font-weight:bold;">🇵🇰 Pakistan Bank</button>
                            <button type="button" onclick="showBank('saudi')" id="btn_saudi" style="padding:8px 15px; border-radius:6px; border:1px solid #cbd5e1; background:white; color:#1e293b; cursor:pointer; font-weight:bold;">🇸🇦 Saudi Arabia Bank</button>
                        </div>
                        <input type="hidden" name="bank_selected" id="bank_selected" value="Pakistan Bank (Faysal)">
                        <div id="pakistan_details" style="display:block; background:white; padding:15px; border-radius:8px; border:1px solid #cbd5e1; font-size:0.95rem;">
                            <p style="margin-bottom:8px;"><b>Account Title:</b> Institution of occupational career hub (IOCH)</p>
                            <p style="margin-bottom:8px;"><b>Bank Name:</b> Faysal Bank</p>
                            <p style="margin-bottom:8px;"><b>Account No.:</b> 3819499000001603</p>
                            <p style="margin-bottom:0;"><b>IBAN:</b> PK26FAYS3819499000001603</p>
                        </div>
                        <div id="saudi_details" style="display:none; background:white; padding:15px; border-radius:8px; border:1px solid #cbd5e1; font-size:0.95rem;">
                            <p style="margin-bottom:8px;"><b>Bank Name:</b> Al Rajhi Bank</p>
                            <p style="margin-bottom:8px;"><b>Account Title:</b> Peerless Training and Development</p>
                            <p style="margin-bottom:0;"><b>IBAN:</b> SA5280000432608016012567</p>
                        </div>
                    </div>

                    <div class="grid-2">
                        <div class="form-group"><label>Paid Amount (min PKR ${PARTNER_COST.toLocaleString()})</label><input type="number" name="fee_amount" min="${PARTNER_COST}" required></div>
                        <div class="form-group">
                            <label>Paid By</label>
                            <select name="paid_by" id="paid_by" onchange="togglePaymentProof()" required>
                                <option value="">Select...</option>
                                <option value="Self Paid">Self Paid</option>
                                <option value="Blood Relation">Blood Relation</option>
                                <option value="Third Party">Third Party</option>
                            </select>
                        </div>
                    </div>

                    <div id="thirdPartyError" style="display:none; background:#fee2e2; color:#b91c1c; padding:10px; border-radius:6px; margin-bottom:15px; font-weight:bold; font-size:14px;">
                        ⚠️ Third Party payments are not accepted. Please select Self Paid or Blood Relation.
                    </div>

                    <div id="payment_proof_box" style="display:none; margin-top:15px;">
                        <div class="file-upload-box" style="height:100px; display:flex; flex-direction:column; justify-content:center;">
                            <input type="file" name="fee_slip_upload" id="fee_slip_file">
                            <label>🧾 Upload Bank Slip / Receipt</label>
                        </div>
                    </div>

                    <h4 style="color:var(--primary); margin:30px 0 15px 0; border-bottom:2px solid #eee; padding-bottom:5px;">Step 7: Communication Evidence</h4>
                    <div class="form-group"><label>How did you communicate with us?</label><select name="source" required><option>Social media (Facebook, WhatsApp)</option><option>Website</option><option>Friend / Family</option><option>Other</option></select></div>
                    <div class="form-group"><label>Upload communication evidence</label><input type="file" name="chat_upload" required style="padding:10px; border:1px dashed #cbd5e1;"></div>

                    <h4 style="color:var(--primary); margin:30px 0 15px 0; border-bottom:2px solid #eee; padding-bottom:5px;">Step 8: Terms and Conditions</h4>

                    <div style="background:#f8fafc; padding:20px; border-radius:8px; border:1px solid #cbd5e1; font-size:0.9rem; max-height:300px; overflow-y:auto; margin-bottom:15px; line-height:1.6;">
                        ${TERMS_HTML}
                    </div>

                    <label style="display:flex; align-items:center; gap:10px; font-weight:600; margin-bottom:20px;">
                        <input type="checkbox" name="terms_accepted" value="Yes" required style="width:auto;"> I have read and agree to the Terms and Conditions mentioned above.
                    </label>

                    <h4 style="color:var(--primary); margin:30px 0 15px 0; border-bottom:2px solid #eee; padding-bottom:5px;">Step 9: Declaration</h4>
                    <div class="grid-2">
                        <div class="form-group"><label>Name (As per ID)</label><input type="text" name="declaration_name" required></div>
                        <div class="form-group">
                            <label>Submission Date &amp; Time (Auto)</label>
                            <input type="text" value="${realTime}" readonly style="background:#e2e8f0; cursor:not-allowed; font-weight:bold; color:#334155;">
                        </div>
                    </div>
                    <div style="background:#f8fafc; padding:20px; border-radius:8px; margin-bottom:20px;">
                        <p style="font-size:0.95rem; color:var(--text-muted); margin-bottom:15px;">I hereby declare that the information is true and I agree to the Student Privacy and Institute Policies.</p>
                        <label style="margin-right:20px; font-weight:600;"><input type="radio" name="declaration" value="Yes" onchange="checkDeclaration()" required style="width:auto;"> Yes, I Agree</label>
                        <label style="font-weight:600;"><input type="radio" name="declaration" value="No" onchange="cancelSubmit()" style="width:auto;"> No</label>
                    </div>

                    <input type="hidden" name="device_info" id="device_info">
                    <input type="hidden" name="device_location" id="device_location" value="Fetching...">

                    <button type="submit" id="submitBtn" class="btn btn-primary" style="width: 100%; padding: 15px; font-size:1.1rem;">Submit Registration</button>
                </form>
            </div>
        </div>
        <script>
            function toggleResit() {
                document.getElementById("resit_fields").style.display = (document.getElementById("resit").value === "Yes") ? "block" : "none";
            }
            function toggleIdFields() {
                var idType = document.getElementById("id_type").value;
                var hasId = (idType === "Passport" || idType === "National Identification Card");
                document.getElementById("passport_fields").style.display = (idType === "Passport") ? "block" : "none";
                document.getElementById("cnic_fields").style.display = (idType === "National Identification Card") ? "block" : "none";
                var photoBox = document.getElementById("photo_box");
                var photoInput = document.getElementById("photo_input");
                if (hasId) { photoBox.style.display = "flex"; photoInput.required = true; } 
                else { photoBox.style.display = "none"; photoInput.required = false; photoInput.value = ""; }
            }
            function togglePaymentProof() {
                var paidBy = document.getElementById("paid_by").value;
                var proofBox = document.getElementById("payment_proof_box");
                var fileInput = document.getElementById("fee_slip_file");
                var submitBtn = document.getElementById("submitBtn");
                var errorMsg = document.getElementById("thirdPartyError");
                if (paidBy === "Third Party") {
                    proofBox.style.display = "none"; fileInput.required = false; errorMsg.style.display = "block";
                    submitBtn.disabled = true; submitBtn.style.opacity = "0.5";
                } else if (paidBy !== "") {
                    proofBox.style.display = "block"; fileInput.required = true; errorMsg.style.display = "none";
                    submitBtn.disabled = false; submitBtn.style.opacity = "1";
                } else {
                    proofBox.style.display = "none"; fileInput.required = false; errorMsg.style.display = "none";
                    submitBtn.disabled = false; submitBtn.style.opacity = "1";
                }
            }
            function checkDeclaration() {
                if (document.getElementById("paid_by").value === "Third Party") return;
                document.getElementById("submitBtn").disabled = false; document.getElementById("submitBtn").style.opacity = "1";
            }
            function cancelSubmit() {
                document.getElementById("submitBtn").disabled = true; document.getElementById("submitBtn").style.opacity = "0.5"; alert("You have selected 'No'. Form submission is cancelled.");
            }
            function showBank(country) {
                var pk = country === 'pakistan';
                document.getElementById('pakistan_details').style.display = pk ? 'block' : 'none';
                document.getElementById('saudi_details').style.display = pk ? 'none' : 'block';
                var on = function (el) { el.style.background = 'var(--primary)'; el.style.color = 'white'; el.style.border = '1px solid var(--primary)'; };
                var off = function (el) { el.style.background = 'white'; el.style.color = '#1e293b'; el.style.border = '1px solid #cbd5e1'; };
                on(document.getElementById(pk ? 'btn_pakistan' : 'btn_saudi'));
                off(document.getElementById(pk ? 'btn_saudi' : 'btn_pakistan'));
                document.getElementById('bank_selected').value = pk ? 'Pakistan Bank (Faysal)' : 'Saudi Arabia Bank (Al Rajhi)';
            }
            function validateForm() {
                var decl = document.querySelector('input[name="declaration"]:checked');
                if (!decl) { alert("Please select declaration (Yes/No)."); return false; }
                if (decl.value === 'No') { alert("You must agree to declaration to submit the form."); return false; }
                if (document.getElementById('paid_by').value === 'Third Party') { alert("Third Party payments are not accepted."); return false; }
                return true;
            }
            document.addEventListener("DOMContentLoaded", function () {
                document.getElementById("device_info").value = navigator.userAgent;
                fetch('https://ipapi.co/json/').then(function (r) { return r.json(); }).then(function (data) {
                    document.getElementById("device_location").value = data.city + ", " + data.region + ", " + data.country_name;
                }).catch(function () { document.getElementById("device_location").value = "Not Available"; });
            });
        </script>
    `;
    res.send(publicHeaderFooter(regContent));
});
// ======================= STUDENT DETAILS (ADVANCED) =======================
// ======================= STUDENT DETAILS (ADVANCED & ERROR-FREE) =======================
// ======================= STUDENT DOCUMENTS (FULL SIZE) =======================
app.get('/student/:id', requireRole('SuperAdmin', 'Admin', 'Tutor'), wrap(async (req, res) => {
    const user = req.session.user;
    const s = await dbGet("SELECT * FROM students WHERE id = ?", [req.params.id]);
    if (!s) return res.send("Student not found.");
    if (!canAccessStudent(user, s)) return res.status(403).send('Access Denied');

    const cfg = await getSettings();
    const x = parseExtra(s.device_info);
    
    const dateStr = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: '2-digit' }).replace(/\//g, '');
    const docNo = `IOCH-${String(s.id).padStart(2, '0')}-${dateStr}`;
    const isDocValid = s.status === 'Active' && s.is_validated == 1;
    const docTitle = `IOCH-Registration-${s.first_name}-${s.surname}`.replace(/\s+/g, '-').toUpperCase();

    // ======================= ADVANCED UI HELPERS =======================
    const pageHeader = (title) => `
        <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #0f172a; padding-bottom:8px; margin-bottom:15px; page-break-inside:avoid; page-break-after:avoid;">
            <div style="flex:1; text-align:left; font-size:12px; color:#64748b; font-weight:bold;">Printed: ${nowStr()}</div>
            <div style="flex:1; text-align:center; font-size:16px; font-weight:800; color:#0f172a; text-transform:uppercase;">${title}</div>
            <div style="flex:1; text-align:right; font-size:12px; color:transparent;">.</div>
        </div>`;

    const pageBreak = `<div style="page-break-before: always; break-before: page; height:1px; overflow:hidden;"></div>`;

        const evidenceFile = (f, label) => {
        if (!f) return `<div style="padding:15px; background:#f8fafc; border:1px dashed #cbd5e1; color:#94a3b8; font-size:14px; text-align:center; border-radius:6px;">No File Attached</div>`;
        const ext = f.split('.').pop().toLowerCase();
        const url = '/uploads/' + encodeURIComponent(f);
        
        // Header with Title and "Open Full Size" button
        const titleHtml = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px; border-left:4px solid #059669; padding-left:10px;">
                <div style="font-size:16px; color:#0f172a; font-weight:800; text-transform:uppercase;">${label}</div>
                <a href="${url}" target="_blank" style="font-size:13px; color:#3b82f6; font-weight:bold; text-decoration:none; background:#eff6ff; padding:6px 12px; border-radius:6px; border:1px solid #bfdbfe;">
                    🔗 Open Full Size
                </a>
            </div>`;
        
        if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) {
            return `<div style="border:1px solid #cbd5e1; border-radius:8px; padding:15px; background:white; text-align:center; page-break-inside:avoid;">
                ${titleHtml}
                <img src="${url}" style="width:100%; max-height:500px; object-fit:contain; border-radius:4px; border:1px solid #f1f5f9;">
            </div>`;
        }
        return `<div style="border:1px solid #cbd5e1; border-radius:8px; padding:20px; background:white; text-align:center; page-break-inside:avoid;">
            ${titleHtml}
            <span style="font-size:40px; display:block; margin-bottom:10px;">📄</span>
            <a href="${url}" target="_blank" style="font-size:16px; color:#3b82f6; font-weight:bold;">Click to Open Document</a>
        </div>`;
    };

    const cardWrap = (icon, title, bodyContent, bg = '#ffffff') => `
        <div style="background:${bg}; border:1px solid #e2e8f0; border-radius:12px; padding:20px; margin-bottom:20px; box-shadow:0 4px 15px rgba(0,0,0,0.02); page-break-inside:avoid;">
            <h3 style="color:#0f172a; font-size:16px; font-weight:800; display:flex; align-items:center; gap:8px; margin-bottom:18px; border-bottom:1px solid #e2e8f0; padding-bottom:12px;">
                <span style="font-size:20px;">${icon}</span> ${title}
            </h3>
            ${bodyContent}
        </div>`;

    const grid = (inner) => `<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:15px;">${inner}</div>`;
    
    const advField = (label, value) => `
        <div style="background:#f8fafc; border-radius:8px; padding:12px 15px; border:1px solid #f1f5f9;">
            <div style="font-size:11px; color:#64748b; text-transform:uppercase; letter-spacing:0.5px; font-weight:700; margin-bottom:4px;">${label}</div>
            <div style="font-size:14px; color:#0f172a; font-weight:600; word-break:break-word;">${esc(value || 'N/A')}</div>
        </div>`;

    // PAGE 1: Section 1, 2 & Card
    const sec1_2_html = `
        ${pageHeader('Student Registration (Page 1)')}
        
        <!-- Step 1 Full Width -->
        <div style="margin-bottom:20px;">
            ${cardWrap('👤', 'Step 1: Personal Details', grid(
                advField('Title', x['Title']) + 
                advField('First Name', s.first_name) + 
                advField('Surname', s.surname) + 
                advField('Gender', s.gender) + 
                advField('Date of Birth', s.dob) + 
                advField('Nationality', s.nationality)
            ))}
        </div>

        <!-- Step 2 Full Width -->
        <div style="margin-bottom:20px;">
            ${cardWrap('📞', 'Step 2: Contact Information', grid(
                advField('Email', s.email) + 
                advField('Mobile', s.contact) + 
                advField('City', s.city) + 
                advField('Postal Code', s.postal_code) + 
                advField('Country', s.country)
            ) + `<div style="margin-top:15px;">${advField('Full Address', s.address)}</div>`)}
        </div>

        <!-- Student Card at Bottom (Center) -->
        <div style="margin-top:25px; padding-top:20px; border-top:2px dashed #cbd5e1; text-align:center; page-break-inside:avoid;">
            <h3 style="color:#0f172a; font-size:16px; font-weight:800; text-transform:uppercase; margin-bottom:15px; display:flex; align-items:center; justify-content:center; gap:8px;">
                🆔 Learner Card
            </h3>
            <div style="display:flex; justify-content:center;">
                ${renderCardInline(s, cfg)}
            </div>
        </div>
    `;

    // PAGE 2: Section 3
    const resitLogic = (s.resit_details && s.resit_details.trim() !== '' && s.resit_details !== 'null') 
        ? `<div style="margin-top:15px; padding:15px; background:#fef2f2; border-radius:8px; border-left:4px solid #ef4444; font-size:14px;"><b>Resit Details:</b> ${esc(s.resit_details)}</div>` 
        : `<div style="margin-top:15px; padding:15px; background:#ecfdf5; border-radius:8px; border-left:4px solid #10b981; font-size:14px; color:#065f46;"><b>Status:</b> Fresh student - first time enrolment in NEBOSH course</div>`;

    const sec3_html = `
        ${pageBreak}
        <div style="page-break-inside: avoid;">
            ${pageHeader('Course Details (Page 2)')}
            ${cardWrap('📚', 'Step 3: Course Details', 
                grid(advField('Course', s.course) + advField('Mode of Study', x['Mode'] || s.mode_of_learning) + advField('Exam Date', x['CourseDate']) + advField('Reason for Course', x['Reason'])) + resitLogic
            )}
            ${s.resit_result_upload ? `<div style="margin-top:20px;">${evidenceFile(s.resit_result_upload, 'Old Result Card')}</div>` : ''}
        </div>
    `;

    // PAGE 3: Section 4
    const sec4_html = `
        ${pageBreak}${pageHeader('Education Details (Page 3)')}
        ${cardWrap('🎓', 'Step 4: Education & Documents', grid(advField('Highest Qualification', s.qualification) + advField('English Proficiency', x['English'])))}
        <div style="margin-top:20px;">${evidenceFile(s.qualification_upload, 'Degree / Certificate')}</div>
    `;

    // PAGE 4: Section 5
    const sec5_html = `
        ${pageBreak}${pageHeader('ID Documents (Page 4)')}
        ${cardWrap('🪪', 'Step 5: Identification Documents', grid(advField('ID Type', s.id_type) + advField('ID Number', s.id_number)))}
        <div style="margin-top:20px; display:flex; flex-direction:column; gap:20px;">
            ${evidenceFile(s.id_front, s.id_type === 'Passport' ? 'Passport First Page' : 'National ID Front')}
            ${evidenceFile(s.id_back, s.id_type === 'Passport' ? 'Passport Second Page' : 'National ID Back')}
        </div>
    `;

    // PAGE 5: Section 6 & 7
    const sec6_7_html = `
        ${pageBreak}${pageHeader('Payment & Communication (Page 5)')}
        ${cardWrap('💰', 'Step 6: Payment Proof', grid(advField('Paid Amount', 'PKR ' + (s.fee_amount || '0')) + advField('Payment Method', x['Paid By']) + advField('Deposited In Bank', x['Bank'])))}
        <div style="margin-top:20px;">${evidenceFile(s.fee_slip_upload, 'Bank Slip / Receipt')}</div>
        
        <div style="margin-top:30px;">
            ${cardWrap('💬', 'Step 7: Communication Evidence', grid(advField('Source', s.source)))}
            <div style="margin-top:20px;">${evidenceFile(s.chat_upload, 'Chat / Evidence')}</div>
        </div>
    `;

    // PAGE 6: Section 8, 9 & QR
    const verifyUrl = `${req.protocol}://${req.get('host')}/verify-document?doc=${docNo}`;
    const qrCodeHtml = `
        <div style="margin-top:20px; padding:20px; border:2px solid ${isDocValid ? '#10b981' : '#ef4444'}; border-radius:12px; display:flex; align-items:center; justify-content:space-between; page-break-inside:avoid; background:${isDocValid ? '#ecfdf5' : '#fef2f2'};">
            <div>
                <h4 style="margin:0 0 5px 0; font-size:16px; color:#0f172a; font-weight:800;">Document Verification</h4>
                <p style="margin:0; font-size:13px; color:#475569;">Status: <b>${isDocValid ? '✅ Valid & Approved' : '❌ Pending Validation'}</b><br>Doc No: <b>${docNo}</b></p>
            </div>
            ${isDocValid ? `<img src="https://api.qrserver.com/v1/create-qr-code/?size=100x100&data=${encodeURIComponent(verifyUrl)}" style="width:100px; height:100px; border-radius:8px;">` : `<div style="width:100px; height:100px; display:flex; align-items:center; justify-content:center; font-size:12px; text-align:center; color:#ef4444; border:1px dashed #ef4444; border-radius:8px;">QR Locked<br>(Pending)</div>`}
        </div>`;

    const sec8_9_html = `
        ${pageBreak}${pageHeader('Terms & Declaration (Page 6)')}
        ${cardWrap('📜', 'Step 8: Terms and Conditions', grid(advField('Status', s.terms_accepted || 'Not Recorded') + advField('Date', s.declaration_date)))}
        
        <div style="margin-top:30px;">
            ${cardWrap('✍️', 'Step 9: Declaration', 
                grid(advField('Agreed', s.declaration === 'Yes' ? 'Yes, I Agree' : 'No') + advField('Name (As per ID)', x['DeclName']) + advField('Date', s.declaration_date)) +
                `<div style="margin-top:15px; font-size:13px; color:#475569; font-style:italic; background:#f8fafc; padding:15px; border-radius:8px;">I hereby declare that the information is true and I agree to the Student Privacy and Institute Policies.</div>` +
                qrCodeHtml
            )}
        </div>
    `;

    // ======================= APPROVAL & BUTTONS =======================
    let approvalSection = '';
    if (canManageStudent(user, s)) {
        const tutors = await dbAll("SELECT id, name FROM users WHERE role = 'Tutor'");
        const tutorOptions = tutors.map(t => `<option value="${esc(t.name)}">${esc(t.name)}</option>`).join('');

        if (s.status === 'Pending') {
            approvalSection = `
            <div class="card no-print" style="border:2px solid #f59e0b; background:#fffbeb; margin-bottom:20px;">
                <div class="card-body" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:15px;">
                    <div>
                        <h3 style="color:#b45309; margin:0 0 5px 0; font-size:16px; font-weight:800;">Action Required</h3>
                        <p style="color:#92400e; margin:0; font-size:13px;">Select a tutor and approve this student to activate their account.</p>
                    </div>
                    <form action="/approve-student/${s.id}" method="POST" style="display:flex; gap:10px; align-items:center; margin:0;">
                        <select name="tutor_name" required style="padding:10px; border-radius:6px; border:1px solid #cbd5e1; font-size:14px; min-width:200px;">
                            <option value="">-- Select Tutor --</option>${tutorOptions}
                        </select>
                        <button type="submit" class="btn btn-success" style="padding:10px 20px; font-size:14px; font-weight:bold;">✔️ Approve</button>
                    </form>
                </div>
            </div>`;
        } else {
            const suspendBtn = s.status === 'Suspended' 
                ? `<form action="/toggle-suspend/${s.id}" method="POST" style="display:inline;"><button type="submit" class="btn btn-primary" style="padding:8px 16px; font-size:13px; border-radius:6px; font-weight:600;">🔄 Re-Approve (Activate)</button></form>`
                : `<form action="/toggle-suspend/${s.id}" method="POST" style="display:inline;"><button type="submit" class="btn btn-danger" style="padding:8px 16px; font-size:13px; border-radius:6px; font-weight:600;">🚫 Suspend</button></form>`;

            const validateBtn = s.is_validated == 1
                ? `<form action="/validate-student/${s.id}" method="POST" style="display:inline;"><button type="submit" class="btn btn-warning" style="padding:8px 16px; font-size:13px; border-radius:6px; font-weight:600; color:white;">❌ Remove Validation</button></form>`
                : `<form action="/validate-student/${s.id}" method="POST" style="display:inline;"><button type="submit" class="btn btn-success" style="padding:8px 16px; font-size:13px; border-radius:6px; font-weight:600; background:#10b981;">✅ Validate Document</button></form>`;

            approvalSection = `
            <div class="card no-print" style="border:1px solid #10b981; background:#ecfdf5; margin-bottom:20px;">
                <div class="card-body" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:15px;">
                    <div>
                        <h3 style="color:#047857; margin:0 0 5px 0; font-size:16px; font-weight:800;">Status: ${esc(s.status)} ${s.is_validated == 1 ? '| Validated ✔️' : ''}</h3>
                        <p style="color:#065f46; margin:0; font-size:13px;"><b>Assigned Tutor:</b> ${esc(s.assigned_tutor || 'None')}</p>
                    </div>
                    <div style="display:flex; gap:10px;">${suspendBtn} ${validateBtn}</div>
                </div>
                <div style="margin-top:15px; padding-top:15px; border-top:1px dashed #34d399;">
                    <form action="/assign-tutor/${s.id}" method="POST" style="display:flex; gap:10px; align-items:center; margin:0;">
                        <label style="margin:0; font-size:13px; font-weight:700; color:#065f46; white-space:nowrap;">Change Tutor:</label>
                        <select name="tutor_name" required style="flex:1; padding:8px; font-size:13px; border-radius:6px; border:1px solid #34d399; background:white;">
                            <option value="">-- Select Tutor --</option>${tutors.map(t => `<option value="${esc(t.name)}" ${s.assigned_tutor === t.name ? 'selected' : ''}>${esc(t.name)}</option>`).join('')}
                        </select>
                        <button type="submit" class="btn btn-primary" style="padding:8px 16px; font-size:13px; border-radius:6px; background:#047857; border:none;">Update</button>
                    </form>
                </div>
            </div>`;
        }
    }

    // ======================= MAIN CONTENT =======================
    const content = `
        <style>
            @media print { 
                .no-print, .sidebar, .top-bar { display: none !important; } 
                .dash-layout, .main-panel, .content-area { margin: 0 !important; padding: 0 !important; display: block !important; } 
                .card { border: none !important; box-shadow: none !important; padding: 0 !important; }
                .main-export-box { border: none !important; padding: 0 !important; }
                body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
                @page { margin: 15mm 10mm; size: auto; }
                .print-top-header { display: block !important; page-break-before: avoid !important; page-break-inside: avoid !important; }
            }
        </style>
        
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;" class="no-print">
            <h2>Student Profile: ${esc(s.first_name)} ${esc(s.surname)}</h2>
            <div style="display:flex; gap:10px;">
                ${user.role === 'SuperAdmin' ? `<a href="/student/${s.id}/edit" class="btn btn-warning">✏️ Edit</a>` + postBtn('/delete-student/' + s.id, '🗑️ Delete', 'btn-danger', 'Pakka delete karna hai?') : ''}
                <button onclick="window.print()" class="btn btn-primary">🖶 Export / Print PDF</button>
                <a href="/student/${s.id}/documents" class="btn btn-success" style="background:#0ea5e9; border:none;">📂 View Documents</a>
                <a href="/students" class="btn btn-outline">← Back</a>
            </div>
        </div>

        <div class="no-print" style="background:#f8fafc; padding:10px 15px; border-radius:8px; margin-bottom:20px; border:1px solid #e2e8f0; font-size:14px;">
            <b>File Name:</b> ${docTitle} <span style="color:#64748b; margin-left:10px;">(Use this name to save PDF)</span>
        </div>
        
        ${approvalSection}

        <div class="main-export-box" style="background:white; padding:30px; border-radius:12px; border:1px solid #e2e8f0;">
            <div class="print-top-header" style="text-align:center; margin-bottom:30px;">
                <img src="/Ioch-wb.png" style="height:90px; margin-bottom:15px;">
                <h1 style="margin:0; font-size:28px; text-transform:uppercase; font-weight:800; letter-spacing:1px; color:#064e3b;">IOCH Registration Form</h1>
            </div>

            ${sec1_2_html}
            ${sec3_html}
            ${sec4_html}
            ${sec5_html}
            ${sec6_7_html}
            ${sec8_9_html}
        </div>
    `;
    res.send(renderDashboard(user, content, 'students'));
}));
// ======================= HELPER FUNCTION (Card Render) =======================
function renderCardInline(s, cfg) {
    const bg = cfg.card_bg ? `background:url('${IMG(cfg.card_bg)}') center/cover no-repeat;` : 'background:linear-gradient(135deg,#ecfdf5,#ffffff);';
    const chip = (f, alt) => f ? `<img src="${IMG(f)}" alt="${alt}" style="height:24px; background:white; padding:2px 4px; border-radius:4px; object-fit:contain;">` : '';
    const photo = s.photo
        ? `<img src="${IMG(s.photo)}" style="width:80px; height:100px; object-fit:cover; border-radius:6px; border:2px solid #047857; background:white;">`
        : `<div style="width:80px; height:100px; border-radius:6px; border:2px solid #047857; background:#d1fae5; color:#047857; font-size:30px; font-weight:bold; display:flex; align-items:center; justify-content:center;">${esc((s.first_name || '?').charAt(0))}</div>`;
    
    return `
    <div style="width:380px; height:240px; border-radius:14px; border:1px solid #94a3b8; overflow:hidden; position:relative; margin:0 auto; text-align:left; font-family:Arial,sans-serif; box-shadow:0 6px 18px rgba(0,0,0,0.15); ${bg} -webkit-print-color-adjust:exact; print-color-adjust:exact;">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(6,78,59,0.95); height:40px;">
            <img src="/Ioch-wb.png" alt="IOCH" style="height:26px; background:white; padding:2px 4px; border-radius:4px;">
            <div style="color:white; font-size:11px; font-weight:bold; letter-spacing:1px;">LEARNER CARD</div>
            <div style="display:flex; gap:4px;">${chip(cfg.logo_nebosh, 'NEBOSH')}${chip(cfg.logo_partner, 'Learner Partner')}</div>
        </div>
        <div style="display:flex; gap:12px; padding:12px; background:rgba(255,255,255,0.85); height:170px; overflow:hidden;">
            ${photo}
            <div style="flex:1; min-width:0; line-height:1.3;">
                <div style="font-size:9px; color:#475569; font-weight:bold;">NAME</div>
                <div style="font-size:12px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.first_name + ' ' + s.surname)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">COURSE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.course)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">PHONE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.contact)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">EMAIL</div>
                <div style="font-size:10px; font-weight:bold; color:#0f172a; word-break:break-word;">${esc(s.email)}</div>
            </div>
        </div>
        <div style="position:absolute; bottom:0; left:0; right:0; display:flex; justify-content:space-between; padding:6px 10px; background:rgba(6,78,59,0.95); color:white; font-size:10px;">
            <span>Card No: <b>${esc(s.card_no || 'Pending')}</b></span><span>Issued: ${esc(s.card_issued || 'N/A')}</span><span>${esc(cfg.card_footer || 'ioch.org.pk')}</span>
        </div>
    </div>`;
}
// ======================= HELPER FUNCTION =======================
function renderCardInline(s, cfg) {
    const bg = cfg.card_bg ? `background:url('${IMG(cfg.card_bg)}') center/cover no-repeat;` : 'background:linear-gradient(135deg,#ecfdf5,#ffffff);';
    const chip = (f, alt) => f ? `<img src="${IMG(f)}" alt="${alt}" style="height:24px; background:white; padding:2px 4px; border-radius:4px; object-fit:contain;">` : '';
    const photo = s.photo
        ? `<img src="${IMG(s.photo)}" style="width:80px; height:100px; object-fit:cover; border-radius:6px; border:2px solid #047857; background:white;">`
        : `<div style="width:80px; height:100px; border-radius:6px; border:2px solid #047857; background:#d1fae5; color:#047857; font-size:30px; font-weight:bold; display:flex; align-items:center; justify-content:center;">${esc((s.first_name || '?').charAt(0))}</div>`;
    
    return `
    <div style="width:380px; height:240px; border-radius:14px; border:1px solid #94a3b8; overflow:hidden; position:relative; margin:0 auto; text-align:left; font-family:Arial,sans-serif; box-shadow:0 6px 18px rgba(0,0,0,0.15); ${bg} -webkit-print-color-adjust:exact; print-color-adjust:exact;">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(6,78,59,0.95); height:40px;">
            <img src="/Ioch-wb.png" alt="IOCH" style="height:26px; background:white; padding:2px 4px; border-radius:4px;">
            <div style="color:white; font-size:11px; font-weight:bold; letter-spacing:1px;">LEARNER CARD</div>
            <div style="display:flex; gap:4px;">${chip(cfg.logo_nebosh, 'NEBOSH')}${chip(cfg.logo_partner, 'Learner Partner')}</div>
        </div>
        <div style="display:flex; gap:12px; padding:12px; background:rgba(255,255,255,0.85); height:170px; overflow:hidden;">
            ${photo}
            <div style="flex:1; min-width:0; line-height:1.3;">
                <div style="font-size:9px; color:#475569; font-weight:bold;">NAME</div>
                <div style="font-size:12px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.first_name + ' ' + s.surname)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">COURSE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.course)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">PHONE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.contact)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">EMAIL</div>
                <div style="font-size:10px; font-weight:bold; color:#0f172a; word-break:break-word;">${esc(s.email)}</div>
            </div>
        </div>
        <div style="position:absolute; bottom:0; left:0; right:0; display:flex; justify-content:space-between; padding:6px 10px; background:rgba(6,78,59,0.95); color:white; font-size:10px;">
            <span>Card No: <b>${esc(s.card_no || 'Pending')}</b></span><span>Issued: ${esc(s.card_issued || 'N/A')}</span><span>${esc(cfg.card_footer || 'ioch.org.pk')}</span>
        </div>
    </div>`;
}
// 3. Registration Form (POST) & Upload Setup
const regUpload = upload.fields([
    { name: 'qualification_upload', maxCount: 1 }, { name: 'fee_slip_upload', maxCount: 1 },
    { name: 'chat_upload', maxCount: 1 }, { name: 'resit_result_upload', maxCount: 1 },
    { name: 'passport_front', maxCount: 1 }, { name: 'passport_back', maxCount: 1 },
    { name: 'cnic_front', maxCount: 1 }, { name: 'cnic_back', maxCount: 1 },
    { name: 'photo', maxCount: 1 }
]);

app.post('/student-register', regUpload, wrap(async (req, res) => {
    const b = req.body;
    const f = req.files || {};
    b.email = String(b.email || '').trim().toLowerCase();
    const back = "<a href='/student-register'>Go Back</a>";
    const discard = () => Object.values(f).forEach(a => safeUnlink(a[0].filename));
    const msg = (text, color = '#000') => { discard(); return res.send(`<h3 style='text-align:center; margin-top:50px; color:${color};'>${esc(text)} ${back}</h3>`); };

    if (b.declaration !== 'Yes') return msg('Please accept declaration.');
    if (b.terms_accepted !== 'Yes') return msg('Please accept the Terms and Conditions.');
    if (b.paid_by === 'Third Party') return msg('Third Party payments are not accepted.', 'red');
    if (!['Passport', 'National Identification Card'].includes(b.id_type)) return msg('Please select a valid ID type.');
    if (!(parseFloat(b.fee_amount) >= PARTNER_COST)) return msg(`Minimum fee PKR ${PARTNER_COST.toLocaleString()} honi chahiye.`, 'red');
    if (!f['fee_slip_upload']) return msg('Bank slip / receipt is required.');
    if (!f['photo'] || !isImg(f['photo'][0].filename)) return msg('Please upload a valid recent photo (JPG / PNG / WEBP).');

    const dup = await dbGet("SELECT id FROM students WHERE lower(email) = lower(?)", [b.email]);
    if (dup) return msg('Is email se pehle hi registration ho chuki hai.', '#b91c1c');

    const fn = k => f[k] ? f[k][0].filename : null;
    let idFront, idBack, idNumber;
    if (b.id_type === 'Passport') { idFront = fn('passport_front'); idBack = fn('passport_back'); idNumber = b.passport_no; }
    else { idFront = fn('cnic_front'); idBack = fn('cnic_back'); idNumber = b.cnic_no; }

    if (!String(idNumber || '').trim()) return msg('ID number zaroori hai.');
    if (!idFront || !idBack) return msg('ID ki dono sides / pages upload karein.');

    const ip = getIp(req);
    const device = cleanPipe(b.device_info || req.headers['user-agent']);
    const location = cleanPipe(b.device_location && b.device_location !== 'Fetching...' ? b.device_location : 'Unknown');
    const extra = ` | Title: ${cleanPipe(b.title)} | Reason: ${cleanPipe(b.course_reason)} | Mode: ${cleanPipe(b.mode_of_learning)} | Paid By: ${cleanPipe(b.paid_by)} | Bank: ${cleanPipe(b.bank_selected)} | English: ${cleanPipe(b.english_level)} | CourseDate: ${cleanPipe(b.course_date)} | DeclName: ${cleanPipe(b.declaration_name)}`;
    const combinedDeviceInfo = `Location: ${location} | Device: ${device}${extra}`;
    const resitDetails = b.resit === 'Yes' ? `Learner No: ${cleanPipe(b.learner_number)} | Institute: ${cleanPipe(b.institute_name)}` : null;

    try {
        await dbRun(`INSERT INTO students (
            first_name, surname, gender, dob, contact, email, address, city, postal_code, country,
            id_type, id_number, nationality, id_front, id_back, qualification, qualification_upload,
            course, fee_amount, fee_slip_upload, source, chat_upload, declaration, declaration_date,
            terms_accepted, status, ip_address, device_info, resit_details, resit_result_upload, mode_of_learning, photo
        ) VALUES (?,?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?, ?,?,?,?,?,?,?, ?,'Pending',?,?,?,?,?,?)`, [
            b.first_name, b.surname, b.gender, b.dob, b.contact, b.email, b.address, b.city, b.postal_code, b.country,
            b.id_type, idNumber, b.nationality, idFront, idBack, b.qualification, fn('qualification_upload'),
            b.course, b.fee_amount, fn('fee_slip_upload'), b.source, fn('chat_upload'), b.declaration, nowStr(),
            b.terms_accepted, ip, combinedDeviceInfo, resitDetails, fn('resit_result_upload'), b.mode_of_learning, fn('photo')
        ]);
    } catch (err) {
        console.error('=== REGISTRATION ERROR ===', err.message);
        discard();
        return res.send(`<div style="max-width:600px; margin:50px auto; padding:30px; background:#fee2e2; border-radius:12px; border:2px solid #ef4444;"><h2 style="color:#b91c1c; margin-bottom:15px;">❌ Registration Failed</h2><p style="color:#7f1d1d; margin-bottom:20px;">Please check all fields and try again.</p><a href="/student-register">← Go Back to Form</a></div>`);
    }
    res.send(publicHeaderFooter(`<div style="display:flex; justify-content:center; align-items:center; min-height:80vh; background:#f8fafc; text-align:center;"><div style="background:white; padding:50px; border-radius:16px;"><h2 style="color:var(--primary); margin-bottom:15px;">🎉 Application Submitted!</h2><p style="color:var(--text-muted); margin-bottom:15px;">Pending approval. Credentials will be sent via Email.</p><a href="/" class="btn btn-primary">Home</a></div></div>`));
}));

// 4. Card Render Helper
function renderCardInline(s, cfg) {
    const bg = cfg.card_bg ? `background:url('${IMG(cfg.card_bg)}') center/cover no-repeat;` : 'background:linear-gradient(135deg,#ecfdf5,#ffffff);';
    const chip = (f, alt) => f ? `<img src="${IMG(f)}" alt="${alt}" style="height:24px; background:white; padding:2px 4px; border-radius:4px; object-fit:contain;">` : '';
    const photo = s.photo
        ? `<img src="${IMG(s.photo)}" style="width:80px; height:100px; object-fit:cover; border-radius:6px; border:2px solid #047857; background:white;">`
        : `<div style="width:80px; height:100px; border-radius:6px; border:2px solid #047857; background:#d1fae5; color:#047857; font-size:30px; font-weight:bold; display:flex; align-items:center; justify-content:center;">${esc((s.first_name || '?').charAt(0))}</div>`;
    
    return `
    <div style="width:380px; height:240px; border-radius:14px; border:1px solid #94a3b8; overflow:hidden; position:relative; margin:0 auto; text-align:left; font-family:Arial,sans-serif; box-shadow:0 6px 18px rgba(0,0,0,0.15); ${bg} -webkit-print-color-adjust:exact; print-color-adjust:exact;">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(6,78,59,0.95); height:40px;">
            <img src="/Ioch-wb.png" alt="IOCH" style="height:26px; background:white; padding:2px 4px; border-radius:4px;">
            <div style="color:white; font-size:11px; font-weight:bold; letter-spacing:1px;">LEARNER CARD</div>
            <div style="display:flex; gap:4px;">${chip(cfg.logo_nebosh, 'NEBOSH')}${chip(cfg.logo_partner, 'Learner Partner')}</div>
        </div>
        <div style="display:flex; gap:12px; padding:12px; background:rgba(255,255,255,0.85); height:170px; overflow:hidden;">
            ${photo}
            <div style="flex:1; min-width:0; line-height:1.3;">
                <div style="font-size:9px; color:#475569; font-weight:bold;">NAME</div>
                <div style="font-size:12px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.first_name + ' ' + s.surname)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">COURSE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.course)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">PHONE</div>
                <div style="font-size:11px; font-weight:bold; color:#0f172a; margin-bottom:4px; word-break:break-word;">${esc(s.contact)}</div>
                <div style="font-size:9px; color:#475569; font-weight:bold;">EMAIL</div>
                <div style="font-size:10px; font-weight:bold; color:#0f172a; word-break:break-word;">${esc(s.email)}</div>
            </div>
        </div>
        <div style="position:absolute; bottom:0; left:0; right:0; display:flex; justify-content:space-between; padding:6px 10px; background:rgba(6,78,59,0.95); color:white; font-size:10px;">
            <span>Card No: <b>${esc(s.card_no || 'Pending')}</b></span><span>Issued: ${esc(s.card_issued || 'N/A')}</span><span>${esc(cfg.card_footer || 'ioch.org.pk')}</span>
        </div>
    </div>`;
}
// ================= ERROR HANDLER =================
app.use((err, req, res, next) => {
    console.error(err);
    const safe = (err instanceof multer.MulterError || err.message === 'File type not allowed') ? err.message : 'Server error. Please try again.';
    res.status(500).send(`<h3 style="text-align:center; margin-top:50px;">${esc(safe)} <a href="javascript:history.back()">Go Back</a></h3>`);
});

// ================= SERVER START (FIX: safe extras load) =================
const http = require('http');
const { Server } = require('socket.io');
const server = http.createServer(app);
const io = new Server(server);

try {
    require('./extras')({
        app, io, db, dbGet, dbAll, dbRun, wrap, esc, requireLogin, requireRole, notStudent,
        renderDashboard, publicHeaderFooter, upload, safeUnlink, isImg, csvCell, postBtn,
        getIp, validMonth, MONTH_EXPR, PARTNER_COST, STAFF_ROLES, bcrypt, crypto, path, fs, getFinance,
        nowStr, uploadDir
    });
    console.log('✅ extras.js loaded successfully');
} catch (err) {
    console.warn('⚠️  extras.js load nahi hua:', err.message);
}

server.listen(port, () => { console.log(`\n🚀 IOCH Portal running at http://localhost:${port}\n`); });