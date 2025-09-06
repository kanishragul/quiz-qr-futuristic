
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import sqlite3 from 'sqlite3';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import { parse } from 'csv-parse';
import QRCode from 'qrcode';
import cors from 'cors';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';
const DB_PATH = process.env.SQLITE_PATH || './db/quiz.db';
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || `http://localhost:${PORT}`;

// Ensure DB exists folder
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new sqlite3.Database(DB_PATH);

// Middlewares
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
      },
    },
  })
);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));

// Static
app.use(express.static('public'));
// QR code endpoint
app.get('/api/qr', async (req, res) => {
  const joinUrl = `${req.protocol}://${req.get('host')}/participant.html`;
  try {
    const dataUrl = await QRCode.toDataURL(joinUrl, { margin: 2, scale: 8 });
    res.json({ joinUrl, dataUrl });
  } catch (e) {
    console.error("QR generation failed:", e); // 🔥 log error to console
    res.status(500).json({ error: 'QR generation failed' });
  }
});


// Helpers
function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}
function authRequired(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
function adminRequired(req, res, next) {
  // simple admin check by email domain or env list
  // For demo, allow if email ends with '@admin.local'
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.email && decoded.email.endsWith('@admin.local')) {
      req.user = decoded;
      return next();
    }
    return res.status(403).json({ error: 'Admin only' });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// QR Join Link (for student quiz page)
app.get('/api/qr', async (req, res) => {
  const joinUrl = `${req.protocol}://${req.get('host')}/participant.html`; // ✅ points to quiz page
  try {
    const dataUrl = await QRCode.toDataURL(joinUrl, { margin: 2, scale: 8 });
    res.json({ joinUrl, dataUrl });
  } catch (e) {
    res.status(500).json({ error: 'QR generation failed' });
  }
});

// Auth
app.post('/api/auth/signup', (req, res) => {
  const { name, roll, email, password } = req.body;
  if (!name || !roll || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  const hash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare('INSERT INTO users (name,roll,email,password_hash) VALUES (?,?,?,?)');
  stmt.run(name, roll, email, hash, function(err) {
    if (err) return res.status(400).json({ error: 'Email already in use' });
    const user = { id: this.lastID, email };
    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.json({ ok: true, token });
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.json({ ok: true, token, user: { id: user.id, name: user.name, roll: user.roll, email: user.email } });
  });
});

app.get('/api/me', authRequired, (req, res) => {
  db.get('SELECT id,name,roll,email FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  });
});

// Quiz APIs
app.get('/api/questions', authRequired, (req, res) => {
  const tab = parseInt(req.query.tab || '0', 10);
  if (!(tab >=1 && tab <=5)) return res.status(400).json({ error: 'Invalid tab' });

  // Check lock
  db.get('SELECT tabs_locked_json FROM progress WHERE user_id = ?', [req.user.id], (err, prog) => {
    let locked = {};
    if (prog) {
      try { locked = JSON.parse(prog.tabs_locked_json || '{}'); } catch { locked = {}; }
    }
    if (locked[String(tab)]) {
      return res.status(403).json({ error: 'Tab locked' });
    }
    db.all('SELECT id,tab,type,text,options_json,points FROM questions WHERE tab = ? ORDER BY id', [tab], (err2, rows) => {
      if (err2) return res.status(500).json({ error: 'DB error' });
      const questions = rows.map(r => ({
        id: r.id, tab: r.tab, type: r.type, text: r.text, options: JSON.parse(r.options_json || '[]'), points: r.points
      }));
      res.json({ tab, questions });
    });
  });
});

app.post('/api/submit', authRequired, (req, res) => {
  const { tab, answers } = req.body; // answers: [{questionId, response}] response may be array or string/bool
  const tabNum = parseInt(tab, 10);
  if (!(tabNum>=1 && tabNum<=5)) return res.status(400).json({ error: 'Invalid tab' });
  if (!Array.isArray(answers)) return res.status(400).json({ error: 'Invalid answers' });

  // Fetch correct answers
  db.all('SELECT id,type,answers_json,tab FROM questions WHERE tab = ?', [tabNum], (err, qs) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const qMap = new Map(qs.map(q=>[q.id, q]));

    let correctCount = 0;
    const now = new Date().toISOString();

    const insertStmt = db.prepare('INSERT INTO answers (user_id,question_id,tab,response_json,is_correct,submitted_at) VALUES (?,?,?,?,?,?)');

    for (const a of answers) {
      const q = qMap.get(a.questionId);
      if (!q) continue;
      let resp = a.response;
      // Normalize response and correct
      const correct = JSON.parse(q.answers_json);
      const type = q.type;
      const normalize = (x) => {
        if (Array.isArray(x)) return x.map(v=>String(v).trim().toLowerCase()).sort();
        return String(x).trim().toLowerCase();
      };
      const normalizedCorrect = normalize(correct);
      const normalizedResp = normalize(resp);

      let isCorrect = 0;
      if (type === 'mcq_multi') {
        // exact set match only
        if (Array.isArray(normalizedResp) && JSON.stringify(normalizedResp) === JSON.stringify(normalizedCorrect)) isCorrect = 1;
      } else if (type === 'mcq_single' || type === 'true_false') {
        // correct can be array with one (or more aliases)
        const corrSet = Array.isArray(normalizedCorrect) ? new Set(normalizedCorrect) : new Set([normalizedCorrect]);
        if (corrSet.has(normalizedResp)) isCorrect = 1;
      } else if (type === 'short_text') {
        const corrSet = Array.isArray(normalizedCorrect) ? new Set(normalizedCorrect) : new Set([normalizedCorrect]);
        if (corrSet.has(normalizedResp)) isCorrect = 1;
      }
      insertStmt.run(req.user.id, q.id, tabNum, JSON.stringify(a.response), isCorrect, now);
      if (isCorrect) correctCount += 1;
    }
    insertStmt.finalize((e)=>{
      if (e) return res.status(500).json({ error: 'Insert error' });

      // Lock tab
      db.get('SELECT tabs_locked_json, started_at FROM progress WHERE user_id = ?', [req.user.id], (err2, prog) => {
        let locked = {};
        let started_at = prog?.started_at;
        if (prog) {
          try { locked = JSON.parse(prog.tabs_locked_json || '{}'); } catch { locked = {}; }
        }
        locked[String(tabNum)] = true;

        const tabsLockedJson = JSON.stringify(locked);
        if (!prog) {
          db.run('INSERT INTO progress (user_id, started_at, tabs_locked_json) VALUES (?,?,?)',
            [req.user.id, new Date().toISOString(), tabsLockedJson]);
        } else {
          db.run('UPDATE progress SET tabs_locked_json = ? WHERE user_id = ?', [tabsLockedJson, req.user.id]);
        }
        res.json({ ok: true, tabLocked: tabNum, correctCount });
      });
    });
  });
});

app.get('/api/status', authRequired, (req, res) => {
  db.get('SELECT tabs_locked_json, started_at, finished_at FROM progress WHERE user_id = ?', [req.user.id], (err, prog) => {
    let locked = {};
    if (prog) {
      try { locked = JSON.parse(prog.tabs_locked_json || '{}'); } catch { locked = {}; }
    }
    res.json({ locked, started_at: prog?.started_at, finished_at: prog?.finished_at });
  });
});

app.post('/api/finish', authRequired, (req, res) => {
  // compute results
  db.get('SELECT started_at, finished_at FROM progress WHERE user_id = ?', [req.user.id], (err, prog) => {
    const finished_at = new Date().toISOString();
    const started_at = prog?.started_at || finished_at;
    db.get('SELECT COUNT(*) AS score FROM answers WHERE user_id = ? AND is_correct = 1', [req.user.id], (err2, row) => {
      const score = row?.score || 0;
      const totalTimeMs = Math.max(0, new Date(finished_at) - new Date(started_at));
      db.run('UPDATE progress SET finished_at = ? WHERE user_id = ?', [finished_at, req.user.id]);
      db.run('INSERT OR REPLACE INTO results (user_id,total_score,total_time_ms) VALUES (?,?,?)', [req.user.id, score, totalTimeMs], function(e3){
        if (e3) return res.status(500).json({ error: 'Result save error' });
        res.json({ ok: true });
      });
    });
  });
});

// Leaderboard logic
function recomputeRanks(cb) {
  db.all('SELECT users.id as user_id, users.name, users.roll, results.total_score, results.total_time_ms FROM results JOIN users ON users.id = results.user_id ORDER BY results.total_score DESC, results.total_time_ms ASC', [], (err, rows) => {
    if (err) return cb(err);
    let rank = 1;
    const updates = [];
    for (const r of rows) {
      updates.push(new Promise((resolve,reject)=>{
        db.run('UPDATE results SET rank = ? WHERE user_id = ?', [rank++, r.user_id], (e)=> e?reject(e):resolve());
      }));
    }
    Promise.all(updates).then(()=>cb(null)).catch(cb);
  });
}

app.post('/api/admin/publish_leaderboard', adminRequired, (req, res) => {
  recomputeRanks((err)=>{
    if (err) return res.status(500).json({ error: 'Rank compute failed' });
    db.run('INSERT OR REPLACE INTO settings (key,value) VALUES ("leaderboard_published","true")', [], (e)=>{
      if (e) return res.status(500).json({ error: 'Publish failed' });
      res.json({ ok: true });
    });
  });
});

app.get('/api/leaderboard', (req, res) => {
  db.get('SELECT value FROM settings WHERE key = "leaderboard_published"', [], (err, row) => {
    const published = row?.value === 'true';
    if (!published) return res.json({ published: false, leaderboard: [] });
    db.all('SELECT users.name, users.roll, results.total_score, results.total_time_ms, results.rank FROM results JOIN users ON users.id = results.user_id ORDER BY results.rank ASC', [], (err2, rows) => {
      if (err2) return res.status(500).json({ error: 'DB error' });
      res.json({ published: true, leaderboard: rows });
    });
  });
});

// Review data (only after published)
app.get('/api/review', authRequired, (req, res) => {
  db.get('SELECT value FROM settings WHERE key = "leaderboard_published"', [], (err, row) => {
    const published = row?.value === 'true';
    if (!published) return res.status(403).json({ error: 'Not available yet' });
    db.all('SELECT q.id, q.tab, q.type, q.text, q.options_json, q.answers_json, a.response_json FROM questions q LEFT JOIN answers a ON a.question_id = q.id AND a.user_id = ? ORDER BY q.tab, q.id', [req.user.id], (err2, rows) => {
      if (err2) return res.status(500).json({ error: 'DB error' });
      const items = rows.map(r => ({
        id: r.id,
        tab: r.tab,
        type: r.type,
        text: r.text,
        options: JSON.parse(r.options_json || '[]'),
        correct: JSON.parse(r.answers_json || '[]'),
        response: r.response_json ? JSON.parse(r.response_json) : null
      }));
      res.json({ items });
    });
  });
});

// Admin CSV upload/reset/export
const upload = multer({ dest: 'uploads/' });
app.post('/api/admin/upload_csv', adminRequired, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const results = [];
  fs.createReadStream(req.file.path)
    .pipe(parse({ columns: true, trim: true }))
    .on('data', (row) => {
      results.push(row);
    })
    .on('end', () => {
      const stmt = db.prepare('INSERT INTO questions (tab,type,text,options_json,answers_json,points) VALUES (?,?,?,?,?,1)');
      for (const r of results) {
        const tab = parseInt(r.tab, 10);
        const type = String(r.question_type).trim();
        const text = String(r.question_text).trim();
        const options_json = r.options && r.options.trim() ? r.options : '[]';
        const answers_json = r.answer && r.answer.trim() ? r.answer : '[]';
        stmt.run(tab, type, text, options_json, answers_json);
      }
      stmt.finalize((e)=>{
        fs.unlinkSync(req.file.path);
        if (e) return res.status(500).json({ error: 'Insert error' });
        res.json({ ok: true, inserted: results.length });
      });
    })
    .on('error', (e) => {
      res.status(500).json({ error: 'CSV parse error' });
    });
});

app.post('/api/admin/reset', adminRequired, (req, res) => {
  db.serialize(()=>{
    db.run('DELETE FROM answers');
    db.run('DELETE FROM progress');
    db.run('DELETE FROM results');
    db.run('DELETE FROM settings WHERE key = "leaderboard_published"');
    res.json({ ok: true });
  });
});

app.get('/api/admin/export', adminRequired, (req, res) => {
  db.all('SELECT users.name, users.roll, users.email, results.total_score, results.total_time_ms, results.rank FROM results JOIN users ON users.id = results.user_id ORDER BY results.rank ASC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const csv = ['name,roll,email,total_score,total_time_ms,rank']
      .concat(rows.map(r=>[r.name,r.roll,r.email,r.total_score,r.total_time_ms,r.rank].join(',')))
      .join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="results.csv"');
    res.send(csv);
  });
});
// Serve static files and fallback
app.use(express.static('public'));

app.get('*', (req, res) => {
  res.sendFile(path.resolve('public/index.html'));
});
// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
