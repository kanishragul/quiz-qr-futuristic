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
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';
const DB_PATH = process.env.SQLITE_PATH || './db/quiz.db';
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || `http://localhost:${PORT}`;

// Ensure DB folder exists
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new sqlite3.Database(DB_PATH);

// ✅ Auto-create schema if not exists
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    roll TEXT,
    email TEXT UNIQUE,
    password_hash TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tab INT,
    type TEXT,
    text TEXT,
    options_json TEXT,
    answers_json TEXT,
    points INT DEFAULT 1
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INT,
    question_id INT,
    tab INT,
    response_json TEXT,
    is_correct INT,
    submitted_at TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS progress (
    user_id INT PRIMARY KEY,
    started_at TEXT,
    finished_at TEXT,
    tabs_locked_json TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS results (
    user_id INT PRIMARY KEY,
    total_score INT,
    total_time_ms INT,
    rank INT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);
});

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

// ---- QR code endpoint ----
app.get('/api/qr', async (req, res) => {
  const joinUrl = `${req.protocol}://${req.get('host')}/participant.html`;
  try {
    const dataUrl = await QRCode.toDataURL(joinUrl, { margin: 2, scale: 8 });
    res.json({ joinUrl, dataUrl });
  } catch (e) {
    console.error("QR generation failed:", e);
    res.status(500).json({ error: 'QR generation failed' });
  }
});

// === Auth helpers ===
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
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
function adminRequired(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.email && decoded.email.endsWith('@admin.local')) {
      req.user = decoded;
      return next();
    }
    return res.status(403).json({ error: 'Admin only' });
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// === Auth APIs ===
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

// ... (⚡ keep all your quiz, submit, leaderboard, review, admin CSV APIs unchanged)

// ✅ SPA fallback (important for Render)
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
