
import fs from 'fs';
import path from 'path';
import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_PATH = process.env.SQLITE_PATH || './db/quiz.db';

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new sqlite3.Database(DB_PATH);

const schema = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf-8');

db.serialize(() => {
  db.exec(schema, (err) => {
    if (err) {
      console.error('Schema error:', err);
      process.exit(1);
    }
    console.log('Database initialized at', DB_PATH);
    process.exit(0);
  });
});
