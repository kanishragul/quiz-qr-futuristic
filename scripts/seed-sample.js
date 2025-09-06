
import fs from 'fs';
import path from 'path';
import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_PATH = process.env.SQLITE_PATH || './db/quiz.db';
const db = new sqlite3.Database(DB_PATH);

const sampleQuestions = [
  // Tab 1
  {tab:1,type:'mcq_single',text:'What is 2 + 2?',options:['1','2','4','8'],answers:['4']},
  {tab:1,type:'true_false',text:'The earth is flat.',options:[],answers:['false']},
  // Tab 2
  {tab:2,type:'mcq_multi',text:'Select vowels',options:['a','b','c','e'],answers:['a','e']},
  {tab:2,type:'short_text',text:'Full form of CPU?',options:[],answers:['central processing unit','c.p.u']},
  // Tab 3
  {tab:3,type:'mcq_single',text:'Capital of India?',options:['Delhi','Mumbai','Kolkata','Chennai'],answers:['Delhi']},
  // Tab 4
  {tab:4,type:'true_false',text:'Water boils at 100°C at sea level.',options:[],answers:['true']},
  // Tab 5
  {tab:5,type:'mcq_single',text:'Which is an even number?',options:['3','5','10','9'],answers:['10']},
];

db.serialize(() => {
  const stmt = db.prepare(`INSERT INTO questions (tab,type,text,options_json,answers_json,points) VALUES (?,?,?,?,?,1)`);
  for (const q of sampleQuestions) {
    stmt.run(q.tab, q.type, q.text, JSON.stringify(q.options || []), JSON.stringify(q.answers));
  }
  stmt.finalize((err) => {
    if (err) {
      console.error('Seed error:', err);
      process.exit(1);
    }
    console.log('Sample questions seeded.');
    process.exit(0);
  });
});
