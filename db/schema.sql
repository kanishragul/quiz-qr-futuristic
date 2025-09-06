PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  roll TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tab INTEGER NOT NULL,                      -- 1..5
  type TEXT NOT NULL,                        -- mcq_single, mcq_multi, true_false, short_text
  text TEXT NOT NULL,
  options_json TEXT NOT NULL DEFAULT '[]',   -- JSON array of options (if applicable)
  answers_json TEXT NOT NULL,                -- JSON array of correct answers
  points INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS answers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  question_id INTEGER NOT NULL,
  tab INTEGER NOT NULL,
  response_json TEXT NOT NULL,               -- JSON array or string depending on type
  is_correct INTEGER NOT NULL,               -- 0/1
  submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS progress (
  user_id INTEGER PRIMARY KEY,
  started_at DATETIME,
  finished_at DATETIME,
  tabs_locked_json TEXT NOT NULL DEFAULT '{}',  -- {"1": true, "2": false, ...}
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS results (
  user_id INTEGER PRIMARY KEY,
  total_score INTEGER NOT NULL,
  total_time_ms INTEGER NOT NULL,
  rank INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
