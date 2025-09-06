
# Quiz QR Futuristic (Ready-to-Run)

A lightweight, free-hosting friendly quiz platform with:
- QR code big-screen join
- Email/password auth
- 5 tabs (games/sections), free navigation, each locks after submit
- Answer protection (server-side only)
- Score = 1 point per question, no negative
- Ranking = score desc, time asc (fastest wins on tie)
- Final leaderboard (not live)
- Review mode (post-leaderboard): show student's answers vs correct side-by-side
- Admin: CSV upload, reset leaderboard, export results
- Futuristic UI (neon, smooth animations)

## Quick Start (Local)

1) Install Node 18+
2) `npm install`
3) Copy `.env.example` to `.env` and edit if needed (defaults work)
4) Initialize DB:
   - `npm run init:db`
   - `npm run seed:sample`  (loads sample 5-tab questions)
5) Run:
   - `npm run dev`
6) Open:
   - Big Screen / Home (QR): http://localhost:3000/
   - Login / Signup: http://localhost:3000/login.html
   - Student Dashboard: http://localhost:3000/dashboard.html
   - Leaderboard (projector): http://localhost:3000/leaderboard.html
   - Review Page: http://localhost:3000/review.html
   - Admin Panel: http://localhost:3000/admin.html

## Deploy (Free Hosting)

- Frontend (static `/public`) -> Vercel (or GitHub Pages)
- Backend (`server.js`) -> Render/Railway
- DB -> SQLite file on backend (simple) or switch to managed Postgres later

## CSV Format

Upload in Admin panel or POST `/api/admin/upload_csv` with form-data `file`:

```
tab,question_type,question_text,options,answer
1,mcq_single,What is 2+2?,"["1","2","4","8"]","["4"]"
1,mcq_multi,Select prime numbers,"["2","3","4","6"]","["2","3"]"
2,true_false,The sky is blue.,[],["true"]
2,short_text,Full form of CPU?,[],["central processing unit","c.p.u"]
```

- `question_type`: `mcq_single` | `mcq_multi` | `true_false` | `short_text`
- `options`: JSON array of strings (empty for non-MCQ)
- `answer`: JSON array of acceptable answers (strings). For `true_false`, use `["true"]` or `["false"]`.

## Notes
- Review mode unlocks only after admin publishes (end of quiz).
- All scoring/validation happens on server. No correct answers sent to client until review.
- JWT auth via cookies; secure in production with HTTPS.
