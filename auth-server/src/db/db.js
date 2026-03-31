import Database from 'better-sqlite3';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const db = new Database(join(__dirname, '../../data.db'));

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema ──────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    UNIQUE NOT NULL,
    password_hash TEXT  NOT NULL,
    created_at  TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS auth_codes (
    code            TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    code_challenge  TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    scope           TEXT,
    user_id         INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    used            INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    client_id   TEXT NOT NULL,
    scope       TEXT,
    expires_at  INTEGER NOT NULL,
    revoked     INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ── Seed test user ──────────────────────────────────────────
const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get('alice');
if (!existingUser) {
  const hash = bcrypt.hashSync('password123', 10);
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('alice', hash);
  console.log('🌱 Seeded test user: alice / password123');
}

export default db;
