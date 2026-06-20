'use strict';

const initSqlJs = require('sql.js');
const path      = require('path');
const fs        = require('fs');

const DB_PATH = path.join(__dirname, '..', 'data.db');

let _db;

// ─── Sauvegarde sur disque ────────────────────────────────────────────────────
function save() {
  fs.writeFileSync(DB_PATH, Buffer.from(_db.export()));
}

// ─── Interface synchrone ──────────────────────────────────────────────────────
const db = {
  /** Exécute un DDL ou une requête sans résultat attendu. */
  exec(sql) {
    _db.run(sql);
    save();
  },

  /** Retourne la première ligne correspondante ou null. */
  get(sql, ...params) {
    const stmt = _db.prepare(sql);
    stmt.bind(params);
    const row = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return row;
  },

  /** Retourne toutes les lignes correspondantes. */
  all(sql, ...params) {
    const stmt = _db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  },

  /** Exécute une requête de modification (INSERT / UPDATE / DELETE). */
  run(sql, ...params) {
    const stmt = _db.prepare(sql);
    stmt.run(params);
    stmt.free();
    save();
  },
};

// ─── Initialisation ───────────────────────────────────────────────────────────
async function initDatabase() {
  const SQL = await initSqlJs();
  const buf = fs.existsSync(DB_PATH) ? fs.readFileSync(DB_PATH) : null;
  _db       = buf ? new SQL.Database(buf) : new SQL.Database();

  _db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      prenom        TEXT    NOT NULL,
      nom           TEXT    NOT NULL,
      email         TEXT    UNIQUE NOT NULL,
      password_hash TEXT    NOT NULL,
      email_verifie INTEGER DEFAULT 0,
      email_token   TEXT,
      created_at    TEXT    DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL,
      token      TEXT    NOT NULL,
      expires_at TEXT    NOT NULL,
      used       INTEGER DEFAULT 0,
      created_at TEXT    DEFAULT (datetime('now'))
    );
  `);

  save();
  console.log('[db] ✅ Base de données prête');
}

module.exports = { db, initDatabase };
