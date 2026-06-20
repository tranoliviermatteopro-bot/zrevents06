const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'data.db');

initSqlJs().then(SQL => {
  const buf = fs.readFileSync(DB_PATH);
  const db = new SQL.Database(buf);
  const stmt = db.prepare('SELECT id, email, email_verifie, email_token FROM users');
  while (stmt.step()) {
    const r = stmt.getAsObject();
    console.log(JSON.stringify(r));
  }
  stmt.free();
  db.close();
});
