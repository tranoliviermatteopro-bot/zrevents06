// Script temporaire : active le compte test en base
const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'data.db');

initSqlJs().then(SQL => {
  const buf = fs.readFileSync(DB_PATH);
  const db = new SQL.Database(buf);

  // Affiche les utilisateurs
  const stmt = db.prepare('SELECT id, prenom, nom, email, email_verifie FROM users');
  console.log('\n=== Utilisateurs en base ===');
  while (stmt.step()) {
    const row = stmt.getAsObject();
    console.log(`[${row.id}] ${row.prenom} ${row.nom} <${row.email}> — vérifié: ${row.email_verifie}`);
  }
  stmt.free();

  // Active tous les comptes non vérifiés
  db.run('UPDATE users SET email_verifie = 1, email_token = NULL WHERE email_verifie = 0');
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));

  console.log('\n✅ Tous les comptes ont été activés.');
  db.close();
});
