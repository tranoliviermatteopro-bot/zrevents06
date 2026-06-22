// logger.js — Envoie les logs vers le Log Dashboard centralisé
// Variables d'environnement requises :
//   LOG_DASHBOARD_URL  = https://log-dashboard-tmye.onrender.com
//   LOG_DASHBOARD_KEY  = la clé API statique définie dans STATIC_KEYS sur le dashboard

const DASHBOARD_URL = process.env.LOG_DASHBOARD_URL || '';
const DASHBOARD_KEY = process.env.LOG_DASHBOARD_KEY || '';

async function log(level, message, meta = null) {
  if (!DASHBOARD_URL || !DASHBOARD_KEY) return;
  try {
    await fetch(`${DASHBOARD_URL}/api/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': DASHBOARD_KEY,
      },
      body: JSON.stringify({ level, message, meta }),
    });
  } catch {
    // Ne pas crasher si le dashboard est indisponible
  }
}

module.exports = {
  debug: (msg, meta) => log('debug', msg, meta),
  info:  (msg, meta) => log('info',  msg, meta),
  warn:  (msg, meta) => log('warn',  msg, meta),
  error: (msg, meta) => log('error', msg, meta),
  critical: (msg, meta) => log('critical', msg, meta),
};
