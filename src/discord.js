'use strict';

const { DISCORD_BOT_URL, DISCORD_API_KEY } = require('./config');

/**
 * Envoie un log structuré au bot Discord.
 * Silencieux en cas d'erreur réseau pour ne jamais bloquer l'app.
 *
 * @param {'info'|'warning'|'error'|'access'} level
 * @param {string} message
 * @param {object} [extra]  url, method, status, ip, user, duration, stack, extra
 */
async function discordLog(level, message, extra = {}) {
  if (!DISCORD_API_KEY) return;

  try {
    await fetch(`${DISCORD_BOT_URL}/log`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key':    DISCORD_API_KEY,
      },
      body: JSON.stringify({
        level,
        site:      'zrevents06',
        env:       process.env.NODE_ENV || 'production',
        message,
        timestamp: new Date().toISOString(),
        ...extra,
      }),
    });
  } catch {
    // Intentionellement silencieux — le bot Discord est optionnel
  }
}

/**
 * Envoie un événement devis au bot Discord.
 * @param {'valide'|'refuse'|'en-attente'} status
 * @param {{ client?: string, montant?: string, description?: string }} data
 */
async function discordDevis(status, data = {}) {
  if (!DISCORD_API_KEY) return;

  try {
    await fetch(`${DISCORD_BOT_URL}/devis`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key':    DISCORD_API_KEY,
      },
      body: JSON.stringify({
        status,
        site: 'zrevents06',
        ...data,
      }),
    });
  } catch {
    // Silencieux
  }
}

module.exports = { discordLog, discordDevis };
