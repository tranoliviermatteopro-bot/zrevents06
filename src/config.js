'use strict';

// ─── Validation des variables d'environnement ─────────────────────────────────
const REQUIRED = ['JWT_SECRET', 'SMTP_HOST', 'SMTP_USER', 'SMTP_PASS'];

for (const key of REQUIRED) {
  if (!process.env[key]) {
    console.warn(`[config] ⚠️  Variable manquante : ${key}`);
  }
}

module.exports = {
  PORT:            parseInt(process.env.PORT || '3000', 10),
  NODE_ENV:        process.env.NODE_ENV || 'development',
  IS_PROD:         process.env.NODE_ENV === 'production',

  // Auth
  JWT_SECRET:      process.env.JWT_SECRET || 'dev-secret-changez-en-prod',
  BASE_URL:        process.env.BASE_URL   || 'http://localhost:3000',

  // SMTP
  SMTP: {
    host:   process.env.SMTP_HOST,
    port:   parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
  },

  // Discord bot
  DISCORD_BOT_URL: process.env.DISCORD_BOT_URL || 'http://localhost:3001',
  DISCORD_API_KEY: process.env.DISCORD_API_KEY || '',
};
