require('dotenv').config();
const helmet = require('helmet');
const logger = require('./logger');

// ─── Discord Log (legacy) ─────────────────────────────────────────────────────
const DISCORD_BOT_URL = process.env.DISCORD_BOT_URL || 'http://localhost:3001';
const DISCORD_API_KEY = process.env.DISCORD_API_KEY || '';

async function discordLog(level, message, extra = {}) {
  // Envoyer au Log Dashboard centralisé
  logger[level] ? logger[level](message, extra) : logger.info(message, extra);

  // Garder Discord si configuré
  if (!DISCORD_API_KEY) return;
  try {
    await fetch(`${DISCORD_BOT_URL}/log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': DISCORD_API_KEY },
      body: JSON.stringify({ level, site: 'zrevents06', message, ...extra }),
    });
  } catch {}
}

function dbLog(level, message, extra = {}) {
  pool.query(
    'INSERT INTO site_logs (level, message, url, method, status, ip, extra) VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [level, message, extra.url || null, extra.method || null, extra.status || null,
     extra.ip || null, extra.extra ? JSON.stringify(extra.extra) : null]
  ).catch(() => {});
}

const express      = require('express');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const bcrypt       = require('bcryptjs');
const nodemailer   = require('nodemailer');
const rateLimit    = require('express-rate-limit');
const dns          = require('dns').promises;
const crypto       = require('crypto');
const path         = require('path');
const { Pool }     = require('pg');
const passport     = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const expressSession = require('express-session');

// ─── Config ───────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-changez-en-prod';
const BASE_URL   = process.env.BASE_URL   || 'http://localhost:3000';
const SMTP_FROM  = process.env.SMTP_FROM  || process.env.SMTP_USER;

const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// ─── PostgreSQL Pool ──────────────────────────────────────────────────────────
// Isoler dans le schéma "zrevents" via options dans la connection string (évite
// le bug pool.on('connect') qui bloque le premier pool.query en pg 8.x)
const _dbUrl = process.env.DATABASE_URL || '';
const _dbUrlWithSchema = _dbUrl
  ? _dbUrl + (_dbUrl.includes('?') ? '&' : '?') + 'options=-c+search_path%3Dzrevents%2Cpublic'
  : '';

const pool = new Pool({
  connectionString: _dbUrlWithSchema || undefined,
  ssl: _dbUrl ? { rejectUnauthorized: false } : false,
});

function toPositional(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

const db = {
  async get(sql, ...params) {
    const { rows } = await pool.query(toPositional(sql), params);
    return rows[0] || null;
  },
  async all(sql, ...params) {
    const { rows } = await pool.query(toPositional(sql), params);
    return rows;
  },
  async run(sql, ...params) {
    await pool.query(toPositional(sql), params);
  },
  async exec(sql) {
    await pool.query(sql);
  },
};

// ─── Application Express ──────────────────────────────────────────────────────
const app = express();

// ─── Sécurité : headers HTTP ──────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],   // inline scripts dans les HTML
      scriptSrcAttr: ["'unsafe-inline'"],             // autorise onclick="..." dans le HTML
      styleSrc:    ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:     ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:      ["'self'", 'data:', 'https:'],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // évite de casser les ressources Google Fonts
}));

// ─── Rate limiter global (anti-scraping / DDoS) ───────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requêtes. Réessayez dans 15 minutes.' },
});
app.use(globalLimiter);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(expressSession({
  secret: process.env.SESSION_SECRET || process.env.JWT_SECRET || 'oauth-state-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    maxAge:   10 * 60 * 1000,
  },
}));

// Middleware logs Discord (erreurs HTTP)
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const status = res.statusCode;
    if (status >= 500) {
      discordLog('error', req.method + ' ' + req.path + ' -> ' + status, {
        method: req.method, url: req.originalUrl, status, ip: req.ip, duration: Date.now() - start,
      });
    } else if (status === 401 || status === 403) {
      discordLog('warning', 'Acces refuse ' + req.method + ' ' + req.path + ' -> ' + status, {
        method: req.method, url: req.originalUrl, status, ip: req.ip,
      });
    }
  });
  next();
});

app.use(express.static(path.join(__dirname, 'livraison'), { index: 'index_4.html' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      10,
  message:  { error: 'Trop de tentatives. Reessayez dans 15 minutes.' },
  standardHeaders: true,
  legacyHeaders:   false,
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

async function hasMxRecord(email) {
  const domain = email.split('@')[1];
  if (!domain) return false;
  try {
    const records = await dns.resolveMx(domain);
    return Array.isArray(records) && records.length > 0;
  } catch {
    return false;
  }
}

function setAuthCookie(res, user, remember = false) {
  const token = jwt.sign(
    { id: user.id, email: user.email, prenom: user.prenom },
    JWT_SECRET,
    { expiresIn: remember ? '30d' : '24h' }
  );
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge:   remember ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ error: 'Non connecte.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie('auth_token');
    res.status(401).json({ error: 'Session expiree.' });
  }
}

// ─── Google OAuth ─────────────────────────────────────────────────────────────
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  app.use(passport.initialize());

  passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  `${BASE_URL}/auth/google/callback`,
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email    = profile.emails?.[0]?.value || '';
      const prenom   = profile.name?.givenName || profile.displayName || 'Utilisateur';
      const nom      = profile.name?.familyName || '';
      const googleId = profile.id;

      let user = await db.get('SELECT * FROM users WHERE google_id = ?', googleId);
      if (!user && email) user = await db.get('SELECT * FROM users WHERE email = ?', email.toLowerCase());

      if (!user) {
        await db.run(
          'INSERT INTO users (prenom, nom, email, google_id, email_verifie, password_hash) VALUES (?, ?, ?, ?, 1, ?)',
          prenom, nom, email.toLowerCase(), googleId, ''
        );
        user = await db.get('SELECT * FROM users WHERE google_id = ?', googleId);
      } else if (!user.google_id) {
        await db.run('UPDATE users SET google_id = ?, email_verifie = 1 WHERE id = ?', googleId, user.id);
        user = await db.get('SELECT * FROM users WHERE id = ?', user.id);
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }));

  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

  app.get('/auth/google/callback', (req, res, next) => {
    passport.authenticate('google', { session: false }, (err, user) => {
      if (err || !user) {
        console.error('[google-oauth] Erreur:', err?.message);
        return res.redirect('/connexion.html?error=google');
      }
      setAuthCookie(res, user, false);
      discordLog('info', 'Connexion Google : ' + user.email, { user: user.email });
      res.redirect('/espace-membre.html');
    })(req, res, next);
  });
}

// ─── Route : Inscription ──────────────────────────────────────────────────────
app.post('/api/inscription', authLimiter, async (req, res) => {
  const { prenom, nom, email, password, password_confirm } = req.body;

  if (!prenom?.trim() || !nom?.trim() || !email?.trim() || !password) {
    return res.status(400).json({ error: 'Tous les champs sont requis.' });
  }
  if (prenom.trim().length > 50 || nom.trim().length > 50) {
    return res.status(400).json({ error: 'Prénom et nom limités à 50 caractères.' });
  }
  if (email.length > 254) {
    return res.status(400).json({ error: 'Adresse e-mail trop longue.' });
  }
  if (password.length > 128) {
    return res.status(400).json({ error: 'Mot de passe trop long (max 128 caractères).' });
  }
  if (!EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'Adresse e-mail invalide.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caracteres.' });
  }
  if (password !== password_confirm) {
    return res.status(400).json({ error: 'Les mots de passe ne correspondent pas.' });
  }

  const hasMx = await hasMxRecord(email);
  if (!hasMx) {
    return res.status(400).json({ error: 'Aucun serveur e-mail trouve pour ce domaine.' });
  }

  const existing = await db.get('SELECT id FROM users WHERE email = ?', email.toLowerCase());
  if (existing) {
    return res.status(400).json({ error: 'Un compte existe deja avec cet e-mail.' });
  }

  const password_hash  = await bcrypt.hash(password, 12);
  const smtpConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
  const needsVerif     = process.env.NODE_ENV === 'production' && smtpConfigured;
  const email_token    = needsVerif ? crypto.randomBytes(32).toString('hex') : null;

  await db.run(
    'INSERT INTO users (prenom, nom, email, password_hash, email_token, email_verifie) VALUES (?, ?, ?, ?, ?, ?)',
    prenom.trim(), nom.trim(), email.toLowerCase(), password_hash, email_token, needsVerif ? 0 : 1
  );

  if (!needsVerif) {
    await discordLog('info', 'Nouvelle inscription (auto-verified) : ' + email, { user: email });
    return res.json({ success: true, message: 'Compte créé et activé ! Vous pouvez vous connecter.' });
  }

  const confirmUrl = `${BASE_URL}/api/confirmer-email?token=${email_token}`;
  try {
    await transporter.sendMail({
      from:    SMTP_FROM,
      to:      email,
      subject: 'Confirmez votre adresse e-mail - zrevents06',
      html:    emailConfirmationHtml(prenom.trim(), confirmUrl),
    });
    await discordLog('info', 'Nouvelle inscription : ' + email, { user: email });
    return res.json({ success: true, message: 'Compte créé ! Vérifiez vos e-mails pour activer votre compte.' });
  } catch (err) {
    // L'email a échoué : on active quand même le compte pour ne pas bloquer l'utilisateur
    console.error('[mail] Erreur envoi confirmation:', err.message);
    await discordLog('error', 'Erreur envoi e-mail confirmation — compte auto-activé', { message: err.message, user: email });
    await db.run('UPDATE users SET email_verifie = 1, email_token = NULL WHERE email = ?', email.toLowerCase());
    return res.json({ success: true, message: 'Compte créé et activé ! (e-mail non envoyé)' });
  }
});

// ─── Route : Confirmation e-mail ──────────────────────────────────────────────
app.get('/api/confirmer-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.redirect('/connexion.html?error=lien_invalide');

  const user = await db.get('SELECT id FROM users WHERE email_token = ? AND email_verifie = 0', token);
  if (!user) return res.redirect('/connexion.html?error=lien_invalide');

  await db.run('UPDATE users SET email_verifie = 1, email_token = NULL WHERE id = ?', user.id);
  res.redirect('/connexion.html?confirmed=1');
});

// ─── Route : Connexion ────────────────────────────────────────────────────────
app.post('/api/connexion', authLimiter, async (req, res) => {
  const { email, password, remember } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'E-mail et mot de passe requis.' });
  }

  const user = await db.get('SELECT * FROM users WHERE email = ?', email.toLowerCase());

  const hashToCheck = user?.password_hash || '$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.';
  const valid       = await bcrypt.compare(password, hashToCheck);

  if (!user || !valid) {
    return res.status(401).json({ error: 'E-mail ou mot de passe incorrect.' });
  }
  if (!user.email_verifie) {
    return res.status(403).json({ error: 'Veuillez confirmer votre adresse e-mail.' });
  }

  setAuthCookie(res, user, remember === 'true' || remember === true);
  await discordLog('info', 'Connexion : ' + email, { user: email, ip: req.ip });
  res.json({ success: true, prenom: user.prenom });
});

// ─── Route : Deconnexion ──────────────────────────────────────────────────────
app.post('/api/deconnexion', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true });
});

// ─── Route : Utilisateur connecte ─────────────────────────────────────────────
app.get('/api/me', requireAuth, async (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, prenom: req.user.prenom });
});

app.get('/api/me/details', requireAuth, async (req, res) => {
  const user = await db.get('SELECT prenom, nom, email, password_hash, google_id FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'Introuvable.' });
  res.json({
    prenom: user.prenom,
    nom: user.nom,
    email: user.email,
    has_password: !!(user.password_hash),
    has_google: !!(user.google_id),
  });
});

// ─── Route : Mot de passe oublie ──────────────────────────────────────────────
app.post('/api/mot-de-passe-oublie', authLimiter, async (req, res) => {
  res.json({ success: true });

  const { email } = req.body;
  if (!email || !EMAIL_RE.test(email)) return;

  const user = await db.get(
    'SELECT id, prenom FROM users WHERE email = ? AND email_verifie = 1',
    email.toLowerCase()
  );
  if (!user) return;

  const token      = crypto.randomBytes(32).toString('hex');
  const expires_at = new Date(Date.now() + 30 * 60 * 1000).toISOString();

  await db.run('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0', user.id);
  await db.run(
    'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
    user.id, token, expires_at
  );

  const resetUrl = `${BASE_URL}/reinitialiser-mot-de-passe.html?token=${token}`;
  try {
    await transporter.sendMail({
      from:    SMTP_FROM,
      to:      email,
      subject: 'Reinitialisation de votre mot de passe - zrevents06',
      html:    emailResetHtml(user.prenom, resetUrl),
    });
  } catch (err) {
    console.error('[mail] Erreur envoi reset:', err.message);
    await discordLog('error', 'Erreur envoi e-mail reset', { message: err.message });
  }
});

// ─── Route : Reinitialisation mot de passe ────────────────────────────────────
app.post('/api/reinitialiser-mot-de-passe', authLimiter, async (req, res) => {
  const { token, password, password_confirm } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token manquant.' });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caracteres.' });
  }
  if (password !== password_confirm) {
    return res.status(400).json({ error: 'Les mots de passe ne correspondent pas.' });
  }

  const record = await db.get(
    'SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token = ?',
    token
  );

  if (!record || record.used || new Date(record.expires_at) <= new Date()) {
    return res.status(400).json({ error: 'Ce lien est invalide ou expire. Faites une nouvelle demande.' });
  }

  const password_hash = await bcrypt.hash(password, 12);
  await db.run('UPDATE users SET password_hash = ? WHERE id = ?', password_hash, record.user_id);
  await db.run('UPDATE password_reset_tokens SET used = 1 WHERE id = ?', record.id);

  res.json({ success: true });
});

// ─── Templates e-mail ─────────────────────────────────────────────────────────
function emailConfirmationHtml(prenom, url) {
  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Confirmez votre e-mail</title></head>
<body style="margin:0;padding:0;background:#F5EDE0;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F5EDE0;padding:40px 20px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#FDF8F2;border-radius:16px;overflow:hidden;box-shadow:0 8px 40px rgba(61,35,20,0.12);max-width:100%;">
  <tr><td style="background:#3D2314;padding:32px 40px;text-align:center;">
    <p style="font-family:Georgia,serif;font-size:24px;color:#D4A574;margin:0;letter-spacing:0.1em;">zrevents06</p>
    <p style="font-size:11px;letter-spacing:0.3em;text-transform:uppercase;color:rgba(253,248,242,0.5);margin:8px 0 0;">Artisan Patissier</p>
  </td></tr>
  <tr><td style="padding:40px 40px 32px;">
    <h1 style="font-family:Georgia,serif;font-size:26px;color:#3D2314;margin:0 0 12px;font-weight:700;">Bienvenue, ${prenom} !</h1>
    <p style="color:#3D2314;opacity:0.72;line-height:1.75;font-size:15px;margin:0 0 28px;">
      Merci de rejoindre notre communaute gourmande. Cliquez ci-dessous pour confirmer votre adresse e-mail et activer votre compte.
    </p>
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:0 0 32px;">
      <a href="${url}" style="display:inline-block;background:linear-gradient(135deg,#C4956A,#D4A574);color:#FDF8F2;text-decoration:none;font-weight:700;font-size:13px;letter-spacing:0.1em;text-transform:uppercase;padding:15px 40px;border-radius:50px;">
        Confirmer mon adresse e-mail
      </a>
    </td></tr></table>
    <p style="color:#3D2314;opacity:0.45;font-size:12px;line-height:1.6;border-top:1px solid rgba(196,149,106,0.2);padding-top:20px;">
      Si le bouton ne fonctionne pas, copiez ce lien :<br>
      <a href="${url}" style="color:#C4956A;word-break:break-all;font-size:11px;">${url}</a>
    </p>
    <p style="color:#3D2314;opacity:0.35;font-size:11px;margin-top:12px;">Vous n'avez pas cree de compte ? Ignorez cet e-mail.</p>
  </td></tr>
  <tr><td style="background:#3D2314;padding:20px 40px;text-align:center;">
    <p style="color:rgba(253,248,242,0.35);font-size:11px;margin:0;">© ${new Date().getFullYear()} zrevents06 - Artisan Patissier</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;
}

function emailResetHtml(prenom, url) {
  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Reinitialisation mot de passe</title></head>
<body style="margin:0;padding:0;background:#F5EDE0;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F5EDE0;padding:40px 20px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#FDF8F2;border-radius:16px;overflow:hidden;box-shadow:0 8px 40px rgba(61,35,20,0.12);max-width:100%;">
  <tr><td style="background:#3D2314;padding:32px 40px;text-align:center;">
    <p style="font-family:Georgia,serif;font-size:24px;color:#D4A574;margin:0;letter-spacing:0.1em;">zrevents06</p>
    <p style="font-size:11px;letter-spacing:0.3em;text-transform:uppercase;color:rgba(253,248,242,0.5);margin:8px 0 0;">Artisan Patissier</p>
  </td></tr>
  <tr><td style="padding:40px 40px 32px;">
    <h1 style="font-family:Georgia,serif;font-size:26px;color:#3D2314;margin:0 0 12px;font-weight:700;">Reinitialiser votre mot de passe</h1>
    <p style="color:#3D2314;opacity:0.72;line-height:1.75;font-size:15px;margin:0 0 6px;">Bonjour ${prenom},</p>
    <p style="color:#3D2314;opacity:0.72;line-height:1.75;font-size:15px;margin:0 0 28px;">
      Nous avons recu une demande de reinitialisation de mot de passe. Cliquez ci-dessous pour en choisir un nouveau :
    </p>
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:0 0 32px;">
      <a href="${url}" style="display:inline-block;background:linear-gradient(135deg,#C4956A,#D4A574);color:#FDF8F2;text-decoration:none;font-weight:700;font-size:13px;letter-spacing:0.1em;text-transform:uppercase;padding:15px 40px;border-radius:50px;">
        Reinitialiser mon mot de passe
      </a>
    </td></tr></table>
    <p style="color:#3D2314;opacity:0.45;font-size:12px;line-height:1.6;border-top:1px solid rgba(196,149,106,0.2);padding-top:20px;">
      Ce lien expire dans 30 minutes. Si vous n'avez pas fait cette demande, ignorez cet e-mail.
    </p>
    <p style="color:#3D2314;opacity:0.35;font-size:11px;margin-top:12px;">
      Lien : <a href="${url}" style="color:#C4956A;word-break:break-all;">${url}</a>
    </p>
  </td></tr>
  <tr><td style="background:#3D2314;padding:20px 40px;text-align:center;">
    <p style="color:rgba(253,248,242,0.35);font-size:11px;margin:0;">© ${new Date().getFullYear()} zrevents06 - Artisan Patissier</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;
}

// ─── Route : Modifier profil ──────────────────────────────────────────────────
app.put('/api/profil', requireAuth, async (req, res) => {
  let { prenom, nom } = req.body;
  prenom = prenom?.trim();
  nom    = nom?.trim();
  if (!prenom || !nom) return res.status(400).json({ error: 'Prénom et nom requis.' });
  if (prenom.length > 50 || nom.length > 50) return res.status(400).json({ error: 'Prénom/nom trop long (max 50 car.).' });

  await db.run('UPDATE users SET prenom = ?, nom = ? WHERE id = ?', prenom, nom, req.user.id);
  const user = await db.get('SELECT * FROM users WHERE id = ?', req.user.id);
  // Renouveler le cookie avec les nouvelles infos
  setAuthCookie(res, user, false);
  discordLog('info', 'Profil modifié : ' + user.email, { user: user.email });
  res.json({ success: true, prenom: user.prenom, nom: user.nom });
});

// ─── Route : Changer mot de passe (depuis l'espace membre) ───────────────────
app.put('/api/changer-mot-de-passe', requireAuth, authLimiter, async (req, res) => {
  const { ancien_mdp, nouveau_mdp, nouveau_mdp_confirm } = req.body;
  if (!ancien_mdp || !nouveau_mdp) return res.status(400).json({ error: 'Tous les champs sont requis.' });
  if (nouveau_mdp.length < 8) return res.status(400).json({ error: 'Le nouveau mot de passe doit faire au moins 8 caractères.' });
  if (nouveau_mdp.length > 128) return res.status(400).json({ error: 'Mot de passe trop long.' });
  if (nouveau_mdp !== nouveau_mdp_confirm) return res.status(400).json({ error: 'Les mots de passe ne correspondent pas.' });

  const user = await db.get('SELECT * FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });

  // Les comptes Google sans mot de passe ont un hash vide
  if (!user.password_hash) return res.status(400).json({ error: 'Votre compte est lié à Google. Définissez d\'abord un mot de passe.' });

  const valid = await bcrypt.compare(ancien_mdp, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Ancien mot de passe incorrect.' });

  const hash = await bcrypt.hash(nouveau_mdp, 12);
  await db.run('UPDATE users SET password_hash = ? WHERE id = ?', hash, user.id);
  discordLog('info', 'Mot de passe changé : ' + user.email, { user: user.email });
  res.json({ success: true });
});

// ─── Route : Historique commandes ─────────────────────────────────────────────
app.get('/api/historique', requireAuth, async (req, res) => {
  const commandes = await db.all(
    'SELECT id, reference, description, montant, statut, created_at FROM commandes WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    req.user.id
  );
  res.json({ commandes });
});

// ─── Route : Supprimer compte ─────────────────────────────────────────────────
app.delete('/api/compte', requireAuth, async (req, res) => {
  const { password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });

  // Si le compte a un mot de passe, on le vérifie
  if (user.password_hash) {
    if (!password) return res.status(400).json({ error: 'Mot de passe requis pour confirmer la suppression.' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Mot de passe incorrect.' });
  }

  // Supprimer les données liées
  await db.run('DELETE FROM password_reset_tokens WHERE user_id = ?', user.id);
  await db.run('DELETE FROM commandes WHERE user_id = ?', user.id);
  await db.run('DELETE FROM users WHERE id = ?', user.id);

  discordLog('warning', 'Compte supprimé : ' + user.email, { user: user.email });
  res.clearCookie('auth_token');
  res.json({ success: true });
});

// ─── Route : Définir un mot de passe (comptes Google sans mdp) ───────────────
app.put('/api/definir-mot-de-passe', requireAuth, async (req, res) => {
  const { nouveau_mdp, nouveau_mdp_confirm } = req.body;
  if (!nouveau_mdp) return res.status(400).json({ error: 'Mot de passe requis.' });
  if (nouveau_mdp.length < 8) return res.status(400).json({ error: 'Au moins 8 caractères.' });
  if (nouveau_mdp.length > 128) return res.status(400).json({ error: 'Mot de passe trop long.' });
  if (nouveau_mdp !== nouveau_mdp_confirm) return res.status(400).json({ error: 'Les mots de passe ne correspondent pas.' });

  const user = await db.get('SELECT * FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (user.password_hash) return res.status(400).json({ error: 'Vous avez déjà un mot de passe.' });

  const hash = await bcrypt.hash(nouveau_mdp, 12);
  await db.run('UPDATE users SET password_hash = ? WHERE id = ?', hash, user.id);
  discordLog('info', 'Mot de passe défini (compte Google) : ' + user.email, { user: user.email });
  res.json({ success: true });
});

// ─── Route : Devis ────────────────────────────────────────────────────────────
app.post('/api/devis', async (req, res) => {
  const {
    nom, email, telephone, date_evenement, heure_evenement,
    lieu, nombre_personnes, type_evenement, message,
  } = req.body;
  res.json({ success: true });

  // Sauvegarder en base de données
  try {
    await db.run(
      `INSERT INTO devis (nom, email, telephone, date_evenement, heure_evenement, lieu, nombre_personnes, type_evenement, details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      nom || '', email || '', telephone || '', date_evenement || '',
      heure_evenement || '', lieu || '', nombre_personnes || null,
      type_evenement || '', message || ''
    );
    dbLog('info', `Nouveau devis reçu de ${nom} <${email}>`, { email });
  } catch (err) { console.error('[DEVIS] Erreur save DB:', err); }

  // Notif Discord via webhook direct (→ canal devis-en-attente)
  const webhookUrl = process.env.DISCORD_WEBHOOK_DEVIS;
  if (webhookUrl) {
    try {
      // Résumé court du message (250 premiers caractères)
      const apercu = message
        ? message.replace(/\n+/g, ' ').slice(0, 250) + (message.length > 250 ? '…' : '')
        : '_(aucun détail fourni)_';

      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: '||@here||',
          embeds: [{
            author: {
              name: '✨ zrevents06 — Pâtisserie & Événements',
              icon_url: 'https://zrevents06.onrender.com/favicon.ico',
            },
            title: '🍰  Nouvelle demande de devis',
            description: `> Un client vient de soumettre une demande.\n> Merci de traiter ce devis dans les meilleurs délais ! ⏰`,
            color: 0xc8853a,
            fields: [
              {
                name: '👤  Client',
                value: `\`\`\`${nom || 'Inconnu'}\`\`\``,
                inline: true,
              },
              {
                name: '📧  Email',
                value: `\`\`\`${email || 'non renseigné'}\`\`\``,
                inline: true,
              },
              {
                name: '​',
                value: '​',
                inline: false,
              },
              {
                name: '📋  Détails de la demande',
                value: apercu,
                inline: false,
              },
              {
                name: '​',
                value: '​',
                inline: false,
              },
              {
                name: '⚡  Actions rapides',
                value: [
                  `✅  [**Valider ce devis**](https://zrevents06.onrender.com/admin/devis/valider?email=${encodeURIComponent(email || '')}&nom=${encodeURIComponent(nom || '')})`,
                  `❌  [**Refuser ce devis**](https://zrevents06.onrender.com/admin/devis/refuser?email=${encodeURIComponent(email || '')}&nom=${encodeURIComponent(nom || '')})`,
                ].join('\n'),
                inline: false,
              },
            ],
            thumbnail: { url: 'https://em-content.zobj.net/source/twitter/376/shortcake_1f370.png' },
            footer: {
              text: 'zrevents06.onrender.com  •  Devis en attente de traitement',
            },
            timestamp: new Date().toISOString(),
          }],
        }),
      });
    } catch {}
  }
});

// ─── Suivi des messages Discord par email (valideId / refuseId) ──────────────
// Permet de supprimer l'ancien message quand le statut change
const devisMsgIds = new Map(); // email → { valideId, refuseId }

// ─── Routes admin : Valider / Refuser un devis ───────────────────────────────
function adminDevisPage(action, email, nom) {
  const isValide = action === 'valider';
  const couleur  = isValide ? '#2ecc71' : '#e74c3c';
  const emoji    = isValide ? '✅' : '❌';
  const titre    = isValide ? 'Devis validé' : 'Devis refusé';
  const texte    = isValide
    ? `Le devis de <strong>${nom || email}</strong> (<em>${email}</em>) a été <strong>validé</strong>. Penser à contacter le client.`
    : `Le devis de <strong>${nom || email}</strong> (<em>${email}</em>) a été <strong>refusé</strong>.`;
  return `<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
  <title>${titre} — zrevents06</title>
  <style>
    body { margin:0; font-family:'Segoe UI',sans-serif; background:#1a1a1a; display:flex; align-items:center; justify-content:center; min-height:100vh; }
    .card { background:#242424; border-radius:16px; padding:48px 56px; text-align:center; box-shadow:0 8px 32px rgba(0,0,0,.4); max-width:460px; }
    .emoji { font-size:64px; margin-bottom:16px; }
    h1 { color:${couleur}; margin:0 0 12px; font-size:1.8rem; }
    p { color:#ccc; line-height:1.6; margin:0 0 28px; }
    a { display:inline-block; padding:12px 28px; background:${couleur}; color:#fff; border-radius:8px; text-decoration:none; font-weight:600; }
    a:hover { opacity:.85; }
  </style>
</head><body>
  <div class="card">
    <div class="emoji">${emoji}</div>
    <h1>${titre}</h1>
    <p>${texte}</p>
    <a href="https://zrevents06.onrender.com">Retour au site</a>
  </div>
</body></html>`;
}

app.get('/admin/devis/valider', async (req, res) => {
  const email = req.query.email || '(inconnu)';
  const nom   = req.query.nom   || 'Client';
  res.send(adminDevisPage('valider', email, nom));

  const whValide  = process.env.DISCORD_WEBHOOK_DEVIS_VALIDE;
  const whRefuse  = process.env.DISCORD_WEBHOOK_DEVIS_REFUSE;
  if (!whValide) { console.log('[DEVIS] DISCORD_WEBHOOK_DEVIS_VALIDE manquant'); return; }
  try {
    const stored = devisMsgIds.get(email) || {};
    console.log(`[DEVIS] valider — email=${email} stored=`, stored);

    // Supprimer l'ancien message dans #devis-validé si déjà validé (double-clic)
    if (stored.valideId && whValide) {
      const delR = await fetch(`${whValide}/messages/${stored.valideId}`, { method: 'DELETE' });
      console.log(`[DEVIS] DELETE ancien valideId=${stored.valideId} → ${delR.status}`);
      stored.valideId = null;
    }
    // Supprimer l'ancien message dans #devis-refusé si existant
    if (stored.refuseId && whRefuse) {
      const delR = await fetch(`${whRefuse}/messages/${stored.refuseId}`, { method: 'DELETE' });
      console.log(`[DEVIS] DELETE ancien refuseId=${stored.refuseId} → ${delR.status}`);
      stored.refuseId = null;
    }

    // Poster dans #devis-validé et récupérer l'ID du message
    const resp = await fetch(`${whValide}?wait=true`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          author: { name: '✨ zrevents06 — Pâtisserie & Événements', icon_url: 'https://zrevents06.onrender.com/favicon.ico' },
          title: '✅  Devis validé',
          description: '> Le devis a été **accepté**. Penser à contacter le client ! 📞',
          color: 0x2ecc71,
          fields: [
            { name: '👤  Client', value: `\`\`\`${nom}\`\`\``, inline: true },
            { name: '📧  Email',  value: `\`\`\`${email}\`\`\``, inline: true },
          ],
          footer: { text: 'zrevents06.onrender.com  •  Devis validé' },
          timestamp: new Date().toISOString(),
        }],
      }),
    });
    const msg = await resp.json();
    console.log(`[DEVIS] POST valide → status=${resp.status} msg.id=${msg.id}`);
    stored.valideId = msg.id;
    devisMsgIds.set(email, stored);
  } catch (err) { console.error('[DEVIS] valider erreur:', err); }
});

app.get('/admin/devis/refuser', async (req, res) => {
  const email = req.query.email || '(inconnu)';
  const nom   = req.query.nom   || 'Client';
  res.send(adminDevisPage('refuser', email, nom));

  const whValide  = process.env.DISCORD_WEBHOOK_DEVIS_VALIDE;
  const whRefuse  = process.env.DISCORD_WEBHOOK_DEVIS_REFUSE;
  if (!whRefuse) { console.log('[DEVIS] DISCORD_WEBHOOK_DEVIS_REFUSE manquant'); return; }
  try {
    const stored = devisMsgIds.get(email) || {};
    console.log(`[DEVIS] refuser — email=${email} stored=`, stored);

    // Supprimer l'ancien message dans #devis-validé si existant
    if (stored.valideId && whValide) {
      const delR = await fetch(`${whValide}/messages/${stored.valideId}`, { method: 'DELETE' });
      console.log(`[DEVIS] DELETE valideId=${stored.valideId} → ${delR.status}`);
      stored.valideId = null;
    }
    // Supprimer l'ancien message dans #devis-refusé si déjà refusé (double-clic)
    if (stored.refuseId && whRefuse) {
      const delR = await fetch(`${whRefuse}/messages/${stored.refuseId}`, { method: 'DELETE' });
      console.log(`[DEVIS] DELETE ancien refuseId=${stored.refuseId} → ${delR.status}`);
      stored.refuseId = null;
    }

    // Poster dans #devis-refusé et récupérer l'ID du message
    const resp = await fetch(`${whRefuse}?wait=true`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          author: { name: '✨ zrevents06 — Pâtisserie & Événements', icon_url: 'https://zrevents06.onrender.com/favicon.ico' },
          title: '❌  Devis refusé',
          description: '> Le devis a été **refusé**.',
          color: 0xe74c3c,
          fields: [
            { name: '👤  Client', value: `\`\`\`${nom}\`\`\``, inline: true },
            { name: '📧  Email',  value: `\`\`\`${email}\`\`\``, inline: true },
          ],
          footer: { text: 'zrevents06.onrender.com  •  Devis refusé' },
          timestamp: new Date().toISOString(),
        }],
      }),
    });
    const msg = await resp.json();
    console.log(`[DEVIS] POST refuse → status=${resp.status} msg.id=${msg.id}`);
    stored.refuseId = msg.id;
    devisMsgIds.set(email, stored);
  } catch (err) { console.error('[DEVIS] refuser erreur:', err); }
});

// ─── Gestionnaire d'erreurs global (évite les fuites de stack trace) ──────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  discordLog('error', 'Erreur serveur non gérée', { message: err.message, url: req.originalUrl });
  res.status(500).json({ error: 'Une erreur interne est survenue.' });
});

// ─── Demarrage : init DB puis ecoute ──────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════
// ─── PANNEAU D'ADMINISTRATION ────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

const ADMIN_JWT_SECRET = (process.env.JWT_SECRET || 'dev-secret') + '-admin';

// ─── Middleware : Auth admin ──────────────────────────────────────────────────
function requireAdminAuth(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Non connecté.' });
  try {
    req.admin = jwt.verify(token, ADMIN_JWT_SECRET);
    next();
  } catch {
    res.clearCookie('admin_token');
    res.status(401).json({ error: 'Session expirée.' });
  }
}

function requireAdminRole(role) {
  return (req, res, next) => {
    if (req.admin.role !== role) return res.status(403).json({ error: 'Accès refusé.' });
    next();
  };
}

// ─── Servir les fichiers statiques admin ─────────────────────────────────────
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// ─── POST /admin/api/login ────────────────────────────────────────────────────
const adminAuthLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

app.post('/admin/api/login', adminAuthLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis.' });
  const admin = await db.get('SELECT * FROM admins WHERE email = ?', email.toLowerCase().trim());
  if (!admin) return res.status(401).json({ error: 'Identifiants incorrects.' });
  const ok = await bcrypt.compare(password, admin.password_hash);
  if (!ok) return res.status(401).json({ error: 'Identifiants incorrects.' });
  const token = jwt.sign(
    { id: admin.id, email: admin.email, nom: admin.nom, role: admin.role },
    ADMIN_JWT_SECRET,
    { expiresIn: '12h' }
  );
  res.cookie('admin_token', token, {
    httpOnly: true, secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict', maxAge: 12 * 60 * 60 * 1000,
  });
  dbLog('info', `Admin connecté : ${admin.email}`, { ip: req.ip });
  res.json({ success: true, admin: { id: admin.id, nom: admin.nom, email: admin.email, role: admin.role } });
});

// ─── POST /admin/api/logout ───────────────────────────────────────────────────
app.post('/admin/api/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ success: true });
});

// ─── GET /admin/api/me ────────────────────────────────────────────────────────
app.get('/admin/api/me', requireAdminAuth, (req, res) => {
  res.json({ admin: req.admin });
});

// ─── GET /admin/api/devis ─────────────────────────────────────────────────────
app.get('/admin/api/devis', requireAdminAuth, async (req, res) => {
  const { statut, q, limit = 50, offset = 0 } = req.query;
  let sql = 'SELECT * FROM devis WHERE 1=1';
  const params = [];
  if (statut && ['en_attente', 'valide', 'refuse'].includes(statut)) {
    sql += ' AND statut = ?'; params.push(statut);
  }
  if (q) {
    sql += ' AND (nom ILIKE ? OR email ILIKE ?)';
    params.push(`%${q}%`, `%${q}%`);
  }
  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));
  const rows = await db.all(sql, ...params);
  const total = await db.get('SELECT COUNT(*) as n FROM devis' + (statut ? ' WHERE statut = ?' : ''), ...(statut ? [statut] : []));
  res.json({ devis: rows, total: parseInt(total?.n || 0) });
});

// ─── GET /admin/api/devis/:id ─────────────────────────────────────────────────
app.get('/admin/api/devis/:id', requireAdminAuth, async (req, res) => {
  const d = await db.get('SELECT * FROM devis WHERE id = ?', req.params.id);
  if (!d) return res.status(404).json({ error: 'Devis introuvable.' });
  res.json({ devis: d });
});

// ─── POST /admin/api/devis/:id/valider ───────────────────────────────────────
app.post('/admin/api/devis/:id/valider', requireAdminAuth, async (req, res) => {
  const d = await db.get('SELECT * FROM devis WHERE id = ?', req.params.id);
  if (!d) return res.status(404).json({ error: 'Devis introuvable.' });

  const whValide = process.env.DISCORD_WEBHOOK_DEVIS_VALIDE;
  const whRefuse = process.env.DISCORD_WEBHOOK_DEVIS_REFUSE;

  // Supprimer l'ancien message refusé si existant
  if (d.discord_refuse_id && whRefuse) {
    await fetch(`${whRefuse}/messages/${d.discord_refuse_id}`, { method: 'DELETE' }).catch(() => {});
  }

  let valideId = d.discord_valide_id;
  if (whValide) {
    try {
      const r = await fetch(`${whValide}?wait=true`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ embeds: [{
          author: { name: '✨ zrevents06 — Pâtisserie & Événements', icon_url: 'https://zrevents06.onrender.com/favicon.ico' },
          title: '✅  Devis validé',
          description: '> Le devis a été **accepté**. Penser à contacter le client ! 📞',
          color: 0x2ecc71,
          fields: [
            { name: '👤  Client', value: `\`\`\`${d.nom}\`\`\``, inline: true },
            { name: '📧  Email',  value: `\`\`\`${d.email}\`\`\``, inline: true },
          ],
          footer: { text: 'zrevents06.onrender.com  •  Devis validé' },
          timestamp: new Date().toISOString(),
        }] }),
      });
      const msg = await r.json();
      valideId = msg.id;
    } catch (err) { console.error('[ADMIN] Discord valider:', err); }
  }

  await db.run(
    `UPDATE devis SET statut='valide', discord_valide_id=?, discord_refuse_id=NULL, updated_at=NOW() WHERE id=?`,
    valideId || null, d.id
  );
  await db.run('INSERT INTO devis_history (devis_id, action, admin_email, notes) VALUES (?, ?, ?, ?)',
    d.id, 'valide', req.admin.email, null);
  // Synchroniser aussi le Map en mémoire
  devisMsgIds.set(d.email, { valideId, refuseId: null });
  dbLog('info', `Devis #${d.id} validé par ${req.admin.email}`, { ip: req.ip });
  res.json({ success: true });
});

// ─── POST /admin/api/devis/:id/refuser ───────────────────────────────────────
app.post('/admin/api/devis/:id/refuser', requireAdminAuth, async (req, res) => {
  const d = await db.get('SELECT * FROM devis WHERE id = ?', req.params.id);
  if (!d) return res.status(404).json({ error: 'Devis introuvable.' });

  const whValide = process.env.DISCORD_WEBHOOK_DEVIS_VALIDE;
  const whRefuse = process.env.DISCORD_WEBHOOK_DEVIS_REFUSE;

  if (d.discord_valide_id && whValide) {
    await fetch(`${whValide}/messages/${d.discord_valide_id}`, { method: 'DELETE' }).catch(() => {});
  }

  let refuseId = d.discord_refuse_id;
  if (whRefuse) {
    try {
      const r = await fetch(`${whRefuse}?wait=true`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ embeds: [{
          author: { name: '✨ zrevents06 — Pâtisserie & Événements', icon_url: 'https://zrevents06.onrender.com/favicon.ico' },
          title: '❌  Devis refusé',
          description: '> Le devis a été **refusé**.',
          color: 0xe74c3c,
          fields: [
            { name: '👤  Client', value: `\`\`\`${d.nom}\`\`\``, inline: true },
            { name: '📧  Email',  value: `\`\`\`${d.email}\`\`\``, inline: true },
          ],
          footer: { text: 'zrevents06.onrender.com  •  Devis refusé' },
          timestamp: new Date().toISOString(),
        }] }),
      });
      const msg = await r.json();
      refuseId = msg.id;
    } catch (err) { console.error('[ADMIN] Discord refuser:', err); }
  }

  await db.run(
    `UPDATE devis SET statut='refuse', discord_refuse_id=?, discord_valide_id=NULL, updated_at=NOW() WHERE id=?`,
    refuseId || null, d.id
  );
  await db.run('INSERT INTO devis_history (devis_id, action, admin_email, notes) VALUES (?, ?, ?, ?)',
    d.id, 'refuse', req.admin.email, null);
  devisMsgIds.set(d.email, { valideId: null, refuseId });
  dbLog('info', `Devis #${d.id} refusé par ${req.admin.email}`, { ip: req.ip });
  res.json({ success: true });
});

// ─── GET /admin/api/devis/:id/print ──────────────────────────────────────────
app.get('/admin/api/devis/:id/print', requireAdminAuth, async (req, res) => {
  const d = await db.get('SELECT * FROM devis WHERE id = ?', req.params.id);
  if (!d) return res.status(404).send('Devis introuvable.');
  const statLabel = { en_attente: 'En attente', valide: 'Validé', refuse: 'Refusé' }[d.statut] || d.statut;
  const statColor = { en_attente: '#f59e0b', valide: '#10b981', refuse: '#ef4444' }[d.statut] || '#6b7280';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>Devis #${d.id} — ${d.nom}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',sans-serif;color:#1f2937;background:#fff;padding:40px}
  .header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px;padding-bottom:20px;border-bottom:2px solid #e5e7eb}
  .brand{font-size:22px;font-weight:700;color:#1d4ed8}.brand span{color:#6b7280;font-size:13px;display:block;font-weight:400}
  .badge{padding:6px 16px;border-radius:999px;font-size:13px;font-weight:600;color:#fff;background:${statColor}}
  h1{font-size:28px;font-weight:700;margin-bottom:4px}
  .ref{color:#6b7280;font-size:14px;margin-bottom:32px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}
  .field label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#6b7280;display:block;margin-bottom:4px}
  .field p{font-size:15px;color:#1f2937;background:#f9fafb;padding:10px 14px;border-radius:8px;border:1px solid #e5e7eb}
  .full{grid-column:1/-1}
  .footer{margin-top:40px;padding-top:20px;border-top:1px solid #e5e7eb;font-size:12px;color:#9ca3af;text-align:center}
  @media print{body{padding:20px}.no-print{display:none}}
</style></head><body>
<div class="header">
  <div class="brand">zrevents06<span>Pâtisserie & Événements</span></div>
  <span class="badge">${statLabel}</span>
</div>
<h1>Devis #${d.id}</h1>
<p class="ref">Reçu le ${new Date(d.created_at).toLocaleDateString('fr-FR', { day: '2-digit', month: 'long', year: 'numeric' })}</p>
<div class="grid">
  <div class="field"><label>Client</label><p>${d.nom}</p></div>
  <div class="field"><label>Email</label><p>${d.email}</p></div>
  <div class="field"><label>Téléphone</label><p>${d.telephone || '—'}</p></div>
  <div class="field"><label>Type d'événement</label><p>${d.type_evenement || '—'}</p></div>
  <div class="field"><label>Date</label><p>${d.date_evenement || '—'}</p></div>
  <div class="field"><label>Heure</label><p>${d.heure_evenement || '—'}</p></div>
  <div class="field"><label>Lieu</label><p>${d.lieu || '—'}</p></div>
  <div class="field"><label>Nombre de personnes</label><p>${d.nombre_personnes || '—'}</p></div>
  <div class="field full"><label>Détails / Message</label><p style="white-space:pre-wrap;min-height:80px">${d.details || '—'}</p></div>
</div>
<div class="footer">zrevents06.onrender.com — Document généré le ${new Date().toLocaleDateString('fr-FR')}</div>
<script>window.print();</script>
</body></html>`);
});

// ─── GET /admin/api/logs ──────────────────────────────────────────────────────
app.get('/admin/api/logs', requireAdminAuth, async (req, res) => {
  const { level, limit = 100, offset = 0 } = req.query;
  let sql = 'SELECT * FROM site_logs WHERE 1=1';
  const params = [];
  if (level && ['error', 'warning', 'info'].includes(level)) {
    sql += ' AND level = ?'; params.push(level);
  }
  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));
  res.json({ logs: await db.all(sql, ...params) });
});

// ─── GET /admin/api/stats ─────────────────────────────────────────────────────
app.get('/admin/api/stats', requireAdminAuth, async (req, res) => {
  const total      = await db.get('SELECT COUNT(*) as n FROM devis');
  const en_attente = await db.get("SELECT COUNT(*) as n FROM devis WHERE statut='en_attente'");
  const valide     = await db.get("SELECT COUNT(*) as n FROM devis WHERE statut='valide'");
  const refuse     = await db.get("SELECT COUNT(*) as n FROM devis WHERE statut='refuse'");
  const parMois    = await db.all(`
    SELECT TO_CHAR(created_at, 'YYYY-MM') as mois, COUNT(*) as total,
           SUM(CASE WHEN statut='valide' THEN 1 ELSE 0 END) as valide
    FROM devis GROUP BY mois ORDER BY mois DESC LIMIT 6
  `);
  const errors   = await db.get("SELECT COUNT(*) as n FROM site_logs WHERE level='error'");
  const warnings = await db.get("SELECT COUNT(*) as n FROM site_logs WHERE level='warning'");
  res.json({
    devis: { total: parseInt(total?.n || 0), en_attente: parseInt(en_attente?.n || 0), valide: parseInt(valide?.n || 0), refuse: parseInt(refuse?.n || 0) },
    parMois: parMois.reverse(),
    logs: { errors: parseInt(errors?.n || 0), warnings: parseInt(warnings?.n || 0) },
  });
});

// ─── GET /admin/api/admins ────────────────────────────────────────────────────
app.get('/admin/api/admins', requireAdminAuth, requireAdminRole('admin'), async (req, res) => {
  const admins = await db.all('SELECT id, nom, email, role, created_at FROM admins ORDER BY created_at DESC');
  res.json({ admins });
});

// ─── POST /admin/api/admins ───────────────────────────────────────────────────
app.post('/admin/api/admins', requireAdminAuth, requireAdminRole('admin'), async (req, res) => {
  const { nom, email, password, role } = req.body;
  if (!nom || !email || !password) return res.status(400).json({ error: 'Nom, email et mot de passe requis.' });
  if (!['admin', 'moderateur'].includes(role)) return res.status(400).json({ error: 'Rôle invalide.' });
  const exists = await db.get('SELECT id FROM admins WHERE email = ?', email.toLowerCase().trim());
  if (exists) return res.status(409).json({ error: 'Un compte avec cet email existe déjà.' });
  const hash = await bcrypt.hash(password, 12);
  await db.run('INSERT INTO admins (nom, email, password_hash, role) VALUES (?, ?, ?, ?)',
    nom.trim(), email.toLowerCase().trim(), hash, role);
  dbLog('info', `Nouvel admin créé : ${email} (${role}) par ${req.admin.email}`);
  res.json({ success: true });
});

// ─── DELETE /admin/api/admins/:id ─────────────────────────────────────────────
app.delete('/admin/api/admins/:id', requireAdminAuth, requireAdminRole('admin'), async (req, res) => {
  if (parseInt(req.params.id) === req.admin.id)
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte.' });
  await db.run('DELETE FROM admins WHERE id = ?', req.params.id);
  res.json({ success: true });
});

// ─── POST /admin/api/setup (création du 1er compte admin) ────────────────────
app.post('/admin/api/setup', async (req, res) => {
  const count = await db.get('SELECT COUNT(*) as n FROM admins');
  if (parseInt(count?.n || 0) > 0) return res.status(403).json({ error: 'Setup déjà effectué.' });
  const { nom, email, password } = req.body;
  if (!nom || !email || !password || password.length < 8)
    return res.status(400).json({ error: 'Nom, email et mot de passe (8 car. min) requis.' });
  const hash = await bcrypt.hash(password, 12);
  await db.run('INSERT INTO admins (nom, email, password_hash, role) VALUES (?, ?, ?, ?)',
    nom.trim(), email.toLowerCase().trim(), hash, 'admin');
  res.json({ success: true });
});

// ─── GET /admin/api/devis/:id/history ────────────────────────────────────────
app.get('/admin/api/devis/:id/history', requireAdminAuth, async (req, res) => {
  const rows = await db.all('SELECT * FROM devis_history WHERE devis_id = ? ORDER BY created_at DESC', req.params.id);
  res.json({ history: rows });
});

// ─── POST /admin/api/devis/:id/notes ─────────────────────────────────────────
app.post('/admin/api/devis/:id/notes', requireAdminAuth, async (req, res) => {
  const { notes } = req.body;
  if (!notes?.trim()) return res.status(400).json({ error: 'Note vide.' });
  await db.run('INSERT INTO devis_history (devis_id, action, admin_email, notes) VALUES (?, ?, ?, ?)',
    req.params.id, 'note', req.admin.email, notes.trim());
  res.json({ success: true });
});

// ─── POST /admin/api/devis/:id/envoyer-email ──────────────────────────────────
app.post('/admin/api/devis/:id/envoyer-email', requireAdminAuth, async (req, res) => {
  const d = await db.get('SELECT * FROM devis WHERE id = ?', req.params.id);
  if (!d) return res.status(404).json({ error: 'Devis introuvable.' });
  const { sujet, corps } = req.body;
  if (!sujet || !corps) return res.status(400).json({ error: 'Sujet et corps requis.' });
  try {
    await transporter.sendMail({ from: SMTP_FROM, to: d.email, subject: sujet, html: corps });
    await db.run('INSERT INTO devis_history (devis_id, action, admin_email, notes) VALUES (?, ?, ?, ?)',
      d.id, 'email_envoye', req.admin.email, `Sujet: ${sujet}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Erreur envoi email: ' + err.message }); }
});

// ─── GET /admin/api/email-templates ──────────────────────────────────────────
app.get('/admin/api/email-templates', requireAdminAuth, async (req, res) => {
  res.json({ templates: await db.all('SELECT * FROM email_templates ORDER BY type, nom') });
});

// ─── POST /admin/api/email-templates ─────────────────────────────────────────
app.post('/admin/api/email-templates', requireAdminAuth, requireAdminRole('admin'), async (req, res) => {
  const { nom, type, sujet, corps } = req.body;
  if (!nom || !sujet || !corps) return res.status(400).json({ error: 'Champs requis.' });
  await db.run('INSERT INTO email_templates (nom, type, sujet, corps) VALUES (?, ?, ?, ?)', nom, type || 'autre', sujet, corps);
  res.json({ success: true });
});

// ─── PUT /admin/api/email-templates/:id ──────────────────────────────────────
app.put('/admin/api/email-templates/:id', requireAdminAuth, requireAdminRole('admin'), async (req, res) => {
  const { nom, type, sujet, corps } = req.body;
  await db.run('UPDATE email_templates SET nom=?, type=?, sujet=?, corps=?, updated_at=NOW() WHERE id=?', nom, type, sujet, corps, req.params.id);
  res.json({ success: true });
});

// ─── DELETE /admin/api/email-templates/:id ───────────────────────────────────
app.delete('/admin/api/email-templates/:id', requireAdminAuth, requireAdminRole('admin'), async (req, res) => {
  await db.run('DELETE FROM email_templates WHERE id = ?', req.params.id);
  res.json({ success: true });
});

// ─── GET /admin/api/users ─────────────────────────────────────────────────────
app.get('/admin/api/users', requireAdminAuth, async (req, res) => {
  const { q, limit = 50, offset = 0 } = req.query;
  let sql = 'SELECT id, prenom, nom, email, email_verifie, actif, created_at FROM users WHERE 1=1';
  const params = [];
  if (q) { sql += ' AND (prenom ILIKE ? OR nom ILIKE ? OR email ILIKE ?)'; const p = '%' + q + '%'; params.push(p, p, p); }
  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));
  const total = await db.get('SELECT COUNT(*) as n FROM users' + (q ? ' WHERE prenom ILIKE ? OR nom ILIKE ? OR email ILIKE ?' : ''), ...(q ? ['%'+q+'%','%'+q+'%','%'+q+'%'] : []));
  res.json({ users: await db.all(sql, ...params), total: parseInt(total?.n || 0) });
});

// ─── PATCH /admin/api/users/:id/status ───────────────────────────────────────
app.patch('/admin/api/users/:id/status', requireAdminAuth, requireAdminRole('admin'), async (req, res) => {
  const { actif } = req.body;
  await db.run('UPDATE users SET actif = ? WHERE id = ?', actif ? 1 : 0, req.params.id);
  res.json({ success: true });
});

// ─── GET /admin/api/newsletter ───────────────────────────────────────────────
app.get('/admin/api/newsletter', requireAdminAuth, async (req, res) => {
  res.json({ campaigns: await db.all('SELECT * FROM email_campaigns ORDER BY envoye_at DESC LIMIT 50') });
});

// ─── POST /admin/api/newsletter ──────────────────────────────────────────────
app.post('/admin/api/newsletter', requireAdminAuth, requireAdminRole('admin'), async (req, res) => {
  const { sujet, corps } = req.body;
  if (!sujet || !corps) return res.status(400).json({ error: 'Sujet et corps requis.' });
  const users = await db.all("SELECT email, prenom FROM users WHERE email_verifie=1 AND (actif IS NULL OR actif=1)");
  let sent = 0;
  for (const u of users) {
    const personalizedCorps = corps.replace(/\{\{prenom\}\}/g, u.prenom || 'Client');
    try {
      await transporter.sendMail({ from: SMTP_FROM, to: u.email, subject: sujet, html: personalizedCorps });
      sent++;
    } catch {}
  }
  await db.run('INSERT INTO email_campaigns (sujet, corps, destinataires, admin_email) VALUES (?, ?, ?, ?)',
    sujet, corps, sent, req.admin.email);
  res.json({ success: true, sent });
});

// ─── Fin PANNEAU D'ADMINISTRATION ─────────────────────────────────────────────

const PORT = process.env.PORT || 3000;

async function startServer() {
  // Créer le schéma dédié si inexistant (isolation vis-à-vis des autres services sur la même DB)
  // search_path est déjà fixé via la connection string (options=-c+search_path=zrevents,public)
  await pool.query('CREATE SCHEMA IF NOT EXISTS zrevents');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL   PRIMARY KEY,
      prenom        TEXT     NOT NULL,
      nom           TEXT     NOT NULL,
      email         TEXT     UNIQUE NOT NULL,
      password_hash TEXT     DEFAULT '',
      google_id     TEXT     UNIQUE,
      email_verifie INTEGER  DEFAULT 0,
      email_token   TEXT,
      actif         INTEGER  DEFAULT 1,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         SERIAL      PRIMARY KEY,
      user_id    INTEGER     NOT NULL,
      token      TEXT        NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used       INTEGER     DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS commandes (
      id          SERIAL      PRIMARY KEY,
      user_id     INTEGER     NOT NULL,
      reference   TEXT        NOT NULL,
      description TEXT        NOT NULL,
      montant     REAL        DEFAULT 0,
      statut      TEXT        DEFAULT 'en_attente',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS devis (
      id                SERIAL      PRIMARY KEY,
      nom               TEXT        NOT NULL,
      email             TEXT        NOT NULL,
      telephone         TEXT,
      date_evenement    TEXT,
      heure_evenement   TEXT,
      lieu              TEXT,
      nombre_personnes  INTEGER,
      type_evenement    TEXT,
      details           TEXT,
      statut            TEXT        DEFAULT 'en_attente',
      discord_valide_id TEXT,
      discord_refuse_id TEXT,
      created_at        TIMESTAMPTZ DEFAULT NOW(),
      updated_at        TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS admins (
      id            SERIAL      PRIMARY KEY,
      nom           TEXT        NOT NULL,
      email         TEXT        UNIQUE NOT NULL,
      password_hash TEXT        NOT NULL,
      role          TEXT        DEFAULT 'moderateur',
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS site_logs (
      id         SERIAL      PRIMARY KEY,
      level      TEXT        NOT NULL,
      message    TEXT        NOT NULL,
      url        TEXT,
      method     TEXT,
      status     INTEGER,
      ip         TEXT,
      extra      TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS devis_history (
      id          SERIAL      PRIMARY KEY,
      devis_id    INTEGER     NOT NULL,
      action      TEXT        NOT NULL,
      admin_email TEXT,
      notes       TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS email_templates (
      id         SERIAL      PRIMARY KEY,
      nom        TEXT        NOT NULL,
      type       TEXT        DEFAULT 'autre',
      sujet      TEXT        NOT NULL,
      corps      TEXT        NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS email_campaigns (
      id            SERIAL      PRIMARY KEY,
      sujet         TEXT        NOT NULL,
      corps         TEXT        NOT NULL,
      destinataires INTEGER     DEFAULT 0,
      envoye_at     TIMESTAMPTZ DEFAULT NOW(),
      admin_email   TEXT
    );
  `);

  // ── Auto-seed comptes admin depuis ADMIN_ACCOUNTS (env var JSON) ──────────
  // Format : [{"nom":"Pascale","email":"...","password":"...","role":"admin"}]
  if (process.env.ADMIN_ACCOUNTS) {
    try {
      const accounts = JSON.parse(process.env.ADMIN_ACCOUNTS);
      for (const acc of accounts) {
        if (!acc.email || !acc.password || !acc.nom) continue;
        const existing = await db.get('SELECT id FROM admins WHERE email = ?', acc.email.toLowerCase().trim());
        if (!existing) {
          const hash = await bcrypt.hash(acc.password, 12);
          await db.run('INSERT INTO admins (nom, email, password_hash, role) VALUES (?, ?, ?, ?)',
            acc.nom.trim(), acc.email.toLowerCase().trim(), hash, acc.role || 'admin');
          console.log(`[Admin] Compte auto-créé : ${acc.email}`);
        }
      }
    } catch (e) {
      console.error('[Admin] Erreur auto-seed ADMIN_ACCOUNTS :', e.message);
    }
  }

  app.listen(PORT, () => {
    console.log('zrevents06 -> http://localhost:' + PORT);
  });
}

startServer().catch(err => {
  console.error('Erreur init DB:', err);
  process.exit(1);
});
