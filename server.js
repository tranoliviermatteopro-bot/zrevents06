require('dotenv').config();
const helmet = require('helmet');

// ─── Discord Log ──────────────────────────────────────────────────────────────
const DISCORD_BOT_URL = process.env.DISCORD_BOT_URL || 'http://localhost:3001';
const DISCORD_API_KEY = process.env.DISCORD_API_KEY || '';

async function discordLog(level, message, extra = {}) {
  if (!DISCORD_API_KEY) return;
  try {
    await fetch(`${DISCORD_BOT_URL}/log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': DISCORD_API_KEY },
      body: JSON.stringify({ level, site: 'zrevents06', message, ...extra }),
    });
  } catch {}
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
const fs           = require('fs');
const initSqlJs    = require('sql.js');
const passport     = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const expressSession = require('express-session');

const DB_PATH = path.join(__dirname, 'data.db');

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

// ─── Wrapper synchrone autour de sql.js ───────────────────────────────────────
let _db;

function saveDb() {
  const data = _db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

const db = {
  exec(sql) {
    _db.run(sql);
    saveDb();
  },
  get(sql, ...params) {
    const stmt = _db.prepare(sql);
    stmt.bind(params);
    const row = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return row;
  },
  all(sql, ...params) {
    const stmt = _db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  },
  run(sql, ...params) {
    const stmt = _db.prepare(sql);
    stmt.run(params);
    stmt.free();
    saveDb();
  },
};

// ─── Application Express ──────────────────────────────────────────────────────
const app = express();

// ─── Sécurité : headers HTTP ──────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'"],   // inline scripts dans les HTML
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
  }, (accessToken, refreshToken, profile, done) => {
    try {
      const email    = profile.emails?.[0]?.value || '';
      const prenom   = profile.name?.givenName || profile.displayName || 'Utilisateur';
      const nom      = profile.name?.familyName || '';
      const googleId = profile.id;

      let user = db.get('SELECT * FROM users WHERE google_id = ?', googleId);
      if (!user && email) user = db.get('SELECT * FROM users WHERE email = ?', email.toLowerCase());

      if (!user) {
        db.run(
          'INSERT INTO users (prenom, nom, email, google_id, email_verifie, password_hash) VALUES (?, ?, ?, ?, 1, ?)',
          prenom, nom, email.toLowerCase(), googleId, ''
        );
        user = db.get('SELECT * FROM users WHERE google_id = ?', googleId);
      } else if (!user.google_id) {
        db.run('UPDATE users SET google_id = ?, email_verifie = 1 WHERE id = ?', googleId, user.id);
        user = db.get('SELECT * FROM users WHERE id = ?', user.id);
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

  const existing = db.get('SELECT id FROM users WHERE email = ?', email.toLowerCase());
  if (existing) {
    return res.status(400).json({ error: 'Un compte existe deja avec cet e-mail.' });
  }

  const password_hash  = await bcrypt.hash(password, 12);
  const smtpConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
  const needsVerif     = process.env.NODE_ENV === 'production' && smtpConfigured;
  const email_token    = needsVerif ? crypto.randomBytes(32).toString('hex') : null;

  db.run(
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
    db.run('UPDATE users SET email_verifie = 1, email_token = NULL WHERE email = ?', email.toLowerCase());
    return res.json({ success: true, message: 'Compte créé et activé ! (e-mail non envoyé)' });
  }
});

// ─── Route : Confirmation e-mail ──────────────────────────────────────────────
app.get('/api/confirmer-email', (req, res) => {
  const { token } = req.query;
  if (!token) return res.redirect('/connexion.html?error=lien_invalide');

  const user = db.get('SELECT id FROM users WHERE email_token = ? AND email_verifie = 0', token);
  if (!user) return res.redirect('/connexion.html?error=lien_invalide');

  db.run('UPDATE users SET email_verifie = 1, email_token = NULL WHERE id = ?', user.id);
  res.redirect('/connexion.html?confirmed=1');
});

// ─── Route : Connexion ────────────────────────────────────────────────────────
app.post('/api/connexion', authLimiter, async (req, res) => {
  const { email, password, remember } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'E-mail et mot de passe requis.' });
  }

  const user = db.get('SELECT * FROM users WHERE email = ?', email.toLowerCase());

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
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, prenom: req.user.prenom });
});

app.get('/api/me/details', requireAuth, (req, res) => {
  const user = db.get('SELECT prenom, nom, email, password_hash, google_id FROM users WHERE id = ?', req.user.id);
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

  const user = db.get(
    'SELECT id, prenom FROM users WHERE email = ? AND email_verifie = 1',
    email.toLowerCase()
  );
  if (!user) return;

  const token      = crypto.randomBytes(32).toString('hex');
  const expires_at = new Date(Date.now() + 30 * 60 * 1000).toISOString();

  db.run('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0', user.id);
  db.run(
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

  const record = db.get(
    'SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token = ?',
    token
  );

  if (!record || record.used || new Date(record.expires_at) <= new Date()) {
    return res.status(400).json({ error: 'Ce lien est invalide ou expire. Faites une nouvelle demande.' });
  }

  const password_hash = await bcrypt.hash(password, 12);
  db.run('UPDATE users SET password_hash = ? WHERE id = ?', password_hash, record.user_id);
  db.run('UPDATE password_reset_tokens SET used = 1 WHERE id = ?', record.id);

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
app.put('/api/profil', requireAuth, (req, res) => {
  let { prenom, nom } = req.body;
  prenom = prenom?.trim();
  nom    = nom?.trim();
  if (!prenom || !nom) return res.status(400).json({ error: 'Prénom et nom requis.' });
  if (prenom.length > 50 || nom.length > 50) return res.status(400).json({ error: 'Prénom/nom trop long (max 50 car.).' });

  db.run('UPDATE users SET prenom = ?, nom = ? WHERE id = ?', prenom, nom, req.user.id);
  const user = db.get('SELECT * FROM users WHERE id = ?', req.user.id);
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

  const user = db.get('SELECT * FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });

  // Les comptes Google sans mot de passe ont un hash vide
  if (!user.password_hash) return res.status(400).json({ error: 'Votre compte est lié à Google. Définissez d\'abord un mot de passe.' });

  const valid = await bcrypt.compare(ancien_mdp, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Ancien mot de passe incorrect.' });

  const hash = await bcrypt.hash(nouveau_mdp, 12);
  db.run('UPDATE users SET password_hash = ? WHERE id = ?', hash, user.id);
  discordLog('info', 'Mot de passe changé : ' + user.email, { user: user.email });
  res.json({ success: true });
});

// ─── Route : Historique commandes ─────────────────────────────────────────────
app.get('/api/historique', requireAuth, (req, res) => {
  const commandes = db.all(
    'SELECT id, reference, description, montant, statut, created_at FROM commandes WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    req.user.id
  );
  res.json({ commandes });
});

// ─── Route : Supprimer compte ─────────────────────────────────────────────────
app.delete('/api/compte', requireAuth, async (req, res) => {
  const { password } = req.body;
  const user = db.get('SELECT * FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });

  // Si le compte a un mot de passe, on le vérifie
  if (user.password_hash) {
    if (!password) return res.status(400).json({ error: 'Mot de passe requis pour confirmer la suppression.' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Mot de passe incorrect.' });
  }

  // Supprimer les données liées
  db.run('DELETE FROM password_reset_tokens WHERE user_id = ?', user.id);
  db.run('DELETE FROM commandes WHERE user_id = ?', user.id);
  db.run('DELETE FROM users WHERE id = ?', user.id);

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

  const user = db.get('SELECT * FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (user.password_hash) return res.status(400).json({ error: 'Vous avez déjà un mot de passe.' });

  const hash = await bcrypt.hash(nouveau_mdp, 12);
  db.run('UPDATE users SET password_hash = ? WHERE id = ?', hash, user.id);
  discordLog('info', 'Mot de passe défini (compte Google) : ' + user.email, { user: user.email });
  res.json({ success: true });
});

// ─── Gestionnaire d'erreurs global (évite les fuites de stack trace) ──────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  discordLog('error', 'Erreur serveur non gérée', { message: err.message, url: req.originalUrl });
  res.status(500).json({ error: 'Une erreur interne est survenue.' });
});

// ─── Demarrage : init DB puis ecoute ──────────────────────────────────────────
const PORT = process.env.PORT || 3000;

initSqlJs().then(SQL => {
  const buf = fs.existsSync(DB_PATH) ? fs.readFileSync(DB_PATH) : null;
  _db = buf ? new SQL.Database(buf) : new SQL.Database();

  _db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER  PRIMARY KEY AUTOINCREMENT,
      prenom        TEXT     NOT NULL,
      nom           TEXT     NOT NULL,
      email         TEXT     UNIQUE NOT NULL,
      password_hash TEXT     DEFAULT '',
      google_id     TEXT     UNIQUE,
      email_verifie INTEGER  DEFAULT 0,
      email_token   TEXT,
      created_at    TEXT     DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         INTEGER  PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER  NOT NULL,
      token      TEXT     NOT NULL,
      expires_at TEXT     NOT NULL,
      used       INTEGER  DEFAULT 0,
      created_at TEXT     DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS commandes (
      id          INTEGER  PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER  NOT NULL,
      reference   TEXT     NOT NULL,
      description TEXT     NOT NULL,
      montant     REAL     DEFAULT 0,
      statut      TEXT     DEFAULT 'en_attente',
      created_at  TEXT     DEFAULT (datetime('now'))
    );
  `);
  saveDb();

  app.listen(PORT, () => {
    console.log('zrevents06 -> http://localhost:' + PORT);
  });
}).catch(err => {
  console.error('Erreur init DB:', err);
  process.exit(1);
});
