'use strict';

const jwt                    = require('jsonwebtoken');
const { JWT_SECRET, IS_PROD } = require('../config');

/**
 * Pose un cookie JWT httpOnly sur la réponse.
 * @param {import('express').Response} res
 * @param {{ id, email, prenom }} user
 * @param {boolean} [remember=false]  30 jours si true, sinon 24 h
 */
function setAuthCookie(res, user, remember = false) {
  const expiresIn = remember ? '30d' : '24h';
  const maxAge    = remember
    ? 30 * 24 * 60 * 60 * 1000
    :      24 * 60 * 60 * 1000;

  const token = jwt.sign(
    { id: user.id, email: user.email, prenom: user.prenom },
    JWT_SECRET,
    { expiresIn },
  );

  res.cookie('auth_token', token, {
    httpOnly: true,
    secure:   IS_PROD,
    sameSite: 'Strict',
    maxAge,
  });
}

/**
 * Middleware : vérifie le cookie JWT et attache req.user.
 * Retourne 401 si absent ou invalide.
 */
function requireAuth(req, res, next) {
  const token = req.cookies?.auth_token;

  if (!token) {
    return res.status(401).json({ error: 'Non connecté.' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie('auth_token');
    res.status(401).json({ error: 'Session expirée.' });
  }
}

module.exports = { setAuthCookie, requireAuth };
