'use strict';

const { discordLog } = require('../discord');

/**
 * Middleware de logging : envoie sur Discord les erreurs 5xx
 * et les refus d'accès 401/403.
 */
function requestLogger(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    const { statusCode: status } = res;
    const duration = Date.now() - start;
    const context  = { method: req.method, url: req.originalUrl, status, ip: req.ip, duration };

    if (status >= 500) {
      discordLog('error',
        `${req.method} ${req.path} → ${status}`,
        context,
      );
    } else if (status === 401 || status === 403) {
      discordLog('warning',
        `Accès refusé ${req.method} ${req.path} → ${status}`,
        context,
      );
    }
  });

  next();
}

module.exports = requestLogger;
