'use strict';

const YEAR = new Date().getFullYear();

const HEADER = `
  <tr><td style="background:#3D2314;padding:32px 40px;text-align:center;">
    <p style="font-family:Georgia,serif;font-size:24px;color:#D4A574;margin:0;letter-spacing:0.1em;">zrevents06</p>
    <p style="font-size:11px;letter-spacing:0.3em;text-transform:uppercase;color:rgba(253,248,242,0.5);margin:8px 0 0;">Artisan Pâtissier</p>
  </td></tr>`;

const FOOTER = `
  <tr><td style="background:#3D2314;padding:20px 40px;text-align:center;">
    <p style="color:rgba(253,248,242,0.35);font-size:11px;margin:0;">© ${YEAR} zrevents06 — Artisan Pâtissier</p>
  </td></tr>`;

function baseLayout(content) {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#F5EDE0;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F5EDE0;padding:40px 20px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0"
  style="background:#FDF8F2;border-radius:16px;overflow:hidden;
         box-shadow:0 8px 40px rgba(61,35,20,0.12);max-width:100%;">
  ${HEADER}
  <tr><td style="padding:40px 40px 32px;">${content}</td></tr>
  ${FOOTER}
</table>
</td></tr></table>
</body></html>`;
}

function ctaButton(url, label) {
  return `
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:0 0 32px;">
  <a href="${url}"
     style="display:inline-block;background:linear-gradient(135deg,#C4956A,#D4A574);
            color:#FDF8F2;text-decoration:none;font-weight:700;font-size:13px;
            letter-spacing:0.1em;text-transform:uppercase;padding:15px 40px;border-radius:50px;">
    ${label}
  </a>
</td></tr></table>
<p style="color:#3D2314;opacity:0.45;font-size:12px;line-height:1.6;
           border-top:1px solid rgba(196,149,106,0.2);padding-top:20px;">
  Si le bouton ne fonctionne pas, copiez ce lien :<br>
  <a href="${url}" style="color:#C4956A;word-break:break-all;font-size:11px;">${url}</a>
</p>`;
}

// ─── Template : confirmation d'e-mail ─────────────────────────────────────────
function emailConfirmationHtml(prenom, url) {
  return baseLayout(`
    <h1 style="font-family:Georgia,serif;font-size:26px;color:#3D2314;margin:0 0 12px;font-weight:700;">
      Bienvenue, ${prenom} !
    </h1>
    <p style="color:#3D2314;opacity:0.72;line-height:1.75;font-size:15px;margin:0 0 28px;">
      Merci de rejoindre notre communauté gourmande. Cliquez ci-dessous pour confirmer votre adresse
      e-mail et activer votre compte.
    </p>
    ${ctaButton(url, 'Confirmer mon adresse e-mail')}
    <p style="color:#3D2314;opacity:0.35;font-size:11px;margin-top:12px;">
      Vous n'avez pas créé de compte ? Ignorez cet e-mail.
    </p>`);
}

// ─── Template : réinitialisation de mot de passe ──────────────────────────────
function emailResetHtml(prenom, url) {
  return baseLayout(`
    <h1 style="font-family:Georgia,serif;font-size:26px;color:#3D2314;margin:0 0 12px;font-weight:700;">
      Réinitialiser votre mot de passe
    </h1>
    <p style="color:#3D2314;opacity:0.72;line-height:1.75;font-size:15px;margin:0 0 6px;">
      Bonjour ${prenom},
    </p>
    <p style="color:#3D2314;opacity:0.72;line-height:1.75;font-size:15px;margin:0 0 28px;">
      Nous avons reçu une demande de réinitialisation de mot de passe. Ce lien expire dans 30 minutes.
    </p>
    ${ctaButton(url, 'Réinitialiser mon mot de passe')}
    <p style="color:#3D2314;opacity:0.35;font-size:11px;margin-top:12px;">
      Vous n'avez pas fait cette demande ? Ignorez cet e-mail.
    </p>`);
}

module.exports = { emailConfirmationHtml, emailResetHtml };
