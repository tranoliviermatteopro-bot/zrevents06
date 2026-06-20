# Endpoints API — zrevents06

## Base URL
`http://localhost:3000` (dev) · configurable via `BASE_URL` dans `.env`

---

## Authentification

### `POST /api/inscription`
Crée un compte inactif et envoie un e-mail de confirmation.

**Corps (JSON)**
```json
{
  "prenom":           "Marie",
  "nom":              "Dupont",
  "email":            "marie@exemple.fr",
  "password":         "motdepasse123",
  "password_confirm": "motdepasse123"
}
```

**Réponses**
| Code | Description |
|------|-------------|
| 200  | `{ success: true, message: "..." }` |
| 400  | Validation échouée — `{ error: "..." }` |
| 429  | Rate limit dépassé |

**Validations serveur**
- Champs requis
- Format e-mail (regex RFC 5322)
- Enregistrement MX du domaine (DNS)
- Mot de passe ≥ 8 caractères
- Correspondance des deux mots de passe
- E-mail unique en base

---

### `GET /api/confirmer-email?token=<token>`
Active le compte après clic sur le lien reçu par e-mail.

Redirige vers `/connexion.html?confirmed=1` (succès) ou `/connexion.html?error=lien_invalide`.

---

### `POST /api/connexion`
Authentifie l'utilisateur et pose un cookie JWT httpOnly.

**Corps (JSON)**
```json
{
  "email":    "marie@exemple.fr",
  "password": "motdepasse123",
  "remember": "true"
}
```

**Réponses**
| Code | Description |
|------|-------------|
| 200  | `{ success: true, prenom: "Marie" }` + cookie `auth_token` |
| 400  | Champs manquants |
| 401  | Identifiants incorrects (message générique) |
| 403  | E-mail non confirmé |
| 429  | Rate limit (10 tentatives / 15 min) |

Cookie `auth_token` : httpOnly, Secure (prod), SameSite=Strict
- Session normale : expire 24h
- "Se souvenir de moi" : expire 30 jours

---

### `POST /api/deconnexion`
Supprime le cookie de session.

**Réponse** : `{ success: true }`

---

### `GET /api/me`
Retourne l'utilisateur connecté. Requiert le cookie `auth_token`.

**Réponse**
```json
{ "id": 1, "email": "marie@exemple.fr", "prenom": "Marie" }
```

| Code | Description |
|------|-------------|
| 200  | Utilisateur connecté |
| 401  | Non connecté / session expirée |

---

## Réinitialisation du mot de passe

### `POST /api/mot-de-passe-oublie`
Envoie un e-mail de réinitialisation (si l'e-mail existe et est vérifié).

**Corps (JSON)**
```json
{ "email": "marie@exemple.fr" }
```

**Réponse** : toujours `{ success: true }` — ne révèle pas si l'e-mail existe.

Token valable **30 minutes**. Un seul token actif par utilisateur.

---

### `POST /api/reinitialiser-mot-de-passe`
Change le mot de passe via un token valide.

**Corps (JSON)**
```json
{
  "token":            "abc123...",
  "password":         "nouveaumotdepasse",
  "password_confirm": "nouveaumotdepasse"
}
```

**Réponses**
| Code | Description |
|------|-------------|
| 200  | `{ success: true }` — token invalidé |
| 400  | Token invalide/expiré ou mot de passe trop court |

---

## Schéma base de données (SQLite)

```sql
CREATE TABLE users (
  id            INTEGER  PRIMARY KEY AUTOINCREMENT,
  prenom        TEXT     NOT NULL,
  nom           TEXT     NOT NULL,
  email         TEXT     UNIQUE NOT NULL,
  password_hash TEXT     NOT NULL,       -- bcrypt, cost 12
  email_verifie INTEGER  DEFAULT 0,
  email_token   TEXT,                    -- NULL après vérification
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE password_reset_tokens (
  id         INTEGER  PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER  NOT NULL,
  token      TEXT     NOT NULL,
  expires_at DATETIME NOT NULL,
  used       INTEGER  DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

---

## Sécurité

| Mesure | Détail |
|--------|--------|
| Hachage | bcrypt cost 12 |
| Timing-safe | bcrypt tourne même si l'utilisateur n'existe pas |
| Rate limiting | 10 req / 15 min sur toutes les routes auth |
| Cookie | httpOnly + Secure (prod) + SameSite=Strict |
| CSRF | SameSite=Strict suffit pour les formulaires same-origin |
| Erreurs génériques | Connexion : ne révèle pas si c'est l'e-mail ou le mot de passe qui est faux |
| Reset token | crypto.randomBytes(32), usage unique, expiration 30 min |
| MX check | DNS lookup avant création de compte |
