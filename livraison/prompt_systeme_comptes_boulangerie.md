# Prompt — Système de comptes pour le site de la boulangerie

## Contexte

Tu travailles sur le site web d'une boulangerie artisanale. Le site existe déjà et propose une vitrine des produits. Tu dois y intégrer un **système de comptes clients complet**, couvrant l'inscription, la connexion et la récupération de mot de passe.

---

## Objectif

Mettre en place un espace membre sécurisé et chaleureux, cohérent avec l'identité visuelle de la boulangerie (tons chauds, typographie artisanale, ambiance accueillante).

---

## Pages et fonctionnalités à créer

### 1. Page d'inscription (`/inscription`)

**Design :**
- Formulaire épuré, centré sur la page, sur fond clair (blanc cassé ou beige)
- Titre : "Créer mon compte" avec une petite icône de croissant ou de pain
- Champs : Prénom, Nom, Adresse e-mail, Mot de passe, Confirmation du mot de passe
- Bouton CTA : "Rejoindre la boulangerie" (couleur principale du site)
- Lien vers la page de connexion : "Déjà un compte ? Se connecter"
- Indicateur de force du mot de passe sous le champ

**Développement :**
- Validation côté client (champs requis, format email, mot de passe ≥ 8 caractères, correspondance des deux mots de passe)
- Validation côté serveur avec messages d'erreur clairs
- Hachage du mot de passe avant stockage (bcrypt ou argon2)
- Envoi d'un e-mail de confirmation à l'adresse fournie
- Protection contre les inscriptions multiples avec le même e-mail
- **Vérification que l'adresse e-mail est réelle et joignable** :
  - Validation du format (regex RFC 5322)
  - Vérification MX : interroger les enregistrements DNS MX du domaine pour s'assurer qu'un serveur de messagerie existe (ex. : `dns.resolve(domain, 'MX')` en Node.js)
  - Envoi d'un e-mail de confirmation avec lien d'activation — le compte reste inactif jusqu'à confirmation
  - (Optionnel) Utiliser un service de vérification d'e-mail tiers (ex. : ZeroBounce, Hunter.io, Mailboxlayer) pour détecter les adresses jetables ou inexistantes

---

### 2. Page de connexion (`/connexion`)

**Design :**
- Même style que la page d'inscription (cohérence visuelle)
- Titre : "Bienvenue !"
- Champs : Adresse e-mail, Mot de passe
- Case à cocher : "Se souvenir de moi"
- Bouton CTA : "Se connecter"
- Lien : "Mot de passe oublié ?"
- Lien : "Pas encore de compte ? S'inscrire"

**Développement :**
- Authentification sécurisée (vérification e-mail + mot de passe hashé)
- Gestion de session (JWT ou cookie de session httpOnly)
- Option "Se souvenir de moi" : session persistante 30 jours
- Limitation du nombre de tentatives (rate limiting) pour prévenir le brute force
- Redirection vers la page précédente après connexion réussie
- Messages d'erreur génériques (ne pas indiquer si c'est l'e-mail ou le mot de passe qui est faux)

---

### 3. Page "Mot de passe oublié" (`/mot-de-passe-oublie`)

**Design :**
- Formulaire simple avec un seul champ : adresse e-mail
- Message rassurant : "Pas de panique ! On vous envoie un lien pour réinitialiser votre mot de passe."
- Bouton : "Envoyer le lien"
- Confirmation après envoi : message de succès même si l'e-mail n'existe pas (sécurité)

**Développement :**
- Génération d'un token unique sécurisé (UUID ou crypto.randomBytes)
- Enregistrement du token en base avec une expiration (15 à 60 minutes)
- Envoi de l'e-mail contenant le lien de réinitialisation
- Page de réinitialisation (`/reinitialiser-mot-de-passe?token=...`) :
  - Vérification de la validité et de l'expiration du token
  - Formulaire : nouveau mot de passe + confirmation
  - Invalidation du token après utilisation

---

## Contraintes techniques

- **Sécurité** : HTTPS obligatoire, protection CSRF sur tous les formulaires, cookies httpOnly et Secure
- **Accessibilité** : labels HTML corrects, messages d'erreur associés aux champs (aria), navigation clavier
- **Responsive** : formulaires adaptés mobile, tablette, desktop
- **Performances** : chargement rapide, pas de dépendances inutiles

---

## Stack suggérée (à adapter selon l'existant)

- **Frontend** : HTML/CSS/JS vanilla ou framework existant du site (React, Vue…)
- **Backend** : Node.js (Express) / PHP / Python (Flask/Django) — selon l'environnement actuel
- **Base de données** : table `users` avec colonnes : id, prenom, nom, email (unique), password_hash, email_verifie, created_at
- **E-mails** : Nodemailer, SendGrid, Mailgun ou équivalent

---

## Livrables attendus

1. Les 3 pages HTML/CSS avec leur design (maquette ou code final)
2. Les routes backend correspondantes avec logique d'authentification
3. Le schéma de la table `users` et `password_reset_tokens`
4. Les templates d'e-mails (confirmation d'inscription + réinitialisation de mot de passe)
5. Un fichier de documentation listant les endpoints créés

---

## Ton et style visuel

L'interface doit refléter l'identité chaleureuse de la boulangerie : **couleurs chaudes** (ocre, beige, brun doux), **typographies artisanales**, messages en tutoiement ou vouvoiement selon le ton du site. Éviter un rendu trop "corporate" ou froid.
