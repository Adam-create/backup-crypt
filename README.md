# backup-crypt

Outil de sauvegarde chiffrée en ligne de commande.  
Chaque fichier est chiffré individuellement avec **AES-256-GCM**, la clé étant dérivée d'une passphrase via **PBKDF2-HMAC-SHA256** (600 000 itérations). Aucune clé ni secret n'est jamais écrit sur le disque.

---

## Chaîne cryptographique

```
Passphrase (saisie via getpass)
        │
        ▼
  [PBKDF2-HMAC-SHA256]  ← salt aléatoire 128 bits (unique par fichier)
  600 000 itérations
        │
        ▼
   Clé AES-256 (32 octets)
        │
        ▼
  [AES-256-GCM]  ← nonce aléatoire 96 bits (unique par fichier)
        │
        ├── ciphertext (même taille que le plaintext)
        └── auth_tag 128 bits  ←── vérifié à la restauration
```

**Format d'un fichier chiffré (header binaire) :**

```
┌──────────┬──────────┬──────────┬──────────────────┐
│ salt 16B │ nonce 12B│  tag 16B │ ciphertext ...   │
└──────────┴──────────┴──────────┴──────────────────┘
  ^── 44 octets de header fixe ──^
```

---

## Prérequis

- Python 3.10+
- pip

## Installation

```bash
git clone https://github.com/<you>/backup-crypt.git
cd backup-crypt
pip install -r requirements.txt
```

---

## Utilisation

### Sauvegarder un répertoire

```bash
python -m backup_crypt backup --source ./documents --dest /media/usb/backup
```

La passphrase est saisie de façon sécurisée (deux fois pour confirmation, jamais affichée).  
L'arborescence source est reproduite à la destination avec l'extension `.enc` ajoutée.

### Restaurer une sauvegarde

```bash
python -m backup_crypt restore --source /media/usb/backup --dest ./restored
```

L'intégrité de chaque fichier est vérifiée avant écriture. Tout fichier corrompu ou
modifié est signalé et ignoré — aucun plaintext partiel n'est jamais écrit.

### Lister les sauvegardes disponibles

```bash
python -m backup_crypt list --dest /media/usb/backup
```

### Options globales

| Option | Description |
|---|---|
| `-v`, `--verbose` | Active les logs de debug |

---

## Exécuter les tests

```bash
python -m pytest tests/ -v
```

---

## Choix cryptographiques

### AES-256-GCM (AEAD)

AES-GCM est un schéma **Authenticated Encryption with Associated Data** : il garantit
à la fois la **confidentialité** (chiffrement CTR) et l'**intégrité** (tag GHASH 128 bits).
Contrairement à AES-CBC, toute modification du ciphertext est détectée avant déchiffrement.
Le tag est vérifié en temps constant par la bibliothèque `cryptography`.

### PBKDF2-HMAC-SHA256

PBKDF2 est recommandé par le NIST (SP 800-132). Les 600 000 itérations correspondent
à la recommandation OWASP 2023 pour SHA-256, rendant les attaques par dictionnaire
coûteuses. Chaque fichier dispose d'un **salt aléatoire de 128 bits** : la même
passphrase produit des clés différentes pour chaque fichier.

### Nonce unique par fichier

Le nonce GCM de 96 bits est généré via `os.urandom(12)` pour chaque fichier.
La réutilisation d'un nonce avec la même clé détruirait la confidentialité et
l'intégrité — ce schéma l'exclut structurellement.

---

## Avertissements de sécurité

> **La perte de la passphrase entraîne la perte définitive des données.**  
> Il n'existe aucun mécanisme de récupération : les clés ne sont jamais stockées.

- Ne stockez jamais la passphrase dans un fichier ou une variable d'environnement.
- Conservez plusieurs copies de sauvegarde sur des supports différents.
- Un fichier `.enc` modifié, même d'un seul bit, échouera à la restauration (tag invalide).

---

## Licence

MIT — voir [LICENSE](LICENSE).
