# CLAUDE.md — Projet 1 : Script de backup chiffré

## Project Overview

Script Python en ligne de commande (CLI) qui sauvegarde un ou plusieurs répertoires
vers un stockage externe (clé USB, disque externe) en chiffrant chaque fichier
individuellement avec AES-256-GCM. La clé de chiffrement est dérivée d'un mot de passe
saisi à l'exécution via PBKDF2-HMAC-SHA256 avec salt aléatoire — aucune clé ou secret
n'est jamais écrit sur le disque.

Le projet est destiné à un portfolio GitHub niveau M2 cybersécurité. Il doit être
fonctionnel, lisible, et témoigner d'une maîtrise réelle des primitives cryptographiques
et des bonnes pratiques de sécurité.

---

## Tech Stack

- **Language** : Python 3.10+
- **Cryptographie** : `cryptography` (AES-256-GCM, PBKDF2-HMAC-SHA256)
- **CLI** : `argparse`
- **Filesystem** : `pathlib`, `shutil`
- **Logging** : `logging` (module standard)
- **Dépendances** : `cryptography` uniquement (hors stdlib)

---

## Project Structure

```
backup-crypt/
├── backup_crypt/
│   ├── __init__.py
│   ├── cli.py          # Point d'entrée argparse
│   ├── crypto.py       # Chiffrement/déchiffrement AES-GCM + dérivation PBKDF2
│   ├── backup.py       # Logique de sauvegarde et restauration
│   └── utils.py        # Détection stockage externe, logging, helpers
├── tests/
│   ├── test_crypto.py
│   └── test_backup.py
├── requirements.txt
├── README.md           # Livrable documentation (voir section Deliverables)
└── CLAUDE.md
```

---

## Commands

```bash
# Installation des dépendances
pip install -r requirements.txt

# Sauvegarde d'un dossier vers le stockage externe détecté
python -m backup_crypt backup --source ./documents --dest /media/usb

# Restauration d'une sauvegarde chiffrée
python -m backup_crypt restore --source /media/usb/backup_2025 --dest ./restored

# Lister les sauvegardes disponibles sur le stockage externe
python -m backup_crypt list --dest /media/usb

# Exécuter les tests
python -m pytest tests/ -v
```

---

## Cryptographic Specification

Ce projet repose sur des primitives éprouvées — **aucun crypto maison**.

| Primitive | Algorithme | Paramètres |
|---|---|---|
| Chiffrement | AES-256-GCM | Clé 256 bits, nonce 96 bits aléatoire par fichier |
| Dérivation de clé | PBKDF2-HMAC-SHA256 | 600 000 itérations, salt 128 bits aléatoire |
| Intégrité | GCM auth tag | 128 bits, vérifié à la restauration |

**Format d'un fichier chiffré** (header binaire) :

```
[ salt 16B ][ nonce 12B ][ auth_tag 16B ][ ciphertext ... ]
```

Chaque fichier possède son propre nonce et son propre salt. La même passe-phrase
produit des clés différentes pour chaque fichier grâce au salt.

---

## Security Constraints

- **Ne jamais** stocker ou logger le mot de passe, la clé dérivée, ou le nonce en clair
- **Ne jamais** réutiliser un nonce : générer via `os.urandom(12)` systématiquement
- **Ne jamais** implémenter de primitive cryptographique maison (pas de XOR custom, etc.)
- Effacer les variables sensibles en mémoire après usage (`del key`)
- Valider l'intégrité du tag GCM avant toute écriture lors de la restauration
- Le mot de passe est saisi via `getpass.getpass()` (pas affiché, pas dans `sys.argv`)

---

## CLI UX Requirements

Le rendu terminal doit être propre et informatif, niveau outil professionnel :

- Barre de progression pour les fichiers en cours (`tqdm` ou implémentation manuelle)
- Résumé final : nombre de fichiers traités, taille totale, durée, erreurs éventuelles
- Messages d'erreur clairs et actionnables (pas de tracebacks bruts pour l'utilisateur)
- Code de sortie non-zéro en cas d'échec (`sys.exit(1)`)
- Couleurs ANSI pour distinguer succès / avertissement / erreur (sans dépendance lourde)

---

## Code Style

- Python type hints sur toutes les fonctions publiques
- Docstrings pour chaque module et fonction publique (format Google style)
- Pas de variable globale mutable
- Fonctions courtes, à responsabilité unique (SRP)
- Les exceptions cryptographiques sont toujours attrapées et relayées proprement
- `pathlib.Path` partout, jamais `os.path`

---

## Common Mistakes to Avoid

- Ne pas utiliser `AES-CBC` ou `AES-ECB` — uniquement `AES-GCM` (AEAD)
- Ne pas dériver la clé une fois pour toute la session : un salt par fichier
- Ne pas tronquer les erreurs de déchiffrement (`InvalidTag`) — les propager explicitement
- Ne pas écrire le fichier restauré si le tag GCM est invalide
- Ne pas hardcoder les paramètres PBKDF2 (itérations dans une constante nommée)
- Ne pas ignorer les cas limites : fichier vide, dossier vide, chemin destination inexistant

---

## Deliverables

### 1. Code source complet et fonctionnel

Tous les modules décrits dans la structure ci-dessus, avec tests passants.

### 2. README.md — Documentation du projet (livrable obligatoire)

Le README doit être rédigé en Markdown, directement exploitable sur GitHub.
Il doit contenir :

- **Présentation du projet** : objectif, contexte, cas d'usage
- **Schéma de la chaîne cryptographique** (bloc texte ASCII ou Mermaid)
- **Prérequis et installation** (Python version, `pip install`)
- **Guide d'utilisation** avec exemples de commandes annotés
- **Détail des choix cryptographiques** : justification de AES-GCM, PBKDF2, paramètres
- **Format des fichiers chiffrés** (structure du header)
- **Avertissements de sécurité** (perte de passe-phrase = perte des données)
- **Licence** (MIT recommandé)

Le README est un livrable à part entière : il doit montrer la capacité à documenter
un outil de sécurité de façon claire, précise et professionnelle.

---

## Definition of Done

- [ ] `backup` chiffre tous les fichiers du dossier source vers la destination
- [ ] `restore` déchiffre et restaure l'arborescence originale
- [ ] Un fichier corrompu ou trafiqué échoue proprement à la restauration (tag invalide)
- [ ] Aucune clé ou passe-phrase n'apparaît dans les logs ou le filesystem
- [ ] Les tests couvrent chiffrement, déchiffrement, et altération intentionnelle
- [ ] Le README est complet et autonome
