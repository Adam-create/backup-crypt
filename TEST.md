# Guide de test — backup-crypt

Ce guide te permet de tester le programme entièrement en local, sans clé USB.

---

## Prérequis

```powershell
$py = "C:\Users\adamo\AppData\Local\Programs\Python\Python311\python.exe"
```

---

## Étape 1 — Créer un environnement de test

```powershell
mkdir C:\TestBackup\source
mkdir C:\TestBackup\destination
mkdir C:\TestBackup\restaure

"Contenu secret du document 1" | Out-File C:\TestBackup\source\doc1.txt
"Données confidentielles"       | Out-File C:\TestBackup\source\doc2.txt
mkdir C:\TestBackup\source\sous-dossier
"Fichier dans un sous-dossier"  | Out-File C:\TestBackup\source\sous-dossier\notes.txt
```

---

## Étape 2 — Lancer le backup

```powershell
& $py -m backup_crypt backup --source C:\TestBackup\source --dest C:\TestBackup\destination
```

Quand la passphrase est demandée, tape `test123` (deux fois pour confirmation).

Tu verras une barre de progression et un résumé : 3 fichiers chiffrés.

---

## Étape 3 — Inspecter les fichiers chiffrés

```powershell
# Liste les fichiers produits
Get-ChildItem C:\TestBackup\destination -Recurse

# Tente de lire un fichier chiffré : contenu binaire illisible
Get-Content C:\TestBackup\destination\doc1.txt.enc
```

Chaque fichier `.txt.enc` contient un header binaire de 44 octets (salt + nonce + tag)
suivi du ciphertext. Sans la passphrase, les données sont inaccessibles.

---

## Étape 4 — Restaurer avec la bonne passphrase

```powershell
& $py -m backup_crypt restore --source C:\TestBackup\destination --dest C:\TestBackup\restaure
```

Tape `test123`. Vérifie le contenu restauré :

```powershell
Get-Content C:\TestBackup\restaure\doc1.txt
Get-Content C:\TestBackup\restaure\sous-dossier\notes.txt
```

Les fichiers sont identiques aux originaux.

---

## Étape 5 — Test de sécurité : mauvaise passphrase

```powershell
# Vide le dossier de restauration
Remove-Item C:\TestBackup\restaure\* -Recurse -Force

# Restaure avec une mauvaise passphrase
& $py -m backup_crypt restore --source C:\TestBackup\destination --dest C:\TestBackup\restaure
# → tape "mauvais_mdp"
```

**Résultat attendu** : tous les fichiers échouent avec une erreur d'authentification,
aucun fichier n'est écrit dans `restaure\`. C'est le comportement correct : un tag GCM
invalide signifie que la clé est mauvaise ou que le fichier a été altéré.

---

## Étape 6 — Test de sécurité : fichier corrompu

```powershell
# Modifie un octet dans un fichier chiffré
$file = "C:\TestBackup\destination\doc1.txt.enc"
$bytes = [System.IO.File]::ReadAllBytes($file)
$bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 0xFF
[System.IO.File]::WriteAllBytes($file, $bytes)

# Tente de restaurer
& $py -m backup_crypt restore --source C:\TestBackup\destination --dest C:\TestBackup\restaure
# → tape "test123"
```

**Résultat attendu** : `doc1.txt.enc` échoue (tag invalide), les autres fichiers
sont restaurés normalement. Aucun plaintext partiel n'est jamais écrit.

---

## Étape 7 — Lister les backups

```powershell
& $py -m backup_crypt list --dest C:\TestBackup\destination
```

Affiche les fichiers `.enc` présents avec leur taille, sans demander de passphrase.

---

## Nettoyage

```powershell
Remove-Item C:\TestBackup -Recurse -Force
```

---

## Avec une vraie clé USB

Branche ta clé (ex. `D:\`), remplace simplement `--dest C:\TestBackup\destination`
par `--dest D:\backup`. Le comportement est identique.
