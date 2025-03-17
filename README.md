# Antivirus Automatisé

Ce projet est un **antivirus automatisé** qui surveille un repertoire spécifique et analyse les fichiers en temps réel. Lorsqu'un fichier infecté est détecté, il est immédiatement **mis en quarantaine** et l'utilisateur recois une notification.

## 🛠️ Technologies utilisées

- **Python** (surveillance et automatisation)
- **Watchdog** (détecter les nouveaux fichiers)
- **ClamAV** (antivirus open-source)

## Installation et Utilisation

### 1 Installation des dépendances

```bash
sudo apt update && sudo apt install -y clamav clamav-daemon python3 python3-pip
pip install watchdog requests
```

### 2 Mise à jour de la base de virus

```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```

### 3 Création des dossiers de scan et de quarantaine

```bash
mkdir -p ~/Documents/scans ~/Documents/quarantaine
```

### 4 Lancement du script

```bash
python3 AVscan.py
```

Le fichier infecté devrait être **déplacé en quarantaine** automatiquement.

## Améliorations possibles

- Création d'une interface web pour gérer les fichiers en quarantaine

* Ajouter un système de journalisation pour enregistrer les détections et les actions effectuées.
