# Projet Camolenn - verificateur Automatisé

Site qui permet de verifier la sécurité d'un fichier 

## Fonctionnalités

- Analyse avec ClamAV, VirusTotal, MetaDefender et Hybrid Analysis.
- Journalisation structurée des événements.
- Serveur sécurisé avec Nginx et pare-feu (UFW).
- sauvegarde mensuelle et reinitialisation des logs grace a un script bash

## Installation

1. Mettre à jour le système et installer les dépendances :

   ```bash
   sudo apt update
   sudo apt install -y golang clamav clamav-daemon build-essential nginx
   ```
2. Configurer ClamAV :

   ```bash
   sudo mkdir -p /etc/clamav
   sudo freshclam
   ```
3. Configurer Nginx :

   ```bash
   sudo nano /etc/nginx/sites-available/avsecure
   sudo ln -s /etc/nginx/sites-available/avsecure /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```
4. Configurer le pare-feu UFW :

   ```bash
   sudo ufw allow 'Nginx Full'
   sudo ufw allow 9555/tcp
   sudo ufw reload
   ```
5. Cloner le dépôt et lancer l'application :

   ```bash
   git clone https://github.com/raphcvrt/Anti-Virus.git
   cd Anti-Virus/
   ./camolenn
   ```

## Arborescence du projet

```
.
├── A FAIRE !!
├── avsecure.log
├── backend
│   ├── logger.go
│   ├── main.go
│   ├── scanner.go
│   └── templates.go
├── backup_logs.sh
├── eicar.com
├── go.mod
├── go.sum
├── README.md
├── Saves
│   └── log_backup_2025-03-19.tar.gz
├── static
│   ├── scripts.js
│   ├── _styles.css
│   └── styles.css
├── templates
│   ├── index.html
│   └── layout.html
└── tree.txt
```

## Améliorations possibles

- **Virtualisation** : Utiliser Docker pour créer un environnement de test isolé.
- **Monitoring** : prometheus
- **Chiffrement des clés API** : vault
- **Sécurisation avancée du serveur** : Configurer SELinux ou AppArmor pour renforcer la sécurité du serveur.
- **Gestion multi-utilisateurs** : Ajouter une gestion des utilisateurs avec des comptes.
- **Optimisation des performances** : systemd
- **Règles d'upload** : limites de taille, extentions specifiques 