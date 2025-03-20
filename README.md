# Projet Camolenn - verificateur Automatisé

## Fonctionnalités

### Sécurité
- Analyse en temps réel avec ClamAV, VirusTotal, MetaDefender et Hybrid Analysis.
- Journalisation structurée des événements.
- Serveur sécurisé avec Nginx et pare-feu (UFW).

### Efficacité
- Analyse parallèle pour des résultats rapides avec des goroutines.
- Gestion des ressources pour éviter les fuites de mémoire.
- Logs au format JSON pour une intégration facile avec des outils de monitoring.

### Technologies
- **Bibliothèques** : Gin, ClamAV, VirusTotal API, MetaDefender API, Hybrid Analysis API.
- **Système d'exploitation** : Linux (Ubuntu/Debian).
- **Serveur Web** : Nginx.

## Installation

1. Mettre à jour le système et installer les dépendances :
   ```bash
   sudo apt update
   sudo apt install -y golang clamav clamav-daemon build-essential nginx

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
   go run backend/main.go backend/logger.go backend/scanner.go backend/templates.go
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
## Liens avec la consigne (PDF)

### Objectifs de formation visés
- **Administrer un poste** : Installation et configuration de ClamAV, Nginx, et UFW.
- **Configurer un réseau simple** : Configuration de Nginx et UFW pour gérer les connexions réseau.
- **Gérer un environnement virtuel** : Utilisation de Docker pour virtualiser l'environnement de test.
- **Mettre en place une interaction client-serveur** : Serveur web Nginx et API pour l'analyse des fichiers.
- **Appréhender la sécurité** : Utilisation de ClamAV, VirusTotal, MetaDefender, et Hybrid Analysis pour la détection de menaces.

### Livrables
- **Dépôt GIT** : Le projet est versionné sur GitHub.
- **Documentation d'architecture** : Ce README et les commentaires dans le code.
- **Documentation d'exploitation** : Instructions d'installation et de configuration.

## Améliorations possibles

### Infrastructure
- **Virtualisation** : Utiliser Docker pour créer un environnement de test isolé.
- **Monitoring** : Ajouter un système de monitoring (Prometheus, Grafana) pour surveiller les performances du serveur.
- **Sauvegarde automatisée** : Automatiser les sauvegardes des logs et des configurations.

### Sécurité
- **Chiffrement des clés API** : Utiliser des outils comme Vault pour sécuriser les clés API.
- **Sécurisation avancée du serveur** : Configurer SELinux ou AppArmor pour renforcer la sécurité du serveur.
- **Gestion multi-utilisateurs** : Ajouter une gestion des utilisateurs avec des permissions spécifiques.

### Linux
- **Automatisation des tâches** : Utiliser des scripts Bash pour automatiser les tâches répétitives (mises à jour, sauvegardes).
- **Gestion des logs** : Configurer logrotate pour gérer les fichiers de logs.
- **Optimisation des performances** : Utiliser `systemd` pour gérer les services et optimiser les ressources.

## Conclusion

Ce projet répond aux exigences du module "Infrastructure & Système d'Information" en couvrant les aspects d'administration système, de configuration réseau, de virtualisation, et de sécurité. Les améliorations proposées permettront de renforcer la robustesse et la sécurité du système.

### Liens avec la consigne (PDF)

1. **Administrer un poste** :
   - Installation et configuration de ClamAV, Nginx, et UFW.
   - Automatisation des tâches avec des scripts Bash.

2. **Configurer un réseau simple** :
   - Configuration de Nginx pour servir l'application web.
   - Configuration de UFW pour gérer les connexions réseau.

3. **Gérer un environnement virtuel** :
   - Utilisation de Docker pour virtualiser l'environnement de test.

4. **Mettre en place une interaction client-serveur** :
   - Serveur web Nginx et API pour l'analyse des fichiers.

5. **Appréhender la sécurité** :
   - Utilisation de ClamAV, VirusTotal, MetaDefender, et Hybrid Analysis pour la détection de menaces.
   - Configuration de UFW pour sécuriser les ports.

### Améliorations possibles

1. **Infrastructure** :
   - Virtualisation avec Docker.
   - Ajout d'un système de monitoring (Prometheus, Grafana).
   - Automatisation des sauvegardes.

2. **Sécurité** :
   - Chiffrement des clés API avec Vault.
   - Renforcement de la sécurité du serveur avec SELinux ou AppArmor.
   - Gestion multi-utilisateurs avec des permissions spécifiques.

3. **Linux** :
   - Automatisation des tâches avec des scripts Bash.
   - Gestion des logs avec logrotate.
   - Optimisation des performances avec `systemd`.
