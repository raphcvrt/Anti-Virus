# Antivirus Automatisé

Ce projet est un **antivirus automatisé** qui surveille un repertoire spécifique et analyse les fichiers en temps réel. Lorsqu'un fichier infecté est détecté, il est immédiatement **mis en quarantaine** et l'utilisateur recois une notification.

## Fonctionnalités

### Sécurité

- Analyse en temps réel avec ClamAV et VirusTotal.
- Journalisation structurée des événements.
- server securisé avec (le procédé suivant)[https://github.com/raphcvrt/LINUX/blob/main/TP5/raphael_couvert.md]

### Efficacité

- Analyse parallèle pour des résultats rapides avec des goroutines.
- Gestion des ressources pour éviter les fuites de mémoire.
- Logs au format JSON pour une intégration facile avec des outils de monitoring.

### Technologies

- **Bibliothèques** : Gin, fsnotify, ClamAV, VirusTotal API.

### Améliorations Possibles

- Chiffrement des clés API.
- securisation avancée du server
- gestion multiutilisateurs
- ajouter plus d'api

```
   11  sudo apt update
   12  sudo apt install -y golang clamav clamav-daemon build-essential
   13  sudo mkdir -p /etc/clamav
   14  sudo freshclam
   15  mkdir -p ~/avsecure
   16  cd ~/avsecure
   17  sudo apt update
   18  sudo apt install nginx
   19  sudo nano /etc/nginx/sites-available/avsecure
   20  sudo ln -s /etc/nginx/sites-available/avsecure /etc/nginx/sites-enabled/
   21  sudo nginx -t
   22  sudo systemctl restart nginx
   23  sudo ufw allow 'Nginx Full'
   24  sudo ufw allow 9555/tcp
   25  sudo ufw reload
   31  sudo systemctl start nginx
   32  sudo systemctl enable nginx
   33  sudo systemctl status nginx
   35  git clone https://github.com/raphcvrt/Anti-Virus.git
   37  cd Anti-Virus/
   40  go run backend/main.go backend/logger.go backend/scanner.go backend/templates.go 
```