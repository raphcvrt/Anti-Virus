# Antivirus Automatisé

Ce projet est un **antivirus automatisé** qui surveille un repertoire spécifique et analyse les fichiers en temps réel. Lorsqu'un fichier infecté est détecté, il est immédiatement **mis en quarantaine** et l'utilisateur recois une notification.

## Fonctionnalités

### Sécurité

- Analyse en temps réel avec ClamAV et VirusTotal.
- Mise en quarantaine automatique des fichiers infectés.
- Alertes Discord en temps réel.
- Journalisation structurée des événements.

### Efficacité

- Analyse parallèle pour des résultats rapides.
- Surveillance de dossier en temps réel avec fsnotify.
- Interface RESTful pour l'upload et la gestion des analyses.

### Optimisation

- Utilisation de goroutines pour un traitement parallèle.
- Gestion des ressources pour éviter les fuites de mémoire.
- Logs au format JSON pour une intégration facile avec des outils de monitoring.

### Technologies

- **Langages** : Go, HTML/CSS/JavaScript.
- **Bibliothèques** : Gin, Logrus, fsnotify, ClamAV, VirusTotal API.
- **Outils** : Discord Webhook, Goroutines.

### Améliorations Possibles

- Chiffrement des clés API.
- Analyse comportementale.
- Support multi-utilisateurs.
