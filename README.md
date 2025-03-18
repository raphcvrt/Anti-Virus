# Antivirus Automatisé

Ce projet est un **antivirus automatisé** qui surveille un repertoire spécifique et analyse les fichiers en temps réel. Lorsqu'un fichier infecté est détecté, il est immédiatement **mis en quarantaine** et l'utilisateur recois une notification.

## Fonctionnalités

### Sécurité

- Analyse en temps réel avec ClamAV et VirusTotal.
- Journalisation structurée des événements.

### Efficacité

- Analyse parallèle pour des résultats rapides avec des goroutines.
- Gestion des ressources pour éviter les fuites de mémoire.
- Logs au format JSON pour une intégration facile avec des outils de monitoring.

### Technologies

- **Bibliothèques** : Gin, Logrus, fsnotify, ClamAV, VirusTotal API.

### Améliorations Possibles

- Chiffrement des clés API.
- securisation avancée du server
- darkmode