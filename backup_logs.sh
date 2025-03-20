#!/bin/bash

# Variables
BACKUP_DIR="/backups"
LOG_DIR="/var/log/avsecure"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_FILE="$BACKUP_DIR/log_backup_$TIMESTAMP.tar.gz"
LOG_FILE="$LOG_DIR/avsecure.log"

# Créer le dossier de sauvegarde s'il n'existe pas
mkdir -p $BACKUP_DIR

# Sauvegarder les logs
tar -czf $BACKUP_FILE $LOG_DIR

# Vider le fichier avsecure.log après la sauvegarde
if [ -f $LOG_FILE ]; then
    > $LOG_FILE  # Vide le fichier
    echo "Fichier $LOG_FILE vidé après sauvegarde."
else
    echo "Fichier $LOG_FILE non trouvé."
fi

echo "Sauvegarde terminée : $BACKUP_FILE"