#!/bin/bash

# Chemin du fichier de log
LOG_FILE="/home/paph/avsecure/Anti-Virus/avsecure.log"

# Répertoire de sauvegarde
BACKUP_DIR="/home/paph/avsecure/Anti-Virus/Saves"

# Nom du fichier de sauvegarde (avec la date actuelle)
BACKUP_NAME="log_backup_$(date +'%Y-%m-%d').tar.gz"

# Vérifier si le répertoire de sauvegarde existe, sinon le créer
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
fi

# Créer une archive compressée du fichier de log
tar -czf "$BACKUP_DIR/$BACKUP_NAME" "$LOG_FILE"

# Vérifier si la sauvegarde a réussi
if [ $? -eq 0 ]; then
    echo "Sauvegarde réussie : $BACKUP_DIR/$BACKUP_NAME"
else
    echo "Erreur lors de la sauvegarde."
    exit 1
fi