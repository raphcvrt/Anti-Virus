package main

import (
	"os"

	"github.com/sirupsen/logrus"
)

var journal = logrus.New()

func initLogger() {
	// Configuration de logrus
	journal.SetFormatter(&logrus.JSONFormatter{}) // Format JSON pour les logs
	journal.SetOutput(os.Stdout)                  // Sortie des logs dans la console
	journal.SetLevel(logrus.InfoLevel)            // Niveau de log (Info, Debug, etc.)

	// Optionnel : Ajouter un fichier de log
	file, err := os.OpenFile("avsecure.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		journal.Fatalf("Erreur lors de l'ouverture du fichier de log: %v", err)
	}
	journal.SetOutput(file) // Rediriger les logs vers le fichier
}

func logEvent(message string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	journal.WithFields(fields).Info(message)
}
