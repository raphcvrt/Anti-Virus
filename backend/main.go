package main

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	watcherRunning bool
	watcherMutex   sync.Mutex
)

// Struct pour les données d'analyse
type ScanResult struct {
	FileName         string `json:"file_name"`
	Date             string `json:"date"`
	ClamAVResult     string `json:"clamav_result"`
	VirusTotalResult string `json:"virustotal_result"`
	Status           string `json:"status"`
}

// Struct pour les statistiques
type Stats struct {
	FilesScanned    int `json:"files_scanned"`
	ThreatsDetected int `json:"threats_detected"`
	WatchedFolders  int `json:"watched_folders"`
	ProtectionRate  int `json:"protection_rate"`
}

// Données factices pour les analyses récentes (à remplacer par une base de données)
var recentScans = []ScanResult{
	{FileName: "document.pdf", Date: time.Now().Format("02/01/2006 15:04"), ClamAVResult: "Clean", VirusTotalResult: "Clean", Status: "Clean"},
	{FileName: "setup.exe", Date: time.Now().Format("02/01/2006 15:04"), ClamAVResult: "Infected", VirusTotalResult: "Infected", Status: "Infected"},
}

// Données factices pour les statistiques (à remplacer par une base de données)
var stats = Stats{
	FilesScanned:    178,
	ThreatsDetected: 7,
	WatchedFolders:  1,
	ProtectionRate:  96,
}

func main() {
	// Initialiser le système de journalisation
	initLogger()
	logEvent("Démarrage de l'application AVsecure", nil)

	r := gin.Default()

	// Servir les fichiers statiques du frontend
	r.Static("/static", "./frontend")

	// Route pour uploader un fichier
	r.POST("/upload", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			logEvent("Erreur lors de la récupération du fichier", map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusBadRequest, gin.H{"error": "Fichier non fourni"})
			return
		}

		// Analyser le fichier
		result, err := analyzeFile(file)
		if err != nil {
			logEvent("Erreur lors de l'analyse du fichier", map[string]interface{}{
				"file":  file.Filename,
				"error": err.Error(),
			})
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Envoyer une alerte Discord si le fichier est infecté
		if result == "infected" {
			sendDiscordAlert(fmt.Sprintf("⚠️ Fichier infecté détecté : %s", file.Filename))
			logEvent("Fichier infecté détecté", map[string]interface{}{
				"file":   file.Filename,
				"result": result,
			})
		}

		c.JSON(http.StatusOK, gin.H{"filename": file.Filename, "result": result})
	})

	// Route pour démarrer la surveillance
	r.POST("/start-watch", func(c *gin.Context) {
		var req struct {
			FolderPath string `json:"folder_path"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			logEvent("Requête invalide pour démarrer la surveillance", map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusBadRequest, gin.H{"error": "Requête invalide"})
			return
		}

		if err := startWatcher(req.FolderPath); err != nil {
			logEvent("Erreur lors du démarrage de la surveillance", map[string]interface{}{
				"folder": req.FolderPath,
				"error":  err.Error(),
			})
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		logEvent("Surveillance démarrée", map[string]interface{}{
			"folder": req.FolderPath,
		})
		c.JSON(http.StatusOK, gin.H{"message": "Surveillance démarrée"})
	})

	// Route pour arrêter la surveillance
	r.POST("/stop-watch", func(c *gin.Context) {
		if err := stopWatcher(); err != nil {
			logEvent("Erreur lors de l'arrêt de la surveillance", map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		logEvent("Surveillance arrêtée", nil)
		c.JSON(http.StatusOK, gin.H{"message": "Surveillance arrêtée"})
	})

	// Route pour servir la page d'accueil
	r.GET("/", func(c *gin.Context) {
		c.File("./frontend/index.html")
	})

	// Nouvelle route : Récupérer les analyses récentes
	r.GET("/api/recent-scans", func(c *gin.Context) {
		c.JSON(http.StatusOK, recentScans)
	})

	// Nouvelle route : Récupérer les statistiques
	r.GET("/api/stats", func(c *gin.Context) {
		c.JSON(http.StatusOK, stats)
	})

	// Démarrer le serveur
	r.Run(":9555")
}

func analyzeFile(file *multipart.FileHeader) (string, error) {
	// Sauvegarder le fichier temporairement
	filePath := "/tmp/" + file.Filename
	fileData, err := file.Open()
	if err != nil {
		logEvent("Erreur lors de l'ouverture du fichier", map[string]interface{}{
			"file":  file.Filename,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de l'ouverture du fichier")
	}
	defer fileData.Close()

	// Créer un fichier temporaire
	tempFile, err := os.Create(filePath)
	if err != nil {
		logEvent("Erreur lors de la création du fichier temporaire", map[string]interface{}{
			"file":  file.Filename,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la création du fichier temporaire")
	}
	defer tempFile.Close()

	// Copier le contenu du fichier uploadé vers le fichier temporaire
	if _, err := io.Copy(tempFile, fileData); err != nil {
		logEvent("Erreur lors de la copie du fichier", map[string]interface{}{
			"file":  file.Filename,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la copie du fichier")
	}

	// Créer des canaux pour recevoir les résultats des analyses
	clamAVChan := make(chan string)
	virusTotalChan := make(chan string)
	errChan := make(chan error)

	// Démarrer les analyses en parallèle avec des goroutines
	go func() {
		result, err := scanWithClamAV(filePath)
		if err != nil {
			errChan <- fmt.Errorf("erreur ClamAV: %v", err)
			return
		}
		clamAVChan <- result
	}()

	go func() {
		result, err := scanWithVirusTotal(filePath)
		if err != nil {
			errChan <- fmt.Errorf("erreur VirusTotal: %v", err)
			return
		}
		virusTotalChan <- result
	}()

	// Attendre les résultats des deux analyses
	var clamAVResult, virusTotalResult string
	var clamAVErr, virusTotalErr error

	for i := 0; i < 2; i++ {
		select {
		case result := <-clamAVChan:
			clamAVResult = result
			logEvent("Résultat de l'analyse ClamAV", map[string]interface{}{
				"file":   file.Filename,
				"result": result,
			})
		case result := <-virusTotalChan:
			virusTotalResult = result
			logEvent("Résultat de l'analyse VirusTotal", map[string]interface{}{
				"file":   file.Filename,
				"result": result,
			})
		case err := <-errChan:
			if strings.Contains(err.Error(), "ClamAV") {
				clamAVErr = err
			} else {
				virusTotalErr = err
			}
			logEvent("Erreur lors de l'analyse", map[string]interface{}{
				"file":  file.Filename,
				"error": err.Error(),
			})
		}
	}

	// Déterminer le résultat final
	finalResult := "clean"
	if clamAVResult == "infected" || virusTotalResult == "infected" {
		finalResult = "infected"
	}

	// Journaliser le résultat final
	logEvent("Résultat final de l'analyse", map[string]interface{}{
		"file":   file.Filename,
		"result": finalResult,
	})

	// Retourner une erreur si l'une des analyses a échoué
	if clamAVErr != nil || virusTotalErr != nil {
		return finalResult, fmt.Errorf("une ou plusieurs analyses ont échoué: ClamAV: %v, VirusTotal: %v", clamAVErr, virusTotalErr)
	}

	return finalResult, nil
}

// Démarrer la surveillance
func startWatcher(folderPath string) error {
	watcherMutex.Lock()
	defer watcherMutex.Unlock()

	if watcherRunning {
		return fmt.Errorf("la surveillance est déjà en cours")
	}

	// Démarrer la surveillance du dossier
	go watchFolder(folderPath)
	watcherRunning = true

	// Journaliser le démarrage de la surveillance
	logEvent("Surveillance démarrée", map[string]interface{}{
		"folder": folderPath,
	})

	return nil
}

// Arrêter la surveillance
func stopWatcher() error {
	watcherMutex.Lock()
	defer watcherMutex.Unlock()

	if !watcherRunning {
		return fmt.Errorf("aucune surveillance en cours")
	}

	watcherRunning = false

	// Journaliser l'arrêt de la surveillance
	logEvent("Surveillance arrêtée", nil)

	return nil
}
