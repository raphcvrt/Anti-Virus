package main

import (
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	watcherRunning bool
	watcherMutex   sync.Mutex
	templates      *template.Template
)

// Structure pour les données d'analyse
type ScanResult struct {
	ID               string `json:"id"`
	FileName         string `json:"file_name"`
	Date             string `json:"date"`
	ClamAVResult     string `json:"clamav_result"`
	VirusTotalResult string `json:"virustotal_result"`
	Status           string `json:"status"`
}

// Structure pour les statistiques
type Stats struct {
	FilesScanned    int `json:"files_scanned"`
	ThreatsDetected int `json:"threats_detected"`
	WatchedFolders  int `json:"watched_folders"`
	ProtectionRate  int `json:"protection_rate"`
}

// Structure pour les dossiers surveillés
type WatchedFolder struct {
	Path      string `json:"path"`
	Status    string `json:"status"`
	StartDate string `json:"start_date"`
}

// Structure pour les fichiers en quarantaine
type QuarantineFile struct {
	ID        string `json:"id"`
	FileName  string `json:"file_name"`
	Date      string `json:"date"`
	Status    string `json:"status"`
	Signature string `json:"signature"`
}

// Données réelles (initialisées à zéro ou vides)
var recentScans = []ScanResult{}

// Statistiques initialisées à zéro
var stats = Stats{
	FilesScanned:    0,
	ThreatsDetected: 0,
	WatchedFolders:  0,
	ProtectionRate:  0,
}

// Liste de dossiers surveillés vide
var watchedFolders = []WatchedFolder{}

// Liste de fichiers en quarantaine vide
var quarantineFiles = []QuarantineFile{}

func main() {
	// Initialiser le système de journalisation
	initLogger()
	logEvent("Démarrage de l'application AVSecure", nil)

	// Initialiser les templates
	var err error
	templates, err = loadTemplates("./templates") // Chemin relatif depuis le dossier backend
	if err != nil {
		logEvent("Erreur lors du chargement des templates", map[string]interface{}{
			"error": err.Error(),
		})
		panic(err)
	}

	// Configurer le serveur Gin
	r := gin.Default()

	// Middleware pour servir les fichiers statiques
	r.Static("/static", "./static") // ../

	// Configurer les routes pour les pages
	r.GET("/", renderDashboard)
	r.GET("/analyse", renderAnalyse)
	r.GET("/surveillance", renderSurveillance)
	r.GET("/historique", renderHistorique)
	r.GET("/quarantaine", renderQuarantaine)
	r.GET("/parametres", renderParametres)

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

		// Ajouter le dossier à la liste des dossiers surveillés
		watchedFolders = append(watchedFolders, WatchedFolder{
			Path:      req.FolderPath,
			Status:    "Active",
			StartDate: time.Now().Format("02/01/2006 15:04"),
		})

		logEvent("Surveillance démarrée", map[string]interface{}{
			"folder": req.FolderPath,
		})
		c.JSON(http.StatusOK, gin.H{"message": "Surveillance démarrée"})
	})

	// Route pour arrêter la surveillance
	r.POST("/stop-watch", func(c *gin.Context) {
		var req struct {
			FolderPath string `json:"folder_path"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			logEvent("Requête invalide pour arrêter la surveillance", map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusBadRequest, gin.H{"error": "Requête invalide"})
			return
		}

		if err := stopWatcher(); err != nil {
			logEvent("Erreur lors de l'arrêt de la surveillance", map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Mettre à jour le statut du dossier
		for i, folder := range watchedFolders {
			if folder.Path == req.FolderPath {
				watchedFolders[i].Status = "Inactive"
				break
			}
		}

		logEvent("Surveillance arrêtée", nil)
		c.JSON(http.StatusOK, gin.H{"message": "Surveillance arrêtée"})
	})

	// Routes API pour les données
	r.GET("/api/recent-scans", func(c *gin.Context) {
		c.JSON(http.StatusOK, recentScans)
	})

	r.GET("/api/stats", func(c *gin.Context) {
		c.JSON(http.StatusOK, stats)
	})

	r.GET("/api/watched-folders", func(c *gin.Context) {
		c.JSON(http.StatusOK, watchedFolders)
	})

	r.GET("/api/quarantine-files", func(c *gin.Context) {
		c.JSON(http.StatusOK, quarantineFiles)
	})

	// Démarrer le serveur
	r.Run("0.0.0.0:9555")
}

// Fonction pour rendre la page d'accueil
func renderDashboard(c *gin.Context) {
	fmt.Println("🔍 Rendu de la page d'accueil")
	data := TemplateData{
		Title:       "AVSecure - Tableau de bord",
		ActivePage:  "dashboard",
		Stats:       stats,
		RecentScans: recentScans,
	}
	renderTemplate(c.Writer, templates, "index.html", data)
}

// Fonction pour rendre la page d'analyse
func renderAnalyse(c *gin.Context) {
	data := TemplateData{
		Title:      "AVSecure - Analyse de fichiers",
		ActivePage: "analyse",
	}
	renderTemplate(c.Writer, templates, "analyse.html", data)
}

// Fonction pour rendre la page de surveillance
func renderSurveillance(c *gin.Context) {
	data := TemplateData{
		Title:          "AVSecure - Surveillance",
		ActivePage:     "surveillance",
		WatchedFolders: watchedFolders,
	}
	renderTemplate(c.Writer, templates, "surveillance.html", data)
}

// Fonction pour rendre la page d'historique
func renderHistorique(c *gin.Context) {
	data := TemplateData{
		Title:       "AVSecure - Historique",
		ActivePage:  "historique",
		RecentScans: recentScans,
	}
	renderTemplate(c.Writer, templates, "historique.html", data)
}

// Fonction pour rendre la page de quarantaine
func renderQuarantaine(c *gin.Context) {
	data := TemplateData{
		Title:           "AVSecure - Quarantaine",
		ActivePage:      "quarantaine",
		QuarantineFiles: quarantineFiles,
	}
	renderTemplate(c.Writer, templates, "quarantaine.html", data)
}

// Fonction pour rendre la page de paramètres
func renderParametres(c *gin.Context) {
	data := TemplateData{
		Title:      "AVSecure - Paramètres",
		ActivePage: "parametres",
	}
	renderTemplate(c.Writer, templates, "parametres.html", data)
}

// Analyse d'un fichier
func analyzeFile(file *multipart.FileHeader) (string, error) {
	// Sauvegarder le fichier temporairement
	filePath := filepath.Join(os.TempDir(), file.Filename)
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

	// Ajouter le résultat à la liste des analyses récentes
	newScan := ScanResult{
		ID:               fmt.Sprintf("%d", len(recentScans)+1),
		FileName:         file.Filename,
		Date:             time.Now().Format("02/01/2006 15:04"),
		ClamAVResult:     clamAVResult,
		VirusTotalResult: virusTotalResult,
		Status:           finalResult,
	}
	recentScans = append([]ScanResult{newScan}, recentScans...)

	// Mettre à jour les statistiques
	stats.FilesScanned++
	if finalResult == "infected" {
		stats.ThreatsDetected++

		// Ajouter à la quarantaine si infecté
		quarantineFiles = append([]QuarantineFile{
			{
				ID:        fmt.Sprintf("%d", len(quarantineFiles)+1),
				FileName:  file.Filename,
				Date:      time.Now().Format("02/01/2006 15:04"),
				Status:    "Isolé",
				Signature: "Détecté par ClamAV et/ou VirusTotal",
			},
		}, quarantineFiles...)
	}

	// Calculer le taux de protection
	if stats.FilesScanned > 0 {
		stats.ProtectionRate = 100 - (stats.ThreatsDetected * 100 / stats.FilesScanned)
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

	// Mettre à jour les statistiques
	stats.WatchedFolders++

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

	// Mettre à jour les statistiques
	stats.WatchedFolders--

	// Journaliser l'arrêt de la surveillance
	logEvent("Surveillance arrêtée", nil)

	return nil
}
