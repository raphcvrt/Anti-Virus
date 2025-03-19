package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	templates *template.Template
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
	ProtectionRate  int `json:"protection_rate"`
}

// Données réelles (initialisées à zéro ou vides)
var recentScans = []ScanResult{}

// Statistiques initialisées à zéro
var stats = Stats{
	FilesScanned:    0,
	ThreatsDetected: 0,
	ProtectionRate:  0,
}

func main() {
	// Supprimer le fichier data.json au démarrage
	if err := os.Remove("data.json"); err != nil {
		if !os.IsNotExist(err) { // Ignorer l'erreur si le fichier n'existe pas
			logEvent("Erreur lors de la suppression du fichier data.json", map[string]interface{}{
				"error": err.Error(),
			})
			panic(err)
		}
	}
	// Initialiser le système de journalisation
	initLogger()
	logEvent("Démarrage de l'application AVSecure", nil)

	// Charger les données persistantes
	if err := loadData(); err != nil {
		logEvent("Erreur lors du chargement des données", map[string]interface{}{
			"error": err.Error(),
		})
		panic(err)
	}

	// Initialiser les templates
	var err error
	templates, err = loadTemplates("./templates")
	if err != nil {
		logEvent("Erreur lors du chargement des templates", map[string]interface{}{
			"error": err.Error(),
		})
		panic(err)
	}

	// Configurer le serveur Gin
	r := gin.Default()

	// Middleware pour servir les fichiers statiques
	r.Static("/static", "./static")

	// Configurer les routes pour les pages
	r.GET("/", renderDashboard)

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

		// Sauvegarder les données après chaque analyse
		if err := saveData(); err != nil {
			logEvent("Erreur lors de la sauvegarde des données", map[string]interface{}{
				"error": err.Error(),
			})
		}

		c.JSON(http.StatusOK, gin.H{"filename": file.Filename, "result": result})
	})

	// Routes API pour les données
	r.GET("/api/recent-scans", func(c *gin.Context) {
		c.JSON(http.StatusOK, recentScans)
	})

	r.GET("/api/stats", func(c *gin.Context) {
		c.JSON(http.StatusOK, stats)
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
		Stats:       stats,       // Assurez-vous que `stats` est bien défini
		RecentScans: recentScans, // Assurez-vous que `recentScans` est bien défini
	}
	renderTemplate(c.Writer, templates, "index.html", data)
}

// Analyse d'un fichier
func analyzeFile(file *multipart.FileHeader) (string, error) {
	logEvent("Début de l'analyse du fichier", map[string]interface{}{
		"file": file.Filename,
	})
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
	// Mettre à jour les statistiques
	stats.FilesScanned++
	if finalResult == "infected" {
		stats.ThreatsDetected++
	}
	if stats.FilesScanned > 0 {
		stats.ProtectionRate = 100 - (stats.ThreatsDetected * 100 / stats.FilesScanned)
	}

	// Sauvegarder les données
	if err := saveData(); err != nil {
		logEvent("Erreur lors de la sauvegarde des données", map[string]interface{}{
			"error": err.Error(),
		})
	}
	return finalResult, nil

}

// Sauvegarder les données dans un fichier JSON
func saveData() error {
	data := struct {
		Stats       Stats
		RecentScans []ScanResult
	}{
		Stats:       stats,
		RecentScans: recentScans,
	}

	file, err := os.Create("data.json")
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(data)
}

func loadData() error {
	file, err := os.Open("data.json")
	if err != nil {
		if os.IsNotExist(err) {
			stats = Stats{
				FilesScanned:    0,
				ThreatsDetected: 0,
				ProtectionRate:  0,
			}
			recentScans = []ScanResult{}
			return nil
		}
		return err
	}
	defer file.Close()

	data := struct {
		Stats       Stats
		RecentScans []ScanResult
	}{}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return err
	}

	stats = data.Stats
	recentScans = data.RecentScans

	logEvent("Données chargées", map[string]interface{}{
		"stats":       stats,
		"recentScans": recentScans,
	})

	return nil
}
