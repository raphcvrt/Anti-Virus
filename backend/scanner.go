package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	VirusTotalAPIKey = "1b9821aec8c7b8bf75b30923ef670b70edaab347f51f7f8f76ff9e329d15cdea"
	VirusTotalURL    = "https://www.virustotal.com/api/v3/files"
)

func scanWithClamAV(filePath string) (string, error) {
	// Exécuter clamscan sur le fichier
	cmd := exec.Command("clamscan", filePath)
	output, err := cmd.CombinedOutput()

	// Convertir la sortie en chaîne de caractères
	outputStr := string(output)

	// Gérer les erreurs
	if err != nil {
		// Si clamscan retourne un code d'erreur 1, c'est qu'un fichier infecté a été détecté
		if strings.Contains(outputStr, "Infected files: 1") {
			logEvent("Fichier infecté détecté", map[string]interface{}{
				"file":   filePath,
				"result": "infected",
			})
			return "infected", nil
		}
		// Sinon, retourner une erreur générique
		logEvent("Erreur lors de l'analyse ClamAV", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de l'analyse: %s", outputStr)
	}

	// Si aucun fichier infecté n'est détecté, retourner "clean"
	logEvent("Fichier analysé avec ClamAV", map[string]interface{}{
		"file":   filePath,
		"result": "clean",
	})
	return "clean", nil
}

func scanWithVirusTotal(filePath string) (string, error) {
	// Ouvrir le fichier
	file, err := os.Open(filePath)
	if err != nil {
		logEvent("Erreur lors de l'ouverture du fichier", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de l'ouverture du fichier: %v", err)
	}
	defer file.Close()

	// Créer un buffer pour stocker le corps de la requête
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Ajouter le fichier au corps de la requête
	fileWriter, err := writer.CreateFormFile("file", filePath)
	if err != nil {
		logEvent("Erreur lors de la création du formulaire", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la création du formulaire: %v", err)
	}
	if _, err := io.Copy(fileWriter, file); err != nil {
		logEvent("Erreur lors de la copie du fichier", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la copie du fichier: %v", err)
	}
	writer.Close()

	// Créer la requête HTTP
	req, err := http.NewRequest("POST", VirusTotalURL, &requestBody)
	if err != nil {
		logEvent("Erreur lors de la création de la requête", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la création de la requête: %v", err)
	}

	// Ajouter les en-têtes nécessaires
	req.Header.Set("x-apikey", VirusTotalAPIKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Envoyer la requête
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logEvent("Erreur lors de l'envoi de la requête", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de l'envoi de la requête: %v", err)
	}
	defer resp.Body.Close()

	// Vérifier le statut de la réponse
	if resp.StatusCode != http.StatusOK {
		logEvent("Erreur de l'API VirusTotal", map[string]interface{}{
			"file":  filePath,
			"error": resp.Status,
		})
		return "", fmt.Errorf("erreur de l'API VirusTotal: %s", resp.Status)
	}

	// Lire la réponse
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logEvent("Erreur lors de la lecture de la réponse", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la lecture de la réponse: %v", err)
	}

	// Récupérer l'ID de l'analyse
	analysisID, ok := result["data"].(map[string]interface{})["id"].(string)
	if !ok {
		logEvent("Erreur lors de la récupération de l'ID de l'analyse", map[string]interface{}{
			"file":  filePath,
			"error": "ID de l'analyse non trouvé",
		})
		return "", fmt.Errorf("erreur lors de la récupération de l'ID de l'analyse")
	}

	// Attendre que l'analyse soit terminée
	time.Sleep(30 * time.Second) // Attendre 30 secondes (ajustez selon vos besoins)

	// Récupérer le rapport d'analyse
	analysisURL := fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", analysisID)
	req, err = http.NewRequest("GET", analysisURL, nil)
	if err != nil {
		logEvent("Erreur lors de la création de la requête", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la création de la requête: %v", err)
	}
	req.Header.Set("x-apikey", VirusTotalAPIKey)

	resp, err = client.Do(req)
	if err != nil {
		logEvent("Erreur lors de l'envoi de la requête", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de l'envoi de la requête: %v", err)
	}
	defer resp.Body.Close()

	// Lire la réponse
	var analysisResult map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&analysisResult); err != nil {
		logEvent("Erreur lors de la lecture de la réponse", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la lecture de la réponse: %v", err)
	}

	// Vérifier si le fichier est infecté
	stats, ok := analysisResult["data"].(map[string]interface{})["attributes"].(map[string]interface{})["stats"].(map[string]interface{})
	if !ok {
		logEvent("Erreur lors de la récupération des statistiques", map[string]interface{}{
			"file":  filePath,
			"error": "Statistiques non trouvées",
		})
		return "", fmt.Errorf("erreur lors de la récupération des statistiques")
	}

	malicious, ok := stats["malicious"].(float64)
	if !ok {
		logEvent("Erreur lors de la récupération du nombre de détections malveillantes", map[string]interface{}{
			"file":  filePath,
			"error": "Détections malveillantes non trouvées",
		})
		return "", fmt.Errorf("erreur lors de la récupération du nombre de détections malveillantes")
	}

	if malicious > 0 {
		logEvent("Fichier infecté détecté par VirusTotal", map[string]interface{}{
			"file":   filePath,
			"result": "infected",
		})
		return "infected", nil
	}

	logEvent("Fichier analysé avec VirusTotal", map[string]interface{}{
		"file":   filePath,
		"result": "clean",
	})
	return "clean", nil
}
