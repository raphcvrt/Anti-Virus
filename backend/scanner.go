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
	"path/filepath"
	"strings"
	"time"
)

const (
	VirusTotalAPIKey     = "1b9821aec8c7b8bf75b30923ef670b70edaab347f51f7f8f76ff9e329d15cdea"
	VirusTotalURL        = "https://www.virustotal.com/api/v3/files"
	MetaDefenderAPIKey   = "47e03f28994a86f5ed05d9dd0a92b8be"
	MetaDefenderURL      = "https://api.metadefender.com/v4/file"
	HybridAnalysisAPIKey = "6ynx25xybde3836dp4z6ejqab366fb05fucls4nbed18617bwew3rwy776e45307"
	HybridAnalysisURL    = "https://www.hybrid-analysis.com/api/v2/submit/file"
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

func scanWithMetaDefender(filePath string) (string, error) {
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

	// Créer la requête HTTP directement sans multipart (selon la doc MetaDefender)
	// La documentation indique que le contenu du fichier doit être envoyé directement dans le corps
	fileInfo, err := file.Stat()
	if err != nil {
		logEvent("Erreur lors de la récupération des informations du fichier", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la récupération des informations du fichier: %v", err)
	}

	// Reset file pointer to beginning
	file.Seek(0, 0)

	// Lire tout le contenu du fichier
	fileContents, err := io.ReadAll(file)
	if err != nil {
		logEvent("Erreur lors de la lecture du fichier", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la lecture du fichier: %v", err)
	}

	// Créer la requête HTTP avec le contenu brut du fichier
	req, err := http.NewRequest("POST", MetaDefenderURL, bytes.NewReader(fileContents))
	if err != nil {
		logEvent("Erreur lors de la création de la requête", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la création de la requête: %v", err)
	}

	// Ajouter les en-têtes nécessaires selon la documentation MetaDefender
	req.Header.Set("apikey", MetaDefenderAPIKey)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("filename", filepath.Base(filePath))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

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
		bodyBytes, _ := io.ReadAll(resp.Body)
		logEvent("Erreur de l'API MetaDefender", map[string]interface{}{
			"file":     filePath,
			"status":   resp.Status,
			"response": string(bodyBytes),
		})
		return "", fmt.Errorf("erreur de l'API MetaDefender: %s - %s", resp.Status, string(bodyBytes))
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

	// Récupérer l'ID de l'analyse (data_id) selon la doc
	dataID, ok := result["data_id"].(string)
	if !ok {
		logEvent("Erreur lors de la récupération de l'ID de l'analyse", map[string]interface{}{
			"file":     filePath,
			"error":    "ID de l'analyse non trouvé",
			"response": result,
		})
		return "", fmt.Errorf("erreur lors de la récupération de l'ID de l'analyse")
	}

	// Attendre que l'analyse soit terminée en effectuant des sondages
	// selon la documentation MetaDefender
	var analysisResult map[string]interface{}
	maxRetries := 15
	for i := 0; i < maxRetries; i++ {
		time.Sleep(2 * time.Second) // Attendre 2 secondes entre chaque tentative

		// Récupérer le rapport d'analyse
		analysisURL := fmt.Sprintf("%s/%s", MetaDefenderURL, dataID)
		req, err = http.NewRequest("GET", analysisURL, nil)
		if err != nil {
			logEvent("Erreur lors de la création de la requête", map[string]interface{}{
				"file":  filePath,
				"error": err.Error(),
			})
			return "", fmt.Errorf("erreur lors de la création de la requête: %v", err)
		}
		req.Header.Set("apikey", MetaDefenderAPIKey)

		resp, err = client.Do(req)
		if err != nil {
			logEvent("Erreur lors de l'envoi de la requête", map[string]interface{}{
				"file":  filePath,
				"error": err.Error(),
			})
			return "", fmt.Errorf("erreur lors de l'envoi de la requête: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			logEvent("Erreur lors de la récupération du statut de l'analyse", map[string]interface{}{
				"file":  filePath,
				"error": resp.Status,
			})
			continue // Essayer à nouveau
		}

		if err := json.NewDecoder(resp.Body).Decode(&analysisResult); err != nil {
			resp.Body.Close()
			logEvent("Erreur lors de la lecture de la réponse", map[string]interface{}{
				"file":  filePath,
				"error": err.Error(),
			})
			return "", fmt.Errorf("erreur lors de la lecture de la réponse: %v", err)
		}
		resp.Body.Close()

		// Vérifier le statut du scan selon la doc MetaDefender
		scanResults, ok := analysisResult["scan_results"].(map[string]interface{})
		if !ok {
			continue // Continuer à attendre
		}

		// Vérifier si l'analyse est terminée
		scanStatus, ok := scanResults["scan_all_result_a"].(string)
		if !ok {
			continue
		}

		// Si l'analyse est terminée, vérifier le résultat
		if scanStatus == "No Threat Detected" {
			logEvent("Fichier analysé avec MetaDefender", map[string]interface{}{
				"file":   filePath,
				"result": "clean",
			})
			return "clean", nil
		} else if scanStatus != "In Progress" {
			logEvent("Fichier infecté détecté par MetaDefender", map[string]interface{}{
				"file":   filePath,
				"result": "infected",
				"status": scanStatus,
			})
			return "infected", nil
		}
	}

	// Si on arrive ici, c'est que l'analyse n'a pas terminé dans le temps imparti
	logEvent("Délai d'attente dépassé pour l'analyse MetaDefender", map[string]interface{}{
		"file": filePath,
	})
	return "", fmt.Errorf("délai d'attente dépassé pour l'analyse MetaDefender")
}

func scanWithHybridAnalysis(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		logEvent("Erreur lors de l'ouverture du fichier", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de l'ouverture du fichier: %v", err)
	}
	defer file.Close()

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Ajouter le fichier au corps de la requête
	fileWriter, err := writer.CreateFormFile("file", filepath.Base(filePath))
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

	// Ajouter uniquement le champ obligatoire environment_id
	writer.WriteField("environment_id", "100") // Windows 7 32-bit (selon la doc)
	writer.Close()

	// Créer la requête HTTP
	req, err := http.NewRequest("POST", HybridAnalysisURL, &requestBody)
	if err != nil {
		logEvent("Erreur lors de la création de la requête", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return "", fmt.Errorf("erreur lors de la création de la requête: %v", err)
	}

	// Ajouter les en-têtes nécessaires selon la doc Hybrid Analysis
	req.Header.Set("api-key", HybridAnalysisAPIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "Falcon Sandbox")

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

	// Vérifier le statut de la réponse (200 OK ou 201 Created)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logEvent("Erreur de l'API Hybrid Analysis", map[string]interface{}{
			"file":     filePath,
			"status":   resp.Status,
			"response": string(bodyBytes),
		})
		return "", fmt.Errorf("erreur de l'API Hybrid Analysis: %s - %s", resp.Status, string(bodyBytes))
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

	// Vérifier si la soumission a réussi selon la doc
	if status, ok := result["submission_id"].(string); !ok || status == "" {
		logEvent("Erreur de soumission Hybrid Analysis", map[string]interface{}{
			"file":     filePath,
			"response": result,
		})
		return "", fmt.Errorf("erreur de soumission Hybrid Analysis: réponse invalide")
	}

	// Récupérer l'ID du job de l'analyse
	jobID, ok := result["job_id"].(string)
	if !ok {
		logEvent("Erreur lors de la récupération de l'ID de l'analyse", map[string]interface{}{
			"file":     filePath,
			"response": result,
		})
		return "", fmt.Errorf("erreur lors de la récupération de l'ID de l'analyse")
	}

	// Attendre que l'analyse soit terminée avec sondage
	maxRetries := 15
	for i := 0; i < maxRetries; i++ {
		time.Sleep(5 * time.Second) // Attendre 5 secondes entre chaque tentative

		// URL pour vérifier le statut de l'analyse selon la doc
		statusURL := fmt.Sprintf("https://www.hybrid-analysis.com/api/v2/report/%s/state", jobID)
		req, err = http.NewRequest("GET", statusURL, nil)
		if err != nil {
			logEvent("Erreur lors de la création de la requête de statut", map[string]interface{}{
				"file":  filePath,
				"error": err.Error(),
			})
			return "", fmt.Errorf("erreur lors de la création de la requête de statut: %v", err)
		}

		req.Header.Set("api-key", HybridAnalysisAPIKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Falcon Sandbox")

		resp, err = client.Do(req)
		if err != nil {
			logEvent("Erreur lors de l'envoi de la requête de statut", map[string]interface{}{
				"file":  filePath,
				"error": err.Error(),
			})
			return "", fmt.Errorf("erreur lors de l'envoi de la requête de statut: %v", err)
		}

		var statusResult map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&statusResult); err != nil {
			resp.Body.Close()
			logEvent("Erreur lors de la lecture du statut", map[string]interface{}{
				"file":  filePath,
				"error": err.Error(),
			})
			continue
		}
		resp.Body.Close()

		// Vérifier si l'analyse est terminée selon la doc
		state, ok := statusResult["state"].(string)
		if !ok {
			continue
		}

		if state == "SUCCESS" {
			// L'analyse est terminée, récupérer le rapport
			summaryURL := fmt.Sprintf("https://www.hybrid-analysis.com/api/v2/report/%s/summary", jobID)
			req, err = http.NewRequest("GET", summaryURL, nil)
			if err != nil {
				logEvent("Erreur lors de la création de la requête de résumé", map[string]interface{}{
					"file":  filePath,
					"error": err.Error(),
				})
				return "", fmt.Errorf("erreur lors de la création de la requête de résumé: %v", err)
			}

			req.Header.Set("api-key", HybridAnalysisAPIKey)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("User-Agent", "Falcon Sandbox")

			resp, err = client.Do(req)
			if err != nil {
				logEvent("Erreur lors de l'envoi de la requête de résumé", map[string]interface{}{
					"file":  filePath,
					"error": err.Error(),
				})
				return "", fmt.Errorf("erreur lors de l'envoi de la requête de résumé: %v", err)
			}
			defer resp.Body.Close()

			var summaryResult map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&summaryResult); err != nil {
				logEvent("Erreur lors de la lecture du résumé", map[string]interface{}{
					"file":  filePath,
					"error": err.Error(),
				})
				return "", fmt.Errorf("erreur lors de la lecture du résumé: %v", err)
			}

			// Vérifier le verdict selon la doc
			verdict, ok := summaryResult["verdict"].(string)
			if !ok {
				logEvent("Erreur lors de la récupération du verdict", map[string]interface{}{
					"file":     filePath,
					"response": summaryResult,
				})
				return "", fmt.Errorf("erreur lors de la récupération du verdict")
			}

			// Vérifier le résultat selon la doc Hybrid Analysis
			if verdict == "malicious" || verdict == "suspicious" {
				logEvent("Fichier infecté détecté par Hybrid Analysis", map[string]interface{}{
					"file":    filePath,
					"result":  "infected",
					"verdict": verdict,
				})
				return "infected", nil
			} else {
				logEvent("Fichier analysé avec Hybrid Analysis", map[string]interface{}{
					"file":    filePath,
					"result":  "clean",
					"verdict": verdict,
				})
				return "clean", nil
			}
		} else if state == "ERROR" || state == "FAILED" {
			logEvent("Échec de l'analyse Hybrid Analysis", map[string]interface{}{
				"file":  filePath,
				"state": state,
			})
			return "", fmt.Errorf("échec de l'analyse Hybrid Analysis: %s", state)
		}
		// Si le statut est PENDING ou IN_PROGRESS, continuer à attendre
	}

	// Si on arrive ici, c'est que l'analyse n'a pas terminé dans le temps imparti
	logEvent("Délai d'attente dépassé pour l'analyse Hybrid Analysis", map[string]interface{}{
		"file": filePath,
	})

	return "", fmt.Errorf("délai d'attente dépassé pour l'analyse Hybrid Analysis")
}
