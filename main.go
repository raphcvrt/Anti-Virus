package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/cors"
)

// Configuration
const (
	WEBHOOK_URL     = "https://discord.com/api/webhooks/1351146832650305628/sqdAh6ZgA4TR-68aaWI5IVBt_ckpUYwb7rI3pF7O6GQxasHKMzl51yiYCw7wsdwWLQmt"
	QUARANTINE_USER = "AVsecure"
	PORT            = "8080"
)

// Global variables
var (
	scanHistory      []ScanResult
	quarantineFolder string
	watchedFolder    string
	watcher          *fsnotify.Watcher
	watcherRunning   bool
	mutex            sync.Mutex
)

// Data structures
type ScanResult struct {
	Timestamp string `json:"timestamp"`
	Filepath  string `json:"filepath"`
	Status    string `json:"status"`
	Action    string `json:"action"`
	Error     string `json:"error,omitempty"`
}

type QuarantineItem struct {
	Name            string `json:"name"`
	Size            int64  `json:"size"`
	QuarantinedDate string `json:"quarantined_date"`
}

type StatusResponse struct {
	Status           string `json:"status"`
	WatchedFolder    string `json:"watched_folder"`
	QuarantineFolder string `json:"quarantine_folder"`
}

type FolderRequest struct {
	FolderPath string `json:"folder_path"`
}

type FileRequest struct {
	FilePath string `json:"file_path"`
}

type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Result  interface{} `json:"result,omitempty"`
}

// Setup quarantine folder
func setupQuarantineFolder() string {
	// Try to check if user exists
	_, err := exec.Command("id", QUARANTINE_USER).Output()
	if err != nil {
		// Try to create user - this might require sudo privileges
		fmt.Printf("[+] Création de l'utilisateur %s...\n", QUARANTINE_USER)
		createUserCmd := exec.Command("sudo", "useradd", "-m", QUARANTINE_USER)
		err = createUserCmd.Run()
		if err != nil {
			fmt.Printf("[-] Échec de la création de l'utilisateur %s. Utilisation du dossier temporaire.\n", QUARANTINE_USER)
			quarantineFolder := filepath.Join(os.TempDir(), "quarantaine")
			os.MkdirAll(quarantineFolder, 0755)
			return quarantineFolder
		}
	}

	// Create quarantine folder in user's home directory
	quarantineFolder := filepath.Join("/home", QUARANTINE_USER, "quarantaine")
	os.MkdirAll(quarantineFolder, 0755)
	fmt.Printf("[+] Dossier de quarantaine : %s\n", quarantineFolder)
	return quarantineFolder
}

// Send Discord alert
func sendDiscordAlert(message string) bool {
	payload := map[string]string{"content": message}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[-] Erreur lors de la création du payload JSON: %v\n", err)
		return false
	}

	resp, err := http.Post(WEBHOOK_URL, "application/json", strings.NewReader(string(jsonPayload)))
	if err != nil {
		fmt.Printf("[-] Erreur lors de l'envoi de l'alerte Discord: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		fmt.Println("[+] Alerte envoyée avec succès sur Discord.")
		return true
	} else {
		fmt.Printf("[-] Échec de l'envoi de l'alerte sur Discord. Code de statut : %d\n", resp.StatusCode)
		return false
	}
}

// Scan file with ClamAV
func scanWithClamAV(filepath string, quarantineFolder string) ScanResult {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	result := ScanResult{
		Timestamp: timestamp,
		Filepath:  filepath,
		Status:    "clean",
		Action:    "none",
	}

	// Execute ClamAV command
	cmd := exec.Command("clamscan", "--move", quarantineFolder, filepath)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Check if it's infected or a real error
		if strings.Contains(string(output), "Infected files: 1") {
			result.Status = "infected"
			result.Action = "quarantined"
			fmt.Printf("[!] Fichier infecté détecté et déplacé en quarantaine : %s\n", filepath)
			sendDiscordAlert(fmt.Sprintf("⚠️ **Fichier infecté détecté** ⚠️\n\n**Fichier:** `%s`\n**Action:** Déplacé en quarantaine.", filepath))
		} else {
			result.Status = "error"
			result.Error = err.Error()
			fmt.Printf("[-] Erreur lors de l'analyse du fichier %s: %v\n", filepath, err)
		}
	} else {
		fmt.Printf("[-] Fichier sain : %s\n", filepath)
	}

	// Add to scan history
	mutex.Lock()
	scanHistory = append(scanHistory, result)
	mutex.Unlock()

	return result
}

// Start watching a folder
func startWatching(folderPath string) error {
	// Stop any existing watcher
	if watcher != nil && watcherRunning {
		stopWatching()
	}

	// Create new watcher
	var err error
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// Start watching goroutine
	watcherRunning = true
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Create == fsnotify.Create {
					// Only process files, not directories
					fileInfo, err := os.Stat(event.Name)
					if err == nil && !fileInfo.IsDir() {
						fmt.Printf("[+] Nouveau fichier détecté : %s\n", event.Name)
						scanWithClamAV(event.Name, quarantineFolder)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("[-] Erreur du watcher: %v\n", err)
			}
		}
	}()

	// Add directory to watcher
	err = watcher.Add(folderPath)
	if err != nil {
		watcherRunning = false
		return err
	}

	watchedFolder = folderPath
	fmt.Printf("[+] Surveillance du dossier : %s\n", folderPath)
	return nil
}

// Stop watching
func stopWatching() {
	if watcher != nil {
		watcher.Close()
		watcherRunning = false
		fmt.Println("[+] Surveillance arrêtée.")
	}
}

// API handlers
func statusHandler(w http.ResponseWriter, r *http.Request) {
	status := "stopped"
	if watcherRunning {
		status = "running"
	}

	response := StatusResponse{
		Status:           status,
		WatchedFolder:    watchedFolder,
		QuarantineFolder: quarantineFolder,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func scanHistoryHandler(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scanHistory)
}

func startMonitoringHandler(w http.ResponseWriter, r *http.Request) {
	var req FolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if folder exists
	if _, err := os.Stat(req.FolderPath); os.IsNotExist(err) {
		response := ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Le dossier '%s' n'existe pas.", req.FolderPath),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Start monitoring
	if err := startWatching(req.FolderPath); err != nil {
		response := ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Erreur lors du démarrage de la surveillance: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Surveillance du dossier '%s' démarrée.", req.FolderPath),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func stopMonitoringHandler(w http.ResponseWriter, r *http.Request) {
	if !watcherRunning {
		response := ApiResponse{
			Success: false,
			Message: "Aucune surveillance en cours.",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	stopWatching()

	response := ApiResponse{
		Success: true,
		Message: "Surveillance arrêtée.",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func scanFileHandler(w http.ResponseWriter, r *http.Request) {
	var req FileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if file exists
	if _, err := os.Stat(req.FilePath); os.IsNotExist(err) {
		response := ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Le fichier '%s' n'existe pas.", req.FilePath),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Scan the file
	result := scanWithClamAV(req.FilePath, quarantineFolder)

	response := ApiResponse{
		Success: true,
		Result:  result,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func quarantineItemsHandler(w http.ResponseWriter, r *http.Request) {
	var items []QuarantineItem

	// Read quarantine directory
	files, err := os.ReadDir(quarantineFolder)
	if err == nil {
		for _, file := range files {
			info, err := file.Info()
			if err != nil {
				continue
			}

			items = append(items, QuarantineItem{
				Name:            file.Name(),
				Size:            info.Size(),
				QuarantinedDate: info.ModTime().Format("2006-01-02 15:04:05"),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func main() {
	// Setup quarantine folder
	quarantineFolder = setupQuarantineFolder()

	// Create router
	router := mux.NewRouter()

	// API routes
	router.HandleFunc("/api/status", statusHandler).Methods("GET")
	router.HandleFunc("/api/scan-history", scanHistoryHandler).Methods("GET")
	router.HandleFunc("/api/start-monitoring", startMonitoringHandler).Methods("POST")
	router.HandleFunc("/api/stop-monitoring", stopMonitoringHandler).Methods("POST")
	router.HandleFunc("/api/scan-file", scanFileHandler).Methods("POST")
	router.HandleFunc("/api/quarantine-items", quarantineItemsHandler).Methods("GET")

	// Apply CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
	})
	handler := c.Handler(router)

	// Start server
	fmt.Printf("[+] Starting server on http://localhost:%s\n", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, handler))
}
