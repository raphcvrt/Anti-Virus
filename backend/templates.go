package main

import (
	"html/template"
	"net/http"
	"path/filepath"
)

// Structure pour les données partagées entre tous les templates
type TemplateData struct {
	Title           string
	ActivePage      string
	Stats           Stats
	RecentScans     []ScanResult
	WatchedFolders  []WatchedFolder
	QuarantineFiles []QuarantineFile
	FlashMessage    string
}

// Fonction pour charger et parser tous les templates
func loadTemplates(templatesDir string) (*template.Template, error) {
	// Créer un nouveau template
	tmpl := template.New("")

	// Fonctions personnalisées pour les templates
	tmpl = tmpl.Funcs(template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
	})

	// Charger tous les fichiers de templates
	pattern := filepath.Join(templatesDir, "*.html")
	_, err := tmpl.ParseGlob(pattern)
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}

// Fonction pour rendre un template avec les données
func renderTemplate(w http.ResponseWriter, tmpl *template.Template, templateName string, data TemplateData) {
	err := tmpl.ExecuteTemplate(w, templateName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		logEvent("Erreur lors du rendu du template", map[string]interface{}{
			"template": templateName,
			"error":    err.Error(),
		})
	}
}
