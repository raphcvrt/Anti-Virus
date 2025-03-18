package main

import (
	"fmt"
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

	// Ajouter des fonctions personnalisées
	tmpl = tmpl.Funcs(template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
	})

	// Charger le layout depuis le dossier templates
	layoutPath := filepath.Join(templatesDir, "layout.html")
	var err error
	tmpl, err = tmpl.ParseFiles(layoutPath)
	if err != nil {
		fmt.Println("Erreur lors du chargement de layout.html:", err)
		return nil, err
	}

	// Charger tous les templates de contenu
	contentTemplates := []string{
		filepath.Join(templatesDir, "index.html"),
		filepath.Join(templatesDir, "analyse.html"),
		filepath.Join(templatesDir, "surveillance.html"),
		filepath.Join(templatesDir, "historique.html"),
		filepath.Join(templatesDir, "quarantaine.html"),
		filepath.Join(templatesDir, "parametres.html"),
	}

	tmpl, err = tmpl.ParseFiles(contentTemplates...)
	if err != nil {
		fmt.Println("Erreur lors du chargement des templates de contenu:", err)
		return nil, err
	}

	// Afficher tous les templates chargés
	fmt.Println("📂 Templates chargés :")
	for _, t := range tmpl.Templates() {
		fmt.Println("   -", t.Name())
	}

	return tmpl, nil
}

// Fonction pour rendre un template avec les données
/*func renderTemplate(w http.ResponseWriter, tmpl *template.Template, templateName string, data TemplateData) {
	fmt.Println("Tentative de rendu du template:", templateName)

	// Le template racine devrait être layout.html, pas le template nommé
	renderErr := tmpl.ExecuteTemplate(w, "layout.html", data)
	if renderErr != nil {
		fmt.Println("Erreur lors du rendu du template:", renderErr)
		http.Error(w, "Erreur de template: "+renderErr.Error(), http.StatusInternalServerError)
	} else {
		fmt.Println("Template rendu avec succès")
	}
}*/
func renderTemplate(w http.ResponseWriter, tmpl *template.Template, templateName string, data TemplateData) {
	fmt.Println("Tentative de rendu du template:", templateName)

	renderErr := tmpl.ExecuteTemplate(w, "layout.html", data)
	if renderErr != nil {
		fmt.Println("Erreur lors du rendu du template:", renderErr)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Erreur de template: %s", renderErr.Error())
	} else {
		fmt.Println("Template rendu avec succès")
	}
}
