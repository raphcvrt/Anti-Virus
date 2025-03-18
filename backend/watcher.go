package main

import (
	"log"

	"github.com/fsnotify/fsnotify"
)

func watchFolder(folderPath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Create == fsnotify.Create {
					log.Println("Nouveau fichier détecté:", event.Name)
					// Analyser le fichier ici
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("Erreur du watcher:", err)
			}
		}
	}()

	err = watcher.Add(folderPath)
	if err != nil {
		log.Fatal(err)
	}
	<-done
}
