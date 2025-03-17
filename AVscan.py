import os
import time
import shutil
import subprocess
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Dossier à surveiller
WATCHED_FOLDER = "/home/paph/Documents/scans"
QUARANTINE_FOLDER = "/home/paph/Documents/quarantaine"

# Webhook Discord
WEBHOOK_URL = "https://discord.com/api/webhooks/1351146832650305628/sqdAh6ZgA4TR-68aaWI5IVBt_ckpUYwb7rI3pF7O6GQxasHKMzl51yiYCw7wsdwWLQmt"

# Création des dossiers si inexistants
os.makedirs(WATCHED_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

def send_discord_alert(filepath):
    """Envoie une alerte via un webhook Discord."""
    message = {
        "content": f"⚠️ **Fichier infecté détecté** ⚠️\n\n**Fichier:** `{filepath}`\n**Action:** Déplacé en quarantaine."
    }
    response = requests.post(WEBHOOK_URL, json=message)
    if response.status_code == 204:
        print("[+] Alerte envoyée avec succès sur Discord.")
    else:
        print(f"[-] Échec de l'envoi de l'alerte sur Discord. Code de statut : {response.status_code}")

class ScanHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        
        filepath = event.src_path
        print(f"[+] Nouveau fichier détecté : {filepath}")
        
        # Scan avec ClamAV
        result = subprocess.run(["clamscan", "--move", QUARANTINE_FOLDER, filepath], capture_output=True, text=True)
        
        if "Infected files: 1" in result.stdout:
            print(f"[!] Fichier infecté détecté et déplacé en quarantaine: {filepath}")
            send_discord_alert(filepath)  # Envoyer une alerte Discord
        else:
            print(f"[-] Fichier sain : {filepath}")

if __name__ == "__main__":
    event_handler = ScanHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCHED_FOLDER, recursive=False)
    observer.start()
    print(f"[+] Surveillance du dossier : {WATCHED_FOLDER}")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()