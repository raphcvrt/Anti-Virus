import os
import time
import subprocess
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
WEBHOOK_URL = "https://discord.com/api/webhooks/1351146832650305628/sqdAh6ZgA4TR-68aaWI5IVBt_ckpUYwb7rI3pF7O6GQxasHKMzl51yiYCw7wsdwWLQmt"
QUARANTINE_USER = "AVsecure"  # Nom de l'utilisateur pour le dossier de quarantaine

# Fonction pour créer un nouvel utilisateur et son dossier de quarantaine
def setup_quarantine_folder():
    """Crée un nouvel utilisateur et son dossier de quarantaine."""
    try:
        # Vérifie si l'utilisateur existe déjà
        subprocess.run(["id", QUARANTINE_USER], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        # Crée l'utilisateur s'il n'existe pas
        print(f"[+] Création de l'utilisateur {QUARANTINE_USER}...")
        subprocess.run(["sudo", "useradd", "-m", QUARANTINE_USER], check=True)

    # Crée le dossier de quarantaine dans le répertoire personnel de l'utilisateur
    quarantine_folder = os.path.join(f"/home/{QUARANTINE_USER}", "quarantaine")
    os.makedirs(quarantine_folder, exist_ok=True)
    print(f"[+] Dossier de quarantaine : {quarantine_folder}")
    return quarantine_folder

# Fonction pour choisir le dossier à surveiller
def choose_watched_folder():
    """Demande à l'utilisateur de choisir le dossier à surveiller."""
    while True:
        watched_folder = input("Entrez le chemin du dossier à surveiller : ").strip()
        if os.path.isdir(watched_folder):
            return watched_folder
        print(f"[-] Le dossier '{watched_folder}' n'existe pas. Veuillez réessayer.")

# Fonction pour envoyer une alerte Discord
def send_discord_alert(message):
    """Envoie une alerte via un webhook Discord."""
    payload = {"content": message}
    response = requests.post(WEBHOOK_URL, json=payload)
    if response.status_code == 204:
        print("[+] Alerte envoyée avec succès sur Discord.")
    else:
        print(f"[-] Échec de l'envoi de l'alerte sur Discord. Code de statut : {response.status_code}")

# Fonction pour analyser un fichier avec ClamAV
def scan_with_clamav(filepath, quarantine_folder):
    """Analyse un fichier avec ClamAV."""
    result = subprocess.run(["clamscan", "--move", quarantine_folder, filepath], capture_output=True, text=True)
    if "Infected files: 1" in result.stdout:
        print(f"[!] Fichier infecté détecté et déplacé en quarantaine : {filepath}")
        send_discord_alert(f"⚠️ **Fichier infecté détecté** ⚠️\n\n**Fichier:** `{filepath}`\n**Action:** Déplacé en quarantaine.")
    else:
        print(f"[-] Fichier sain : {filepath}")

# Gestionnaire d'événements pour Watchdog
class ScanHandler(FileSystemEventHandler):
    def __init__(self, quarantine_folder):
        self.quarantine_folder = quarantine_folder

    def on_created(self, event):
        if event.is_directory:
            return
        filepath = event.src_path
        print(f"[+] Nouveau fichier détecté : {filepath}")
        scan_with_clamav(filepath, self.quarantine_folder)

# Point d'entrée du script
if __name__ == "__main__":
    # Configuration initiale
    quarantine_folder = setup_quarantine_folder()
    watched_folder = choose_watched_folder()

    # Démarrer la surveillance
    event_handler = ScanHandler(quarantine_folder)
    observer = Observer()
    observer.schedule(event_handler, watched_folder, recursive=False)
    observer.start()
    print(f"[+] Surveillance du dossier : {watched_folder}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()