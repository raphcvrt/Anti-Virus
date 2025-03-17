import os
import time
import subprocess
import requests
import json
import threading
from flask import Flask, jsonify, request
from flask_cors import CORS
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
WEBHOOK_URL = "https://discord.com/api/webhooks/1351146832650305628/sqdAh6ZgA4TR-68aaWI5IVBt_ckpUYwb7rI3pF7O6GQxasHKMzl51yiYCw7wsdwWLQmt"
QUARANTINE_USER = "AVsecure"
SCAN_HISTORY = []
CURRENT_WATCHED_FOLDER = ""
OBSERVER = None
QUARANTINE_FOLDER = ""
OBSERVER_RUNNING = False

# Fonction pour créer un nouvel utilisateur et son dossier de quarantaine
def setup_quarantine_folder():
    """Crée un nouvel utilisateur et son dossier de quarantaine."""
    try:
        # Vérifie si l'utilisateur existe déjà
        subprocess.run(["id", QUARANTINE_USER], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        # Crée l'utilisateur s'il n'existe pas
        print(f"[+] Création de l'utilisateur {QUARANTINE_USER}...")
        try:
            subprocess.run(["sudo", "useradd", "-m", QUARANTINE_USER], check=True)
        except subprocess.CalledProcessError:
            print(f"[-] Échec de la création de l'utilisateur {QUARANTINE_USER}. Utilisation du dossier temporaire.")
            quarantine_folder = os.path.join("/tmp", "quarantaine")
            os.makedirs(quarantine_folder, exist_ok=True)
            return quarantine_folder

    # Crée le dossier de quarantaine dans le répertoire personnel de l'utilisateur
    quarantine_folder = os.path.join(f"/home/{QUARANTINE_USER}", "quarantaine")
    os.makedirs(quarantine_folder, exist_ok=True)
    print(f"[+] Dossier de quarantaine : {quarantine_folder}")
    return quarantine_folder

# Fonction pour envoyer une alerte Discord
def send_discord_alert(message):
    """Envoie une alerte via un webhook Discord."""
    payload = {"content": message}
    try:
        response = requests.post(WEBHOOK_URL, json=payload)
        if response.status_code == 204:
            print("[+] Alerte envoyée avec succès sur Discord.")
            return True
        else:
            print(f"[-] Échec de l'envoi de l'alerte sur Discord. Code de statut : {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Erreur lors de l'envoi de l'alerte Discord: {str(e)}")
        return False

# Fonction pour analyser un fichier avec ClamAV
def scan_with_clamav(filepath, quarantine_folder):
    """Analyse un fichier avec ClamAV."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    scan_result = {
        "timestamp": timestamp,
        "filepath": filepath,
        "status": "clean",
        "action": "none"
    }
    
    try:
        result = subprocess.run(["clamscan", "--move", quarantine_folder, filepath], 
                               capture_output=True, text=True)
        
        if "Infected files: 1" in result.stdout:
            scan_result["status"] = "infected"
            scan_result["action"] = "quarantined"
            print(f"[!] Fichier infecté détecté et déplacé en quarantaine : {filepath}")
            send_discord_alert(f"⚠️ **Fichier infecté détecté** ⚠️\n\n**Fichier:** `{filepath}`\n**Action:** Déplacé en quarantaine.")
        else:
            print(f"[-] Fichier sain : {filepath}")
    except Exception as e:
        scan_result["status"] = "error"
        scan_result["action"] = "none"
        scan_result["error"] = str(e)
        print(f"[-] Erreur lors de l'analyse du fichier {filepath}: {str(e)}")
    
    SCAN_HISTORY.append(scan_result)
    return scan_result

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

# API Routes
@app.route('/api/status', methods=['GET'])
def get_status():
    global OBSERVER_RUNNING, CURRENT_WATCHED_FOLDER
    return jsonify({
        "status": "running" if OBSERVER_RUNNING else "stopped",
        "watched_folder": CURRENT_WATCHED_FOLDER,
        "quarantine_folder": QUARANTINE_FOLDER
    })

@app.route('/api/scan-history', methods=['GET'])
def get_scan_history():
    return jsonify(SCAN_HISTORY)

@app.route('/api/start-monitoring', methods=['POST'])
def start_monitoring():
    global OBSERVER, OBSERVER_RUNNING, CURRENT_WATCHED_FOLDER
    
    data = request.json
    folder_path = data.get('folder_path', '')
    
    if not os.path.isdir(folder_path):
        return jsonify({"success": False, "message": f"Le dossier '{folder_path}' n'existe pas."}), 400
    
    if OBSERVER_RUNNING:
        stop_monitoring()
    
    CURRENT_WATCHED_FOLDER = folder_path
    event_handler = ScanHandler(QUARANTINE_FOLDER)
    OBSERVER = Observer()
    OBSERVER.schedule(event_handler, folder_path, recursive=False)
    OBSERVER.start()
    OBSERVER_RUNNING = True
    
    print(f"[+] Surveillance du dossier : {folder_path}")
    return jsonify({"success": True, "message": f"Surveillance du dossier '{folder_path}' démarrée."})

@app.route('/api/stop-monitoring', methods=['POST'])
def stop_monitoring():
    global OBSERVER, OBSERVER_RUNNING
    
    if OBSERVER and OBSERVER_RUNNING:
        OBSERVER.stop()
        OBSERVER.join()
        OBSERVER_RUNNING = False
        print("[+] Surveillance arrêtée.")
        return jsonify({"success": True, "message": "Surveillance arrêtée."})
    else:
        return jsonify({"success": False, "message": "Aucune surveillance en cours."})

@app.route('/api/scan-file', methods=['POST'])
def scan_file():
    data = request.json
    file_path = data.get('file_path', '')
    
    if not os.path.isfile(file_path):
        return jsonify({"success": False, "message": f"Le fichier '{file_path}' n'existe pas."}), 400
    
    result = scan_with_clamav(file_path, QUARANTINE_FOLDER)
    return jsonify({"success": True, "result": result})

@app.route('/api/quarantine-items', methods=['GET'])
def get_quarantine_items():
    global QUARANTINE_FOLDER
    items = []
    
    try:
        for item in os.listdir(QUARANTINE_FOLDER):
            full_path = os.path.join(QUARANTINE_FOLDER, item)
            items.append({
                "name": item,
                "size": os.path.getsize(full_path),
                "quarantined_date": time.ctime(os.path.getctime(full_path))
            })
    except Exception as e:
        print(f"[-] Erreur lors de la récupération des éléments en quarantaine: {str(e)}")
    
    return jsonify(items)

if __name__ == "__main__":
    # Configuration initiale
    QUARANTINE_FOLDER = setup_quarantine_folder()
    
    # Démarrer le serveur Flask
    print("[+] Starting server on http://localhost:8080")
    app.run(host='localhost', port=8080, debug=True)