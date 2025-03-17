// Global variables
let monitoringStatus = false;
let scanHistory = [];
let quarantineItems = [];
const API_URL = 'http://localhost:8080/api';

// DOM Elements
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tabs
    const tabElems = document.querySelectorAll('a[data-bs-toggle="tab"]');
    tabElems.forEach(el => {
        el.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            
            // Hide all tabs
            document.querySelectorAll('.tab-pane').forEach(tab => {
                tab.classList.remove('show', 'active');
            });
            
            // Remove active class from all nav links
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            
            // Show the selected tab
            document.getElementById(targetId).classList.add('show', 'active');
            
            // Add active class to clicked nav link
            this.classList.add('active');
        });
    });
    
    // Load initial data
    getStatus();
    getScanHistory();
    getQuarantineItems();
    
    // Set up refresh intervals
    setInterval(getStatus, 5000);
    setInterval(getScanHistory, 5000);
    setInterval(getQuarantineItems, 10000);
    
    // Add event listeners for buttons
    document.getElementById('start-monitoring').addEventListener('click', startMonitoring);
    document.getElementById('stop-monitoring').addEventListener('click', stopMonitoring);
    document.getElementById('scan-file').addEventListener('click', scanFile);
    document.getElementById('save-settings').addEventListener('click', saveSettings);
});

// Fetch current status
function getStatus() {
    fetch(`${API_URL}/status`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('monitor-status').textContent = data.status === 'running' ? 'Actif' : 'Inactif';
            document.getElementById('watched-folder').textContent = `Dossier surveillé: ${data.watched_folder || 'Aucun'}`;
            document.getElementById('status-badge').textContent = data.status === 'running' ? 'Actif' : 'Inactif';
            document.getElementById('status-badge').className = `badge rounded-pill float-end ${data.status === 'running' ? 'bg-success' : 'bg-danger'}`;
        })
        .catch(error => console.error('Erreur lors de la récupération du statut:', error));
}

// Fetch scan history
function getScanHistory() {
    fetch(`${API_URL}/scan-history`)
        .then(response => response.json())
        .then(data => {
            scanHistory = data;
            updateScanHistoryTable();
        })
        .catch(error => console.error('Erreur lors de la récupération de l\'historique des analyses:', error));
}

// Update scan history table
function updateScanHistoryTable() {
    const tbody = document.getElementById('scan-history-table-body');
    tbody.innerHTML = '';

    scanHistory.forEach(scan => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${scan.timestamp}</td>
            <td>${scan.filepath}</td>
            <td class="${scan.status === 'infected' ? 'status-infected' : scan.status === 'clean' ? 'status-clean' : 'status-error'}">${scan.status}</td>
            <td>${scan.action}</td>
        `;
        tbody.appendChild(row);
    });
}

// Fetch quarantine items
function getQuarantineItems() {
    fetch(`${API_URL}/quarantine-items`)
        .then(response => response.json())
        .then(data => {
            quarantineItems = data;
            updateQuarantineTable();
        })
        .catch(error => console.error('Erreur lors de la récupération des fichiers en quarantaine:', error));
}

// Update quarantine table
function updateQuarantineTable() {
    const tbody = document.getElementById('quarantine-table-body');
    tbody.innerHTML = '';

    quarantineItems.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${item.name}</td>
            <td>${(item.size / 1024).toFixed(2)} KB</td>
            <td>${item.quarantined_date}</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="deleteQuarantineItem('${item.name}')">Supprimer</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Start monitoring a folder
function startMonitoring() {
    const folderPath = document.getElementById('folder-path').value;
    if (!folderPath) {
        alert('Veuillez spécifier un dossier à surveiller.');
        return;
    }

    fetch(`${API_URL}/start-monitoring`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ folder_path: folderPath }),
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Surveillance démarrée avec succès.');
                getStatus();
            } else {
                alert(`Erreur: ${data.message}`);
            }
        })
        .catch(error => console.error('Erreur lors du démarrage de la surveillance:', error));
}

// Stop monitoring
function stopMonitoring() {
    fetch(`${API_URL}/stop-monitoring`, {
        method: 'POST',
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Surveillance arrêtée avec succès.');
                getStatus();
            } else {
                alert(`Erreur: ${data.message}`);
            }
        })
        .catch(error => console.error('Erreur lors de l\'arrêt de la surveillance:', error));
}

// Scan a specific file
function scanFile() {
    const filePath = document.getElementById('file-path').value;
    if (!filePath) {
        alert('Veuillez spécifier un fichier à analyser.');
        return;
    }

    fetch(`${API_URL}/scan-file`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ file_path: filePath }),
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const result = data.result;
                const scanResultDiv = document.getElementById('scan-result');
                scanResultDiv.innerHTML = `
                    <div class="alert ${result.status === 'infected' ? 'alert-danger' : result.status === 'clean' ? 'alert-success' : 'alert-warning'}">
                        <strong>Résultat de l'analyse:</strong> ${result.status}<br>
                        <strong>Action:</strong> ${result.action}<br>
                        ${result.error ? `<strong>Erreur:</strong> ${result.error}` : ''}
                    </div>
                `;
                getScanHistory();
            } else {
                alert(`Erreur: ${data.message}`);
            }
        })
        .catch(error => console.error('Erreur lors de l\'analyse du fichier:', error));
}

// Save settings
function saveSettings() {
    const discordNotifications = document.getElementById('discord-notifications').checked;
    const webhookUrl = document.getElementById('webhook-url').value;

    // Here you would typically send these settings to the backend to save them
    // For now, we'll just display a success message
    alert('Paramètres enregistrés avec succès.');
}

// Delete a quarantine item
function deleteQuarantineItem(itemName) {
    if (confirm(`Êtes-vous sûr de vouloir supprimer ${itemName} de la quarantaine ?`)) {
        // Here you would typically send a request to the backend to delete the item
        // For now, we'll just remove it from the frontend list
        quarantineItems = quarantineItems.filter(item => item.name !== itemName);
        updateQuarantineTable();
        alert(`${itemName} a été supprimé de la quarantaine.`);
    }
}