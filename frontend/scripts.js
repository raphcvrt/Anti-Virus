// Données dynamiques
let filesScanned = 0;
let threatsDetected = 0;
let watchedFolders = 0;
let protectionRate = 0;

// Fonction pour mettre à jour les cartes de statistiques
function updateStats() {
    document.getElementById('files-scanned').textContent = filesScanned;
    document.getElementById('threats-detected').textContent = threatsDetected;
    document.getElementById('watched-folders').textContent = watchedFolders;
    document.getElementById('protection-rate').textContent = `${protectionRate}%`;
}

// Fonction pour récupérer les analyses récentes depuis le backend
function fetchRecentScans() {
    fetch('/api/recent-scans')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.getElementById('recent-scans');
            tableBody.innerHTML = ''; // Vider le tableau avant d'ajouter de nouvelles données

            data.forEach(scan => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${scan.fileName}</td>
                    <td>${scan.date}</td>
                    <td>${scan.clamAVResult}</td>
                    <td>${scan.virusTotalResult}</td>
                    <td><span class="status-badge ${scan.status === 'Clean' ? 'status-clean' : 'status-infected'}">${scan.status}</span></td>
                    <td><a href="#" class="view-details" data-id="1"><i class="fas fa-eye"></i></a></td>
                `;
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Erreur lors de la récupération des analyses récentes:', error));
}

// Fonction pour récupérer les statistiques depuis le backend
function fetchStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            // Mettre à jour les variables globales
            filesScanned = data.filesScanned;
            threatsDetected = data.threatsDetected;
            watchedFolders = data.watchedFolders;
            protectionRate = data.protectionRate;

            // Mettre à jour les cartes de statistiques
            updateStats();
        })
        .catch(error => console.error('Erreur lors de la récupération des statistiques:', error));
}

// Fonction pour ajouter une analyse récente (exemple local)
function addRecentScan(fileName, date, clamAVResult, virusTotalResult, status) {
    const tableBody = document.getElementById('recent-scans');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${fileName}</td>
        <td>${date}</td>
        <td>${clamAVResult}</td>
        <td>${virusTotalResult}</td>
        <td><span class="status-badge ${status === 'Clean' ? 'status-clean' : 'status-infected'}">${status}</span></td>
        <td><a href="#" class="view-details" data-id="1"><i class="fas fa-eye"></i></a></td>
    `;
    tableBody.appendChild(row);
}

// Initialisation du dashboard
document.addEventListener('DOMContentLoaded', function() {
    const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
    const currentDate = new Date().toLocaleDateString('fr-FR', options);
    document.getElementById('current-date').textContent = currentDate;

    // Récupérer les données en temps réel depuis le backend
    fetchRecentScans();
    fetchStats();

    // Ajouter des analyses récentes (exemple local)
    addRecentScan('document.pdf', '18/03/2025 14:32', 'Clean', 'Clean', 'Clean');
    addRecentScan('setup.exe', '18/03/2025 13:15', 'Infected', 'Infected', 'Infected');

    // Initialiser le graphique (si vous en avez un)
    initChart();
});

// (Conserver les autres fonctions JavaScript du template)