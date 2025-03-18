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
            // Mettre à jour les cartes de statistiques
            document.getElementById('files-scanned').textContent = data.filesScanned;
            document.getElementById('threats-detected').textContent = data.threatsDetected;
            document.getElementById('watched-folders').textContent = data.watchedFolders;
            document.getElementById('protection-rate').textContent = `${data.protectionRate}%`;
        })
        .catch(error => console.error('Erreur lors de la récupération des statistiques:', error));
}

// Initialisation du dashboard
document.addEventListener('DOMContentLoaded', function() {
    const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
    const currentDate = new Date().toLocaleDateString('fr-FR', options);
    document.getElementById('current-date').textContent = currentDate;

    // Récupérer les données en temps réel depuis le backend
    fetchRecentScans();
    fetchStats();
});