// Fonction pour récupérer les analyses récentes depuis le backend
function fetchRecentScans() {
    fetch('/api/recent-scans')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.getElementById('recent-scans');
            
            // Si le tableau est vide, afficher un message
            if (data.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="6" class="text-center">Aucune analyse récente</td></tr>';
                return;
            }
            
            tableBody.innerHTML = ''; // Vider le tableau avant d'ajouter de nouvelles données

            data.forEach(scan => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${scan.file_name}</td>
                    <td>${scan.date}</td>
                    <td>${scan.clamav_result}</td>
                    <td>${scan.virustotal_result}</td>
                    <td><span class="status-badge ${scan.status.toLowerCase() === 'clean' ? 'status-clean' : 'status-infected'}">${scan.status}</span></td>
                    <td><a href="#" class="view-details" data-id="${scan.id}"><i class="fas fa-eye"></i></a></td>
                `;
                tableBody.appendChild(row);
            });
        })
        .catch(error => {
            console.error('Erreur lors de la récupération des analyses récentes:', error);
            // En cas d'erreur, afficher un message
            const tableBody = document.getElementById('recent-scans');
            tableBody.innerHTML = '<tr><td colspan="6" class="text-center">Erreur lors du chargement des analyses</td></tr>';
        });
}

// Fonction pour récupérer les statistiques depuis le backend
function fetchStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            // Mettre à jour les cartes de statistiques
            document.getElementById('files-scanned').textContent = data.files_scanned;
            document.getElementById('threats-detected').textContent = data.threats_detected;
            document.getElementById('watched-folders').textContent = data.watched_folders;
            document.getElementById('protection-rate').textContent = `${data.protection_rate}%`;
        })
        .catch(error => {
            console.error('Erreur lors de la récupération des statistiques:', error);
            // En cas d'erreur, maintenir les valeurs à 0
            document.getElementById('files-scanned').textContent = '0';
            document.getElementById('threats-detected').textContent = '0';
            document.getElementById('watched-folders').textContent = '0';
            document.getElementById('protection-rate').textContent = '0%';
        });
}

// Fonction pour activer/désactiver le dark mode
function toggleDarkMode() {
    const body = document.body;
    const themeToggle = document.getElementById("theme-toggle");

    // Basculer entre les thèmes
    if (body.getAttribute("data-theme") === "dark") {
        body.setAttribute("data-theme", "light");
        localStorage.setItem("theme", "light");
        themeToggle.querySelector(".toggle-ball").style.transform = "translateX(0)";
    } else {
        body.setAttribute("data-theme", "dark");
        localStorage.setItem("theme", "dark");
        themeToggle.querySelector(".toggle-ball").style.transform = "translateX(30px)";
    }
}

// Initialiser le thème au chargement de la page
function initializeTheme() {
    const body = document.body;
    const themeToggle = document.getElementById("theme-toggle");
    const savedTheme = localStorage.getItem("theme");

    // Appliquer le thème sauvegardé ou le thème par défaut (light)
    if (savedTheme === "dark") {
        body.setAttribute("data-theme", "dark");
        themeToggle.querySelector(".toggle-ball").style.transform = "translateX(30px)";
    } else {
        body.setAttribute("data-theme", "light");
        themeToggle.querySelector(".toggle-ball").style.transform = "translateX(0)";
    }
}

// Initialisation du dashboard
document.addEventListener('DOMContentLoaded', function() {
    const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
    const currentDate = new Date().toLocaleDateString('fr-FR', options);
    document.getElementById('current-date').textContent = currentDate;

    // Récupérer les données en temps réel depuis le backend
    fetchRecentScans();
    fetchStats();

    // Initialiser le thème
    initializeTheme();

    // Ajouter un écouteur d'événement pour le bouton de bascule de thème
    const themeToggle = document.getElementById("theme-toggle");
    themeToggle.addEventListener("click", toggleDarkMode);
});

// Gestion de l'upload de fichiers
document.addEventListener("DOMContentLoaded", function () {
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-input");
    const uploadButton = document.getElementById("upload-button");

    // Gérer le clic sur le bouton "Choisir un fichier"
    uploadButton.addEventListener("click", function () {
        fileInput.click(); // Déclencher le sélecteur de fichiers
    });

    // Gérer la sélection de fichiers
    fileInput.addEventListener("change", function (e) {
        const file = e.target.files[0];
        if (file) {
            uploadFile(file);
        }
    });

    // Gérer le glisser-déposer
    dropzone.addEventListener("dragover", function (e) {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", function () {
        dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", function (e) {
        e.preventDefault();
        dropzone.classList.remove("dragover");

        const file = e.dataTransfer.files[0];
        if (file) {
            uploadFile(file);
        }
    });

    // Fonction pour envoyer le fichier au backend
    function uploadFile(file) {
        const formData = new FormData();
        formData.append("file", file);

        fetch("/upload", {
            method: "POST",
            body: formData,
        })
            .then((response) => response.json())
            .then((data) => {
                if (data.error) {
                    alert("Erreur : " + data.error);
                } else {
                    alert("Fichier analysé : " + data.result);
                    // Actualiser la page ou afficher les résultats
                    window.location.reload(); // Par exemple, recharger la page
                }
            })
            .catch((error) => {
                console.error("Erreur lors de l'upload :", error);
                alert("Une erreur s'est produite lors de l'upload.");
            });
    }
});