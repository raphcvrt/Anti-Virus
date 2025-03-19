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
            document.getElementById('protection-rate').textContent = `${data.protection_rate}%`;
        })
        .catch(error => {
            console.error('Erreur lors de la récupération des statistiques:', error);
            // En cas d'erreur, maintenir les valeurs à 0
            document.getElementById('files-scanned').textContent = '0';
            document.getElementById('threats-detected').textContent = '0';
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

// Afficher l'indicateur de chargement
function showLoader() {
    const dropzone = document.getElementById("dropzone");
    
    // Sauvegarder le contenu original
    if (!dropzone.getAttribute('data-original-content')) {
        dropzone.setAttribute('data-original-content', dropzone.innerHTML);
    }
    
    // Afficher l'indicateur de chargement
    dropzone.innerHTML = `
        <div class="loading-animation">
            <i class="fas fa-shield-virus fa-spin"></i>
            <p>Analyse en cours...</p>
        </div>
    `;
}

// Masquer l'indicateur de chargement
function hideLoader() {
    const dropzone = document.getElementById("dropzone");
    const originalContent = dropzone.getAttribute('data-original-content');
    
    if (originalContent) {
        dropzone.innerHTML = originalContent;
    }
}

// Fonction pour envoyer le fichier au backend
function uploadFile(file) {
    // Vérifier si un fichier est déjà en cours d'analyse
    if (document.getElementById("dropzone").classList.contains("uploading")) {
        return;
    }
    
    const dropzone = document.getElementById("dropzone");
    dropzone.classList.add("uploading");
    
    showLoader();
    
    const formData = new FormData();
    formData.append("file", file);

    fetch("/upload", {
        method: "POST",
        body: formData,
    })
        .then((response) => response.json())
        .then((data) => {
            hideLoader();
            dropzone.classList.remove("uploading");
            
            if (data.error) {
                showToast("Erreur : " + data.error, "error");
            } else {
                showToast("Fichier analysé : " + data.result, "success");
                // Actualiser les données sans recharger la page
                fetchRecentScans();
                fetchStats();
            }
        })
        .catch((error) => {
            console.error("Erreur lors de l'upload :", error);
            hideLoader();
            dropzone.classList.remove("uploading");
        });
}

// Afficher une notification toast
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <div class="toast-content">
            <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
            <span>${message}</span>
        </div>
        <i class="fas fa-times toast-close"></i>
    `;
    
    container.appendChild(toast);
    
    // Animation d'entrée
    setTimeout(() => {
        toast.classList.add("toast-visible");
    }, 10);
    
    // Fermeture automatique après 5 secondes
    setTimeout(() => {
        toast.classList.remove("toast-visible");
        setTimeout(() => {
            container.removeChild(toast);
        }, 300);
    }, 5000);
    
    // Fermeture manuelle
    const closeBtn = toast.querySelector(".toast-close");
    closeBtn.addEventListener("click", () => {
        toast.classList.remove("toast-visible");
        setTimeout(() => {
            container.removeChild(toast);
        }, 300);
    });
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
    
    // Variable pour suivre si un upload est en cours
    let isUploading = false;

    // Gérer le clic sur le bouton "Choisir un fichier"
    if (uploadButton) {
        uploadButton.addEventListener("click", function (e) {
            e.preventDefault(); // Empêcher la soumission du formulaire
            e.stopPropagation(); // Empêcher la propagation du clic
            
            // Éviter les clics multiples
            if (isUploading) return;
            
            fileInput.click(); // Déclencher le sélecteur de fichiers
        });
    }

    // Gérer la sélection de fichiers
    if (fileInput) {
        fileInput.addEventListener("change", function (e) {
            const file = e.target.files[0];
            if (file && !isUploading) {
                isUploading = true;
                uploadFile(file);
                
                // Réinitialiser la valeur pour permettre de sélectionner le même fichier à nouveau
                fileInput.value = '';
                
                // Réinitialiser le drapeau après un délai
                setTimeout(() => {
                    isUploading = false;
                }, 500);
            }
        });
    }

    // Gérer le glisser-déposer
    if (dropzone) {
        // Empêcher le comportement par défaut du navigateur
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        // Mettre en évidence la zone de dépôt lors du survol
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, function() {
                if (!isUploading) {
                    dropzone.classList.add("dragover");
                }
            }, false);
        });

        // Supprimer la mise en évidence lors du départ
        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, function() {
                dropzone.classList.remove("dragover");
            }, false);
        });

        // Gérer le dépôt de fichiers
        dropzone.addEventListener("drop", function(e) {
            if (isUploading) return;
            
            const file = e.dataTransfer.files[0];
            if (file) {
                isUploading = true;
                uploadFile(file);
                
                // Réinitialiser le drapeau après un délai
                setTimeout(() => {
                    isUploading = false;
                }, 500);
            }
        }, false);
    }
});
document.addEventListener('DOMContentLoaded', function () {
    const uploadForm = document.querySelector('form'); // Sélectionnez votre formulaire d'upload
    const loader = document.getElementById('loader');
    const loadingText = document.getElementById('loading-text');

    if (uploadForm) {
        uploadForm.addEventListener('submit', function (e) {
            // Afficher l'indicateur de chargement
            loader.style.display = 'block';
            loadingText.style.display = 'block';

            // Optionnel : Désactiver le bouton d'upload pour éviter les soumissions multiples
            const submitButton = uploadForm.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
            }

            // Vous pouvez également ajouter un délai pour simuler une attente avant la redirection
            setTimeout(function () {
                loader.style.display = 'none';
                loadingText.style.display = 'none';
                if (submitButton) {
                    submitButton.disabled = false;
                }
            }, 5000); // Délai de 5 secondes (à ajuster selon vos besoins)
        });
    }
});
document.addEventListener('DOMContentLoaded', function () {
    const uploadForm = document.querySelector('form'); // Sélectionnez votre formulaire d'upload
    const loader = document.getElementById('loader');
    const loadingText = document.getElementById('loading-text');

    if (uploadForm) {
        uploadForm.addEventListener('submit', function (e) {
            e.preventDefault(); // Empêcher la soumission par défaut du formulaire

            // Afficher l'indicateur de chargement
            loader.style.display = 'block';
            loadingText.style.display = 'block';

            // Récupérer le fichier
            const formData = new FormData(uploadForm);

            // Envoyer le fichier via AJAX
            fetch('/upload', {
                method: 'POST',
                body: formData,
            })
            .then(response => response.json())
            .then(data => {
                // Masquer l'indicateur de chargement
                loader.style.display = 'none';
                loadingText.style.display = 'none';

                // Afficher le résultat
                alert(`Résultat de l'analyse : ${data.result}`);
            })
            .catch(error => {
                // Masquer l'indicateur de chargement en cas d'erreur
                loader.style.display = 'none';
                loadingText.style.display = 'none';

                console.error('Erreur lors de l\'upload:', error);
                alert('Une erreur est survenue lors de l\'analyse du fichier.');
            });
        });
    }
});