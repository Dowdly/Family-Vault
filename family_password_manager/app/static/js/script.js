function validatePassword(password) {
    if (password.length < 8) {
        alert('Password must be at least 8 characters long.');
        return false;
    }
    return true;
}


function handleFamilyVaultClick() {
    const isLoggedIn = localStorage.getItem('token') !== null; 
    if (isLoggedIn) {
        navigateWithToken('/passwords/manage-passwords');
    } else {
        navigateWithToken('/auth/login');
    }
}



function sortPasswords() {
    const sortValue = document.getElementById('sortSelect').value;
    const sortOrder = document.getElementById('sortOrder').value;
    let passwordList = document.getElementById('passwordList').querySelector('tbody');
    let passwords = Array.from(passwordList.getElementsByClassName('password-item'));

    passwords.sort((a, b) => {
        let aValue = a.dataset[sortValue] || ""; 
        let bValue = b.dataset[sortValue] || ""; 

        let result = 0;
        if (sortValue === 'date_added') {
            result = new Date(aValue) - new Date(bValue);
        } else {
            result = aValue.localeCompare(bValue);
        }
        // Reverses the result for descending order
        return sortOrder === 'desc' ? -result : result;
    });

    // Clear and repopulate the list
    passwordList.innerHTML = '';
    passwords.forEach(password => passwordList.appendChild(password));
}


function filterByCategory() {
    const selectedCategory = document.getElementById('categoryFilter').value;
    let passwords = document.getElementsByClassName('password-item');

    Array.from(passwords).forEach(password => {
        if (selectedCategory === 'all' || password.dataset.category === selectedCategory) {
            password.style.display = '';
        } else {
            password.style.display = 'none';
        }
    });
}



function deleteSelectedPasswords() {
    const selectedPasswords = document.querySelectorAll('.password-checkbox:checked');
    const passwordIds = Array.from(selectedPasswords).map(cb => cb.value);

    if (passwordIds.length === 0) {
        alert('No passwords selected.');
        return;
    }

    if (confirm('Are you sure you want to delete the selected passwords?')) {
        fetchWithToken('/passwords/delete-multiple', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ passwordIds })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to delete passwords');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                passwordIds.forEach(id => {
                    const row = document.getElementById(`password-${id}`);
                    if (row) row.remove();
                });
                alert('Selected passwords deleted successfully.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error deleting passwords: ' + error.message);
        });
    }
}







function fetchWithToken(url, options = {}) {
    const token = localStorage.getItem('token');
    
    if (token) {
        options.headers = options.headers || {};
        options.headers.Authorization = `Bearer ${token}`;
        console.log('Sending request to', url, 'with token:', token);
    } else {
        console.error('No token found. Please log in again.');
        return Promise.reject('No token found');
    }

    return fetch(url, options)
        .then(response => {
            console.log('Received response with status:', response.status, 'from', url);
            return response;
        })
        .catch(error => {
            console.error('Error during fetchWithToken for', url, ':', error);
            throw error;
        });
}

function navigateWithToken(url) {
    const token = localStorage.getItem('token');

    fetch(url, {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
    })
    .then(response => {
        if (response.ok) {
            response.text().then(html => {
                document.open();
                document.write(html);
                document.close();
            });
        } else if (response.status === 401) {
            window.location.href = '/auth/login';
        } else {
            throw new Error('Failed to navigate');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Navigation failed');
    });
}


function searchPasswords() {
    let searchValue = document.getElementById('searchInput').value.toLowerCase();
    let passwords = document.getElementsByClassName('password-item');

    Array.from(passwords).forEach(password => {
        let textValue = password.textContent || password.innerText;
        if (textValue.toLowerCase().indexOf(searchValue) > -1) {
            password.style.display = '';
        } else {
            password.style.display = 'none';
        }
    });
}

function updatePasswordStrengthIndicators() {
    let passwords = document.getElementsByClassName('password-item');
    Array.from(passwords).forEach(password => {
        let strengthIndicator = document.getElementById('strength-' + password.dataset.passwordId);
        let strength = calculatePasswordStrength(password.dataset.decryptedPassword);
        strengthIndicator.className = 'password-strength-indicator ' + strength;
    });
}

function calculatePasswordStrength(password) {
    let strength = 0;
    if (password.match(/[a-z]/)) strength++;
    if (password.match(/[A-Z]/)) strength++;
    if (password.match(/[0-9]/)) strength++;
    if (password.match(/[@$!%*?&]/)) strength++;
    // Returns a class name based on strength
    return ['weak', 'fair', 'good', 'strong'][strength];
}



function togglePasswordVisibility(passwordId, context) {
    let passwordField;
    let toggleIcon;

    if (context === 'manage') {
        passwordField = document.querySelector('#password-' + passwordId + ' .password-value');
        toggleIcon = document.querySelector('#password-' + passwordId + ' .password-toggle');

        // Check if the password is currently visible as text or hidden
        if (passwordField.type === 'text' && passwordField.value === decryptedPasswords[passwordId]) {
            // Hide the password
            passwordField.type = 'password';
            passwordField.value = '••••••••'; // Placeholder for hidden password
            if (toggleIcon) toggleIcon.classList.remove('fa-eye-slash');
            if (toggleIcon) toggleIcon.classList.add('fa-eye');
        } else {
            // Show the password
            passwordField.type = 'text';
            passwordField.value = decryptedPasswords[passwordId];
            if (toggleIcon) toggleIcon.classList.add('fa-eye-slash');
            if (toggleIcon) toggleIcon.classList.remove('fa-eye');
        }
    } else if (context === 'edit') {
        passwordField = document.getElementById('password');
        toggleIcon = document.querySelector('.password-toggle');

        if (passwordField.type === 'password') {
            passwordField.type = 'text';
            if (toggleIcon) toggleIcon.classList.add('fa-eye-slash');
            if (toggleIcon) toggleIcon.classList.remove('fa-eye');
        } else {
            passwordField.type = 'password';
            if (toggleIcon) toggleIcon.classList.remove('fa-eye-slash');
            if (toggleIcon) toggleIcon.classList.add('fa-eye');
        }
    }
}


// Function to apply high contrast mode
function applyHighContrastMode() {
    if (localStorage.getItem('highContrast') === 'true') {
        document.body.classList.add('high-contrast');
    }
}


function toggleHighContrastMode() {
    document.body.classList.toggle('high-contrast');
    localStorage.setItem('highContrast', document.body.classList.contains('high-contrast'));
}

// Function to handle checkbox click for multi-select
function handleCheckboxClick(e) {
    let inBetween = false;
    const checkboxes = document.querySelectorAll('.password-checkbox');

    if (e.shiftKey && lastChecked) {
        checkboxes.forEach(checkbox => {
            if (checkbox === e.target || checkbox === lastChecked) {
                inBetween = !inBetween;
            }

            if (inBetween) {
                checkbox.checked = e.target.checked;
            }
        });
    }

    lastChecked = e.target;
}

$(function () {
    $('[data-toggle="tooltip"]').tooltip();
});




document.addEventListener('DOMContentLoaded', function() {



    applyHighContrastMode();


    applyHighContrastMode();

    const highContrastToggle = document.getElementById('high-contrast-toggle');
    if (highContrastToggle) {
        highContrastToggle.addEventListener('click', toggleHighContrastMode);
    }


    let lastChecked; // Variable keeps track of the last checked checkbox

    function handleCheckboxClick(e) {
        let inBetween = false;
        const checkboxes = document.querySelectorAll('.password-checkbox');

        // This will check if the shift key is pressed and there is a last checked checkbox
        if (e.shiftKey && lastChecked) {
            checkboxes.forEach(checkbox => {
                // Check if the current checkbox is the clicked checkbox or the last checked checkbox
                if (checkbox === e.target || checkbox === lastChecked) {
                    inBetween = !inBetween;
                }

                // If inBetween is true, the current checkbox's checked state is set to match the clicked checkbox's state
                if (inBetween) {
                    checkbox.checked = e.target.checked;
                }
            });
        }

        lastChecked = e.target; // Update lastChecked to the currently clicked checkbox
    }

    document.querySelectorAll('.password-checkbox').forEach(checkbox => 
        checkbox.addEventListener('click', handleCheckboxClick));
    
    function handleFamilyVaultClick() {
        const isLoggedIn = localStorage.getItem('token') !== null; 
        if (isLoggedIn) {
            navigateWithToken('/passwords/manage-passwords');
        } else {
            navigateWithToken('/auth/login');
        }
    }


    document.getElementById('sortOrder').addEventListener('change', sortPasswords);
   
});
