function checkPasswordStrength() {
    var strengthBar = document.getElementById('password-strength');
    var strengthText = document.getElementById('strength-text');
    var password = document.getElementById('password').value;
    var strength = 0;

    if (password.match(/[a-z]+/)) {
        strength += 1;
    }
    if (password.match(/[A-Z]+/)) {
        strength += 1;
    }
    if (password.match(/[0-9]+/)) {
        strength += 1;
    }
    if (password.match(/[$@#&!]+/)) {
        strength += 1;
    }

    switch (strength) {
        case 0:
            strengthText.innerHTML = '';
            strengthBar.style.width = '0%';
            strengthBar.style.backgroundColor = 'red';
            break;
        case 1:
            strengthText.innerHTML = 'Weak (Add numbers, uppercase letters, and special characters)';
            strengthBar.style.width = '25%';
            strengthBar.style.backgroundColor = 'red';
            break;
        case 2:
            strengthText.innerHTML = 'Medium (Add more characters and special characters)';
            strengthBar.style.width = '50%';
            strengthBar.style.backgroundColor = 'orange';
            break;
        case 3:
            strengthText.innerHTML = 'Strong (Add more characters)';
            strengthBar.style.width = '75%';
            strengthBar.style.backgroundColor = 'yellow';
            break;
        case 4:
            strengthText.innerHTML = 'Very Strong';
            strengthBar.style.width = '100%';
            strengthBar.style.backgroundColor = 'green';
            break;
    }
}




function generatePassword() {
    var chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+?><:{}[]';
    var passwordLength = 12;
    var password = '';

    for (var i = 0; i <= passwordLength; i++) {
        var randomNumber = Math.floor(Math.random() * chars.length);
        password += chars.substring(randomNumber, randomNumber +1);
    }

    document.getElementById('generated-password').value = password;
    document.getElementById('use-password-btn').style.display = 'inline-block'; 
}

function useGeneratedPassword() {
    var generatedPassword = document.getElementById('generated-password').value;
    document.getElementById('password').value = generatedPassword;
    alert('Remember to note down your generated password!');
    checkPasswordStrength(); 
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



function deletePassword(passwordId) {
    if (confirm('Are you sure you want to delete this password?')) {
        fetchWithToken(`/passwords/delete-password/${passwordId}`, { method: 'POST' })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to delete password');
                }
                return response.json(); 
            })
            .then(data => {
                if (data.success) {
                    alert('Password deleted successfully');
                    const passwordElement = document.getElementById(`password-${passwordId}`);
                    if (passwordElement) {
                        passwordElement.remove();
                    }
                } else {
                    throw new Error(data.error || 'Failed to delete password');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert(error.message);
            });
    }
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
            // If user unauthorized, this redirects to the login page
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

function importPasswords(event) {
    event.preventDefault();
    const fileInput = document.getElementById('importFile');
    if (!fileInput.files.length) {
        alert('Please select a file to import.');
        return;
    }
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);

    const importUrl = '/passwords/import-passwords';
    fetch(importUrl, {
        method: 'POST',
        body: formData,
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to import passwords');
        }
        return response.json();
    })
    .then(data => {
        if (data.success && Array.isArray(data.imported_passwords)) {
            alert('Passwords imported successfully');
            updatePasswordList(data.imported_passwords);
        } else {
            alert('Passwords imported, but no data returned');
        }
    })
    .catch(error => {
        console.error('Error importing passwords:', error);
        alert(error.message);
    });
}

function updatePasswordList(importedPasswords) {
    const passwordList = document.getElementById('passwordList').getElementsByTagName('tbody')[0];
    importedPasswords.forEach(password => {
        const row = document.createElement('tr');
        row.id = `password-${password.password_id}`;
        row.className = 'password-item';
        row.dataset.passwordId = password.password_id;
        row.innerHTML = `
            <td><input type="checkbox" class="password-checkbox" value="${password.password_id}"></td>
            <td>${password.website_name}</td>
            <td>${password.username}</td>
            <td>
                <div class="password-container">
                    <input type="password" class="password-value" readonly>
                    <i class="fas fa-eye password-toggle" onclick="togglePasswordVisibility('${password.password_id}', 'manage')"></i>
                </div>
            </td>
            <td>
                <a href="#" class="btn btn-info" onclick="navigateWithToken('/passwords/edit-password/${password.password_id}')">Edit</a>
                <button type="button" class="btn btn-warning" onclick="deletePassword('${password.password_id}')">Delete</button>
            </td>
        `;
        passwordList.appendChild(row);
    });
}






function submitEditPasswordForm(event, passwordId) {
    event.preventDefault();
    var formData = new FormData(document.getElementById('editPasswordForm'));
    var data = Object.fromEntries(formData.entries());

    fetchWithToken(`/passwords/edit-password/${passwordId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
        .then(response => {
            if (response.ok) {
                alert('Password updated successfully');
                window.location.href = '/passwords/manage-passwords';
            } else {
                throw new Error('Failed to update password');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert(error.message);
        });
}

function submitAddPasswordForm(event) {
    event.preventDefault();
    var formData = new FormData(document.getElementById('addPasswordForm'));
    var data = Object.fromEntries(formData.entries());

    fetchWithToken('/passwords/add-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.message || 'Failed to add password');
            });
        }
        return response.json();
    })
    .then(data => {
        if(data.success === true || data.message) {
            navigateWithToken('/passwords/manage-passwords');
        } else {
            throw new Error('Unexpected response received from the server');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error: ' + error.message);
    });
}


document.addEventListener('DOMContentLoaded', function () {
    var passwordFields = document.getElementsByClassName('password-value');
    for (var i = 0; i < passwordFields.length; i++) {
        var passwordId = passwordFields[i].closest('.password-item').getAttribute('data-password-id');
        passwordFields[i].value = window.decryptedPasswords[passwordId] || '••••••••';
    }
});