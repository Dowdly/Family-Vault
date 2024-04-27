window.onerror = function (msg, url, lineNo, columnNo, error) {
    console.error(`Error occurred: ${msg} at ${url}:${lineNo}:${columnNo}`);
    console.error('Error object:', error);
    return false; 
}; 
document.addEventListener('DOMContentLoaded', function () {
    console.log("DOMContentLoaded - popup.js loaded");
    const loginForm = document.getElementById('loginForm');
    const savePasswordButton = document.getElementById('savePassword');
    const loginButton = document.getElementById('loginButton');
    const passwordGenerator = document.getElementById('passwordGenerator');
    const generateButton = document.getElementById('generateButton');
    const copyButton = document.getElementById('copyButton');
    const generatedPassword = document.getElementById('generatedPassword');
    const passwordLengthSlider = document.getElementById('passwordLength');
    const lengthDisplay = document.getElementById('lengthDisplay');
    const logoutButton = document.getElementById('logoutButton');
    const welcomeMessageDiv = document.getElementById('welcomeMessage');
    const savePasswordManuallyButton = document.getElementById('savePasswordManually');

    let currentUsername
    
    function showLoggedInUI(username) {
    loginForm.style.display = 'none';
    logoutButton.style.display = 'block';
    savePasswordManuallyButton.style.display = 'block';
    passwordGenerator.style.display = 'block';

    if (username) {
        currentUsername = username;
    }

    if (currentUsername) {
        welcomeMessageDiv.innerText = `Welcome ${currentUsername}!`;
    }

    welcomeMessageDiv.style.display = 'block';

    if (savePasswordButton) {
        savePasswordButton.style.display = 'none';
    }

    // Generates a password if none is already present
    if (!generatedPassword.value) {
        updatePasswordGenerator();
    }
}
    
    
    

    function showLoginFormUI() {
        loginForm.style.display = 'block';
        logoutButton.style.display = 'none';
        savePasswordManuallyButton.style.display = 'none';
        passwordGenerator.style.display = 'none';
        welcomeMessageDiv.style.display = 'none';
        if (savePasswordButton) {
            savePasswordButton.style.display = 'none';
        }
        if (fetchCurrentUrlButton) {
            fetchCurrentUrlButton.style.display = 'none';
        }
        if (passwordStrength) {
            passwordStrength.style.display = 'none';
        }
    }

    function fetchCurrentUrl() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (tabs[0] && tabs[0].url) {
                const websiteField = document.getElementById('websiteUrl');
                if (websiteField) {
                    websiteField.value = tabs[0].url;
                }
            }
        });
    }


    function updatePasswordGenerator() {
        const passwordLength = passwordLengthSlider.value;
        generatedPassword.value = generatePassword(passwordLength);
        updatePasswordStrength(generatedPassword.value);
    }

    passwordLengthSlider.oninput = updatePasswordGenerator;

    generatedPassword.addEventListener('focus', function() {
        updatePasswordGenerator();
    });

    function updatePasswordStrength(password) {
        const strengthIndicator = document.getElementById('passwordStrength');
        if (strengthIndicator) {
            strengthIndicator.style.display = 'block';
            const strength = calculatePasswordStrength(password);
            strengthIndicator.innerText = 'Strength: ' + strength;
        }
    }

    function calculatePasswordStrength(password) {
        let strength = 'Weak';
        if (password.length > 12 && /[a-zA-Z]/.test(password) && /\d/.test(password) && /[^a-zA-Z\d]/.test(password)) {
            strength = 'Strong';
        } else if (password.length > 8) {
            strength = 'Medium';
        }
        return strength;
    }

    if (savePasswordButton) {
        savePasswordButton.style.display = 'none';
    }

    const fetchCurrentUrlButton = document.getElementById('fetchCurrentUrl');
    if (fetchCurrentUrlButton) {
        fetchCurrentUrlButton.addEventListener('click', fetchCurrentUrl);
    }



    function savePasswordData(token, websiteName, websiteUrl, username, password) {
        const apiUrl = 'https://3e4c-84-203-55-131.ngrok-free.app/passwords/api/add-password';
        console.log("Attempting to save password data"); // Debug log
    
        const payload = {
            website_name: websiteName,
            website_url: websiteUrl,
            username: username,
            password: password
        };
    
        fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify(payload)
        })
        .then(response => {
            if (response.ok) {
                console.log('Password data saved successfully');
                return response.json();
            } else {
                console.error('Error saving password data:', response);
                throw new Error('Failed to save password');
            }
        })
        .then(data => {
            console.log('Server response:', data);
            alert('Password saved successfully!');
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error saving password. Check console for details.');
        });
    }

    function savePasswordManually() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            let websiteUrl = '';
            if (tabs[0] && tabs[0].url) {
                websiteUrl = tabs[0].url;
            }

            const website = prompt("Enter the website URL:", websiteUrl);
            const username = prompt("Enter the username:");
            const password = prompt("Enter the password:");
    
            if (website && username && password) {
                chrome.storage.local.get(['token'], function(result) {
                    if (result.token) {
                        savePasswordData(result.token, website, websiteUrl, username, password);
                    } else {
                        alert('You must be logged in to save passwords.');
                    }
                });
            } else {
                alert('Please provide all the details.');
            }
        });
    }

    
    function updatePasswordGenerator() {
        const passwordLength = passwordLengthSlider.value;
        generatedPassword.value = generatePassword(passwordLength);
        updatePasswordStrength(generatedPassword.value);
    }
    
    passwordLengthSlider.oninput = function() {
        updatePasswordGenerator();
        lengthDisplay.innerText = passwordLengthSlider.value;
    };

    function generatePassword(length) {
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
        let password = "";
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length);
            password += charset[randomIndex];
        }
        return password;
    }

    

    copyButton.onclick = function() {
        navigator.clipboard.writeText(generatedPassword.value);
    };

    function checkTokenValidity() {
        chrome.storage.local.get(['token', 'username'], function (result) {
            if (result.token) {
                // Shows the UI using the stored username (if available)
                showLoggedInUI(result.username);
    
                // Validates the user's token in the background
                fetch('https://3e4c-84-203-55-131.ngrok-free.app/auth/validate-token', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${result.token}` }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.message === "Token is valid" && data.username) {
                        // Updates the UI with the new username
                        showLoggedInUI(data.username);
                    } else {
                        showLoginFormUI();
                    }
                })
                .catch(() => {
                    showLoginFormUI();
                });
            } else {
                showLoginFormUI();
            }
        });
    }

    loginButton.addEventListener('click', function () {
        console.log("Login button clicked");
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
    
        fetch('https://3e4c-84-203-55-131.ngrok-free.app/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        })
        .then(response => {
            return response.json(); 
        })
        .then(data => {
            if (!data.token) {
                throw new Error('No token received.');
            }
            chrome.storage.local.set({ 
                'token': data.token, 
                'username': email.split('@')[0] 
            }, () => {
                showLoggedInUI(email.split('@')[0]);
            });
        })
        .catch(error => {
            console.error('Login error:', error);
            alert('Login error: ' + error.message);
        });
    });
    

    logoutButton.addEventListener('click', function () {
        console.log("Logout button clicked");
        fetch('https://3e4c-84-203-55-131.ngrok-free.app/auth/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        })
        .then(response => {
            if (response.ok) {
                chrome.storage.local.remove(['token'], function() {
                    showLoginFormUI(); 
                });
            } else {
                alert('Logout failed. Please try again.');
            }
        })
        .catch(error => {
            console.error('Logout error:', error);
            alert('Logout error. Check console for details.');
        });
    });
    

    if (savePasswordManuallyButton) {
        savePasswordManuallyButton.addEventListener('click', savePasswordManually);
    }

    checkTokenValidity();
});
