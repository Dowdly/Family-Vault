let authToken = null;

chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
    if (request.action === "loginSuccess") {
        authToken = request.token;
        localStorage.setItem('authToken', authToken);
    }
});

function debugLog(message) {
    console.log("[Debug] " + message);
}

function getToken(callback) {
    chrome.storage.local.get(['token'], function (result) {
        if (result.token) {
            callback(result.token);
        } else {
            console.error('No token found in storage');
        }
    });
}

function savePasswordData(token, websiteName, websiteUrl, username, password) {
    const apiUrl = 'https://3e4c-84-203-55-131.ngrok-free.app/passwords/api/add-password';
    debugLog(`Sending password data to: ${apiUrl} with token: ${token}`);

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
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        debugLog('Password data saved:', JSON.stringify(data));
    })
    .catch(error => console.error('Error saving password data:', error));
}

function findUsernameField(form) {
    return form.querySelector('input[type="text"], input[type="email"], input[name="username"], input[name="login"], input[name="user"], input[id="username"], input[id="login"], input[id="user"]');
}

function findPasswordField(form) {
    return form.querySelector('input[type="password"]');
}

function processFormSubmission(form) {
    let usernameField = findUsernameField(form);
    let passwordField = findPasswordField(form);
    
    if (usernameField && passwordField) {
        let username = usernameField.value;
        let password = passwordField.value;
        if (username && password) {
            getToken(token => {
                savePasswordData(token, document.title, window.location.href, username, password);
            });
        }
    } else {
        debugLog('Username or password field not found in form');
    }
}

function attachFormListeners() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        if (!form.dataset.formListenerAttached) {
            form.addEventListener('submit', (event) => {
                processFormSubmission(form);
                form.dataset.formListenerAttached = "true";
            }, true); // Use capture phase for event listening
        }
    });
}

function observeDOMChanges() {
    const observer = new MutationObserver(mutations => {
        mutations.forEach(mutation => {
            if (mutation.addedNodes.length) {
                attachFormListeners(); // Re-attach listeners to include new forms
            }
        });
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

attachFormListeners();
observeDOMChanges();
