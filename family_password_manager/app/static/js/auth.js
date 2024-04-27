function login(event) {
    event.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    console.log('Attempting login with:', email);

    fetch('/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email, password: password })
    })
    .then(response => {
        console.log('Login response status:', response.status);
        if (!response.ok) {
            throw new Error('Login failed: ' + response.status);
        }
        return response.json();
    })
    .then(data => {
        console.log('Login response data:', data);
        if (data.error) {
            console.error('Login error:', data.error);
            alert('Error: ' + data.error);
        } else if (data.token) {
            localStorage.setItem('token', data.token);
            console.log('Token stored:', localStorage.getItem('token'));

            if (chrome.runtime && chrome.runtime.sendMessage) {
                chrome.runtime.sendMessage("ifpnnakcbofogpihgmjlemgnhffgeief", {token: data.token}, function(response) {
                    console.log("Token sent to extension:", response);
                });
            }

            navigateWithToken('/passwords/manage-passwords');
        }
    })
    .catch(error => {
        console.error('Error during login process:', error);
        alert('Login failed: ' + error.message);
    });
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

function submitCreateUserForm(event) {
    event.preventDefault();
    var formData = new FormData(document.getElementById('createUserForm'));
    var data = Object.fromEntries(formData.entries());

    fetchWithToken('/auth/create-user', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if(response.ok) {
            alert('User created successfully');
            navigateWithToken('/user_home'); 
        } else {
            throw new Error('Failed to create user');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert(error.message);
    });
}

document.addEventListener('DOMContentLoaded', (event) => {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', login);
    }

    const createUserForm = document.getElementById('createUserForm');
    if (createUserForm) {
        createUserForm.addEventListener('submit', submitCreateUserForm);
    }
});
