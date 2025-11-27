# FamilyVault 🔐

**A centralised password manager designed specifically for families, featuring parental oversight, activity logging, and a complementary Chrome Extension.**

---

## 📖 Contents
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Tech Stack](#-tech-stack)
- [System Architecture](#-system-architecture)
- [Installation & Setup](#-installation--setup)
- [Usage](#-usage)
- [Future Roadmap](#-future-roadmap)
- [Acknowledgments](#-acknowledgments)

---

## 📋 Overview
**FamilyVault** bridges the gap in the digital security market by catering specifically to family units. While conventional password managers focus on individual privacy or corporate sharing, FamilyVault introduces a hierarchical system allowing parents (Admins) to manage and monitor digital access for their children (Users).

The solution consists of two parts:
1. **Web Application:** A dashboard for managing vaults, users, and viewing activity logs.
2. **Chrome Extension:** A browser tool that automatically captures login credentials and syncs them to the family vault.

---

## ✨ Key Features

### 🛡️ Security & Management
- **Role-Based Access:** Distinct dashboards for `Admins` (Parents) and `Regular Users` (Children).
- **Activity Logging:** Admins have full visibility into password changes and account activity via a centralised log.
- **Zero-Interference Capture:** The Chrome extension detects login forms and captures credentials automatically.
- **Password Strength Meter:** Real-time analysis of password complexity (uppercase, lowercase, special characters).

### ⚙️ Utilities
- **Password Generator:** Built-in tool to create cryptographically strong passwords.
- **Bulk Import/Export:** Support for `.csv` data migration.
- **Accessibility:** Integrated High Contrast Mode for improved visibility.
- **Responsive Design:** Optimised for both desktop and mobile web usage.

---

## 🛠 Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Python, Flask, SQLAlchemy |
| **Database** | Microsoft Azure SQL Server |
| **Frontend** | HTML5, CSS3, JavaScript |
| **Extension** | JavaScript, JSON Web Tokens (JWT) |
| **Security** | Bcrypt (Hashing), Python Cryptography Lib (AES Encryption) |
| **Dev Tools** | Git, Postman, Ngrok |

---

## 🏗 System Architecture

The system uses a client-server model ensuring secure transmission of data.

1.  **Client (Extension):** Detects DOM form submissions $\rightarrow$ Extracts credentials $\rightarrow$ Encrypts payload.
2.  **Transport:** Data is sent via secure HTTPS requests using JWT for session validation.
3.  **Server (Flask):** Validates requests $\rightarrow$ Handles business logic $\rightarrow$ Interacts with the database.
4.  **Storage:** Credentials are stored in Azure SQL, with sensitive data encrypted at rest.

---

## 🚀 Installation & Setup

### Prerequisites
* Python 3.8+
* Google Chrome Browser

### Step 1: Clone the Repository
Start by cloning the project to your local machine.

```bash
git clone https://github.com/yourusername/familyvault.git
cd familyvault

```

### Step 2: Virtual Environment

```bash
It is recommended to run the project in a virtual environment.

For Windows:


python -m venv venv
venv\Scripts\activate

For Mac/Linux:

python3 -m venv venv
source venv/bin/activate

```

### Step 3: Install Dependencies

```bash
Once the virtual environment is active, install the required packages.

pip install -r requirements.txt

```

### Step 4: Configuration
```bash
Create a .env file in the root directory with your specific configuration settings.



FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your_secret_key
DATABASE_URL=your_azure_sql_connection_string

```


### Step 5: Run the Application
```bash

Start the Flask server.

python app.py

```

### Step 6: Chrome Extension Setup

    Open Google Chrome and navigate to chrome://extensions/.
    Toggle Developer mode (top right corner).
    Click Load unpacked.
    Select the /extension folder located in this repository.

💻 Usage

    Register an Admin Account: The first account created should be the parent account.
    Create Child Accounts: Use the Admin dashboard to generate accounts for family members.
    Login to Extension: Click the FamilyVault icon in your browser toolbar and log in.
    Browse the Web: As you log into websites (e.g., Netflix, Facebook), the extension will prompt to save credentials.
    Monitor: Admins can view the "Activity Log" tab in the web app to see recent activity.

🔮 Future Roadmap

    [ ] Two-Factor Authentication (2FA): Integration with TOTP apps.
    [ ] Cross-Browser Support: Support for Firefox and Safari.
    [ ] Mobile App: Native iOS/Android application.
    [ ] Advanced Form Heuristics: Improved detection for non-standard login forms.

👏 Acknowledgments

This project was developed as a final year software engineering project. Special thanks to my supervisor, Paul Laird, for his expertise and guidance on the browser extension architecture.
