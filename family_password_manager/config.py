import os
import urllib.parse

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Flask configuration
SECRET_KEY = 'yv7Ll8Y1WjM5Zq-9fJgTxD-d5JPh59Ho'

# SQLAlchemy configuration
username = urllib.parse.quote_plus('Marko')  
password = urllib.parse.quote_plus('Martian1!@')  

SQLALCHEMY_DATABASE_URI = (
    f"mssql+pyodbc://{username}:{password}"
    "@dbsproject.database.windows.net:1433/"
    "project?"
    "driver=ODBC+Driver+17+for+SQL+Server&"
    "Encrypt=yes&"
    "TrustServerCertificate=no"
)
SQLALCHEMY_TRACK_MODIFICATIONS = False
