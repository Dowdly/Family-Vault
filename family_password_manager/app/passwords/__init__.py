from flask import Blueprint

passwords = Blueprint('passwords', __name__)

from app.passwords import routes
