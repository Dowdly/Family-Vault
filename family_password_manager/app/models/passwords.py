from app import db
from cryptography.fernet import Fernet

class Password(db.Model):
    __tablename__ = 'passwords'

    password_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    website_name = db.Column(db.String(255), nullable=False)
    website_url = db.Column(db.String(255))
    username = db.Column(db.String(255), nullable=False)
    encrypted_password = db.Column(db.String(255), nullable=False)
    encryption_key = db.Column(db.String(255), nullable=False)  # Ensure this is not nullable
    category = db.Column(db.String(255), default='General')  # Default category if none provided
    date_added = db.Column(db.DateTime, default=db.func.current_timestamp())
    date_modified = db.Column(db.DateTime)
