from app import db
from flask_login import UserMixin
from app import login_manager

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    hashed_password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='standard', nullable=False)
    date_joined = db.Column(db.DateTime, default=db.func.current_timestamp())
    last_login = db.Column(db.DateTime)
    active_token = db.Column(db.String(512), nullable=True)  # Increased length to 512
    def get_id(self):
        return str(self.user_id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))