from app import db

class SharedPassword(db.Model):
    __tablename__ = 'shared_passwords'

    shared_password_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    password_id = db.Column(db.Integer, db.ForeignKey('passwords.password_id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    date_shared = db.Column(db.DateTime, default=db.func.current_timestamp())
