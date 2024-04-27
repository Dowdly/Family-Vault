from app import db
from datetime import datetime

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    password_id = db.Column(db.Integer, db.ForeignKey('passwords.password_id'), nullable=True)
    activity_type = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    snapshot_website_name = db.Column(db.String(255))
    snapshot_website_url = db.Column(db.String(255))
    snapshot_username = db.Column(db.String(255))
    snapshot_password = db.Column(db.String(255)) 

    date_time = db.Column(db.DateTime, default=datetime.utcnow)