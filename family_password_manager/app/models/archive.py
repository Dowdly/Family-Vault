from app import db
from datetime import datetime

class Archive(db.Model):
    __tablename__ = 'archives'

    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    activity_type = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)  
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Archive {self.activity_type} by User {self.user_id}>"
