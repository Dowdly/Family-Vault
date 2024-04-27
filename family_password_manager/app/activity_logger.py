
from app import db
from app.models.activity_logs import ActivityLog

def log_activity(user_id, activity_type, description, website_name=None, website_url=None, username=None, password=None):
    # Creates a new log entry with snapshot details
    log_entry = ActivityLog(
        user_id=user_id,
        activity_type=activity_type,
        description=description,
        snapshot_website_name=website_name,
        snapshot_website_url=website_url,
        snapshot_username=username,
        snapshot_password=password 
    )
    db.session.add(log_entry)
