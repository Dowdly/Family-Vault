from app import db
from app.models.activity_logs import ActivityLog
from app.models.archive import Archive
from datetime import datetime, timedelta

#Not yet implemented, but is planned to be used to archive old logs

def archive_old_logs():
    # Defineing how old an entry needs to be to be archived (e.g., 6 months)
    archive_before_date = datetime.utcnow() - timedelta(days=180)

    # Fetch old log entries
    old_logs = ActivityLog.query.filter(ActivityLog.date_time < archive_before_date).all()

    for log in old_logs:
        # Create an archive entry
        archive_entry = Archive(
            user_id=log.user_id,
            activity_type=log.activity_type,
            description=log.description,
            date_time=log.date_time
        )

        # Add to archive
        db.session.add(archive_entry)

        # Remove from active logs
        db.session.delete(log)

    # Commit changes to the database
    db.session.commit()

    print(f"Archived {len(old_logs)} entries.")

# Run the archiving process
if __name__ == '__main__':
    archive_old_logs()
