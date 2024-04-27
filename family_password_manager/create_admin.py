# create_admin.py
from app import create_app, db, bcrypt
from app.models.users import User

app = create_app()

with app.app_context():
    admin_username = "mark"
    admin_email = "mark@admin.com"
    admin_password = "1234"

    hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
    admin_user = User(username=admin_username, email=admin_email, hashed_password=hashed_password, role='admin')

    db.session.add(admin_user)
    db.session.commit()

    print("Admin user created.")
