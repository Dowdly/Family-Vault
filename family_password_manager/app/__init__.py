import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    app.logger.setLevel(logging.DEBUG)

    # Your existing configuration...
    app.config['SECRET_KEY'] = '\xe7.\x16g\xabe\x17\xdb\xf6\xca\xa6\xd4\xe5!\xbb\x03\x9b\xcd\xcc`{\xeb\x80\x9a'
    app.config.from_object('config')
    app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
    
    CORS(app, resources={r"/passwords/*": {
        "origins": ["chrome-extension://*"],  # Update this in production
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"],
        "supports_credentials": True
    }})
    
    jwt = JWTManager(app)
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = 'auth.login'
    
    @login_manager.user_loader
    def load_user(user_id):
        from app.models.users import User
        if user_id is not None:
            return User.query.get(int(user_id))
        return None

    # Blueprint registrations
    from app.main import main as main_blueprint
    from app.passwords import passwords as passwords_blueprint
    from app.auth import auth as auth_blueprint
    app.register_blueprint(main_blueprint)
    app.register_blueprint(passwords_blueprint, url_prefix='/passwords')
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    return app
