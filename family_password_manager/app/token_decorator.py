from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from flask_login import current_user
from app.models.users import User

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            current_app.logger.debug("OPTIONS request, bypassing token verification.")
            return f(*args, **kwargs)

        auth_header = request.headers.get('Authorization', None)
        if not auth_header:
            current_app.logger.error("No Authorization header in the request.")
            return jsonify({'message': 'Missing Authorization header'}), 401

        token = auth_header.split(" ")[1] if len(auth_header.split(" ")) > 1 else None
        if not token:
            current_app.logger.error("Bearer token not found.")
            return jsonify({'message': 'Bearer token not found'}), 401

        current_app.logger.debug(f"Received token: {token}")

        try:
            current_app.logger.debug("Attempting to verify JWT token...")
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            current_user = User.query.get(user_id)

            if not current_user or current_user.active_token != token:
                raise Exception("Invalid or expired token associated with the user.")

            current_app.logger.debug(f"Token verified successfully for user ID: {user_id}")

        except Exception as e:
            current_app.logger.error(f"Token verification failed: {e}")
            return jsonify({'message': f'Token is invalid: {str(e)}'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def unified_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return f(*args, **kwargs)

        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user:
                raise Exception("User not found.")
           

            return f(*args, **kwargs)
        except:
            return jsonify({'error': 'Authentication required'}), 401

    return decorated_function