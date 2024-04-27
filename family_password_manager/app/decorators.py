# decorators.py
from functools import wraps
from flask import jsonify
from flask_login import current_user
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

def unified_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return f(*args, **kwargs)

        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            return f(*args, **kwargs)
        except:
            return jsonify({'error': 'Authentication required'}), 401

    return decorated_function
