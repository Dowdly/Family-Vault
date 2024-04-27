from .forms import UpdateUsernameForm, UpdatePasswordForm
import jwt
import datetime
from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from . import auth
from app import bcrypt, db
from app.auth.forms import LoginForm, RegistrationForm
from app.models.users import User
from app.auth.forms import CreateUserForm
from flask_cors import cross_origin
from datetime import timedelta
from flask_jwt_extended import create_access_token
import logging
from flask import current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_login import current_user, login_required
from flask import flash, redirect, render_template, request, url_for



@auth.route('/register-admin', methods=['GET', 'POST'])
@cross_origin() 
def register_admin():
    # Only allows registration if no users exist
    if User.query.first() is not None:
        flash('Admin registration is not allowed', 'danger')
        return redirect(url_for('main.index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        admin_user = User(username=form.username.data, email=form.email.data, hashed_password=hashed_password, role='admin')
        db.session.add(admin_user)
        db.session.commit()
        flash('Admin account has been created!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register_admin.html', title='Register Admin', form=form)


@auth.route('/create-user', methods=['GET', 'POST'])
@login_required
@cross_origin() 
def create_user():
    if current_user.role != 'admin':
        flash('Unauthorized Access!', 'danger')
        return redirect(url_for('main.index'))

    form = CreateUserForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, hashed_password=hashed_password, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('main.index'))

    return render_template('auth/create_user.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
@cross_origin()
def login():
    current_app.logger.debug(f"Login route called. Method: {request.method}, User Authenticated: {current_user.is_authenticated}")

    if current_user.is_authenticated:
        current_app.logger.info('User already authenticated')
        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            token = current_user.active_token  
            if token: 
                return jsonify({'token': token, 'sendToExtension': True}), 200
            else:
                token = create_access_token(identity=current_user.user_id, expires_delta=timedelta(hours=24))
                current_user.active_token = token  # Updates the user's active token
                db.session.commit()
                return jsonify({'token': token, 'sendToExtension': True}), 200
        return redirect(url_for('passwords.manage'))

    if request.method == 'POST':
        # Debug Checks if the request is JSON or a regular form submission
        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            data = request.get_json()
            current_app.logger.info(f'JSON login request received: {data}')
            user = User.query.filter_by(email=data.get('email')).first()

            if user and bcrypt.check_password_hash(user.hashed_password, data.get('password')):
                login_user(user, remember=True)
                token = create_access_token(identity=user.user_id, expires_delta=timedelta(hours=24))
                
                # Store the active token in the user model
                user.active_token = token
                db.session.commit()

                current_app.logger.info(f'JWT token generated for user {user.email}: {token}')
                return jsonify({'token': token, 'sendToExtension': True})
            else:
                current_app.logger.warning('Invalid email or password for JSON login')
                return jsonify({'error': 'Invalid email or password'}), 401
        else:
            form = LoginForm()
            if form.validate_on_submit():
                user = User.query.filter_by(email=form.email.data).first()
                if user and bcrypt.check_password_hash(user.hashed_password, form.password.data):
                    login_user(user, remember=form.remember.data)
                    token = create_access_token(identity=user.user_id, expires_delta=timedelta(hours=24))
                    user.active_token = token
                    db.session.commit()
                    current_app.logger.info(f'User logged in via web form: {user.email}')

                    # Redirects the user to Manage Passwords page
                    return redirect(url_for('passwords.manage'))
                else:
                    current_app.logger.warning('Login unsuccessful via web form')
                    flash('Login Unsuccessful. Please check email and password', 'danger')
            if request.is_json or request.headers.get('Content-Type') == 'application/json':
                return jsonify({'error': 'Form validation failed or login unsuccessful'}), 400

            return render_template('auth/login.html', title='Login', form=form)

    # User is not authenticated, return the login template
    # If POST is executed, this line will only be reached for non-JSON requests
    return render_template('auth/login.html', title='Login', form=LoginForm())


@auth.route('/validate-token', methods=['POST'])
@jwt_required()
def validate_token():
    try:
        # If token is valid, gets the user identity
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user:
            raise Exception("User not found")
        return jsonify({"message": "Token is valid", "user_id": current_user_id, "username": user.username}), 200
    except Exception as e:
        # Handles invalid token case
        return jsonify({"message": "Token is invalid or expired"}), 401



@auth.route('/user_profile', methods=['GET', 'POST'])
@cross_origin()
def user_profile():
    update_username_form = UpdateUsernameForm()
    update_password_form = UpdatePasswordForm()

    if update_username_form.validate_on_submit():
        current_user.username = update_username_form.username.data
        db.session.commit()
        flash('Your username has been updated!', 'success')

    if update_password_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(update_password_form.password.data).decode('utf-8')
        current_user.hashed_password = hashed_password
        db.session.commit()
        flash('Your password has been updated!', 'success')

    return render_template('user_profile.html', update_username_form=update_username_form, update_password_form=update_password_form)


@auth.route('/logout', methods=['GET', 'POST'])
@cross_origin() 
def logout():
    current_user.active_token = None
    db.session.commit()
    logout_user()
    if request.method == 'POST':
        # Returns a JSON response for AJAX request
        return jsonify({'message': 'Logged out successfully'}), 200
    else:
        # For non-AJAX requests, redirect to the below login page
        flash('You have been logged out.', 'info')
        return redirect(url_for('auth.login'))





@auth.route('/register', methods=['GET', 'POST'])
def register():
    # Checks if the user is authenticated and an admin
    if current_user.is_authenticated:
        if current_user.role != 'admin':
            flash('Only admins can create new accounts.', 'warning')
            return redirect(url_for('main.index'))  # Redirect to a different page for regular users
        # For admins, the form is rendered with role selection
        form = CreateUserForm(request.form)
    else:
        # For unauthenticated users, a form without role selection
        form = RegistrationForm(request.form)

    if request.method == 'POST' and form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_role = 'standard'  # Default role for new registrations
        
        if hasattr(form, 'role'):
            user_role = form.role.data if current_user.is_authenticated and current_user.role == 'admin' else 'standard'
        
        user = User(username=form.username.data, email=form.email.data, hashed_password=hashed_password, role=user_role)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)