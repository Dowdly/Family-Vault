import csv
from io import StringIO
from flask import render_template, redirect, url_for, flash, request, jsonify, Response, make_response
from flask_login import current_user
from . import passwords
from app import db, bcrypt
from app.passwords.forms import CreatePasswordForm, EditPasswordForm
from app.models.passwords import Password
from app.password_utils import encrypt_password, decrypt_password
from app.token_decorator import unified_login_required
from flask_cors import cross_origin
from flask import current_app as app
from app.activity_logger import log_activity
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.users import User
from app.models.activity_logs import ActivityLog
from flask import request, jsonify
from flask_login import login_required, current_user
from flask import flash, redirect, render_template, url_for, jsonify
from datetime import datetime



@passwords.route('/manage-passwords')
@unified_login_required
@cross_origin()
def manage():
    password_records = Password.query.filter_by(user_id=current_user.user_id).all()
    decrypted_passwords = {}
    for record in password_records:
        decrypted_passwords[record.password_id] = decrypt_password(record.encrypted_password, record.encryption_key)
    return render_template('passwords/manage.html', passwords=password_records, decrypted_passwords=decrypted_passwords)



@passwords.route('/export-passwords')
@unified_login_required
@cross_origin()
def export_passwords():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['website_name', 'username', 'decrypted_password', 'website_url', 'category'])

    passwords = Password.query.filter_by(user_id=current_user.user_id).all()
    for password in passwords:
        decrypted_password = decrypt_password(password.encrypted_password, password.encryption_key)
        cw.writerow([password.website_name, password.username, decrypted_password, password.website_url, password.category])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=passwords.csv"
    output.headers["Content-type"] = "text/csv"
    return output

#Enables the deletion of multiple passwords although has to iterate through each password to delete them. Can be slow if you're deleting a lot!
@passwords.route('/delete-multiple', methods=['POST'])
@unified_login_required
@cross_origin()
def delete_multiple_passwords():
    data = request.get_json()
    password_ids = data.get('passwordIds')

    if not password_ids:
        return jsonify({'error': 'No passwords specified'}), 400

    try:
        # Retrieve and log each password before deletion
        for password_id in password_ids:
            password = Password.query.filter_by(password_id=password_id, user_id=current_user.user_id).first()
            if password:
                # Log the deletion activity
                decrypted_password = decrypt_password(password.encrypted_password, password.encryption_key)
                log_activity(
                    user_id=current_user.user_id,
                    activity_type='Delete Password',
                    description=f'Deleted password for {password.website_name}',
                    website_name=password.website_name,
                    website_url=password.website_url,
                    username=password.username,
                    password=decrypted_password 
                )
                db.session.delete(password)

        db.session.commit()
        return jsonify({'success': 'Passwords deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@passwords.route('/import-passwords', methods=['POST'])
@unified_login_required
@cross_origin()
def import_passwords():
    file = request.files['file']
    stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
    csv_input = csv.reader(stream)
    next(csv_input, None)  

    imported_passwords = []
    for row in csv_input:
        website_name, username, plaintext_password, website_url, category = row
        encrypted_password, encryption_key = encrypt_password(plaintext_password)

        new_password = Password(
            user_id=current_user.user_id,
            website_name=website_name,
            username=username,
            encrypted_password=encrypted_password,
            encryption_key=encryption_key,
            website_url=website_url,
            category=category
        )
        db.session.add(new_password)
        db.session.flush() 

        activity_description = f'Imported password for {website_name} ({username})'
        new_activity_log = ActivityLog(
            user_id=current_user.user_id,
            snapshot_website_name=website_name,
            snapshot_website_url=website_url,
            snapshot_username=username,
            snapshot_password=plaintext_password, 
            activity_type='Password Import',
            description=activity_description,
            date_time=datetime.now()
        )
        db.session.add(new_activity_log)
        imported_passwords.append({'password_id': new_password.password_id, 'website_name': website_name, 'username': username, 'category': category, 'date_added': datetime.now().isoformat()})

    db.session.commit()
    
    return jsonify({'success': 'Passwords imported successfully', 'imported_passwords': imported_passwords})



@passwords.route('/decrypt-password/<int:id>', methods=['GET'])
@unified_login_required
@cross_origin()
def decrypt_password_route(id):
    password_record = Password.query.get_or_404(id)
    if password_record.user_id != current_user.user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    decrypted_password = decrypt_password(password_record.encrypted_password, password_record.encryption_key)
    return jsonify({'decrypted_password': decrypted_password})

@passwords.route('/add-password', methods=['GET', 'POST'])
@unified_login_required
@cross_origin()
def add_password():
    form = CreatePasswordForm()
    if form.validate_on_submit():
        encrypted_password, encryption_key = encrypt_password(form.password.data)
        new_password = Password(
            user_id=current_user.user_id,
            website_name=form.website_name.data,
            website_url=form.website_url.data,
            username=form.username.data,
            encrypted_password=encrypted_password,
            encryption_key=encryption_key,
            category=form.category.data
        )
        db.session.add(new_password)
        
        log_activity(
            user_id=current_user.user_id,
            activity_type='Add Password',
            description='Added a new password.',
            website_name=form.website_name.data,
            website_url=form.website_url.data,
            username=form.username.data,
            password=form.password.data  
        )
        
        db.session.commit()

        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': True, 'message': 'Password added successfully'}), 200

        flash('Password added successfully!', 'success')
        return redirect(url_for('passwords.manage'))

    if request.is_json or request.headers.get('Content-Type') == 'application/json':
        form_errors = {field: errors for field, errors in form.errors.items()}
        return jsonify({'error': 'Form validation failed', 'form_errors': form_errors}), 400

    return render_template('passwords/add_password.html', form=form)



@passwords.route('/api/add-password', methods=['POST'])
@jwt_required()
@cross_origin()
def api_add_password():
    app.logger.debug("Received /api/add-password request")

    user_id = get_jwt_identity()
    app.logger.debug(f"JWT Identity (user_id): {user_id}")

    current_user = User.query.get(user_id)
    if not current_user:
        app.logger.error("User not found with the provided JWT identity")
        return jsonify({'error': 'User not found'}), 404

    try:
        data = request.get_json()
        app.logger.debug(f"Received password data: {data}")

        encrypted_password, encryption_key = encrypt_password(data['password'])
        new_password = Password(
            user_id=current_user.user_id,
            website_name=data['website_name'],
            website_url=data['website_url'],
            username=data['username'],
            encrypted_password=encrypted_password,
            encryption_key=encryption_key,
            category="External"
        )
        db.session.add(new_password)
        db.session.flush()  
        log_activity(
            user_id=current_user.user_id,
            activity_type='API Add Password',
            description=f"Password added via API for {data['website_name']}",
            website_name=data['website_name'],
            website_url=data['website_url'],
            username=data['username'],
            password=data['password']  
        )
        db.session.commit()
        return jsonify({'message': 'Password saved successfully'}), 200
    except Exception as e:
        app.logger.error(f"Error in api_add_password: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

    
@passwords.route('/edit-password/<int:id>', methods=['GET', 'POST'])
@unified_login_required
@cross_origin()
def edit_password(id):
    password_record = Password.query.get_or_404(id)
    if password_record.user_id != current_user.user_id:
        flash('Unauthorized to edit this password.', 'danger')
        return redirect(url_for('passwords.manage'))

    form = EditPasswordForm(obj=password_record)
    if form.validate_on_submit():
        original_decrypted_password = decrypt_password(password_record.encrypted_password, password_record.encryption_key)

        encrypted_password, encryption_key = encrypt_password(form.password.data)
        password_record.website_name = form.website_name.data
        password_record.website_url = form.website_url.data
        password_record.username = form.username.data
        password_record.encrypted_password = encrypted_password
        password_record.encryption_key = encryption_key
        password_record.category = form.category.data

       
        log_activity(
            user_id=current_user.user_id,
            activity_type='Edit Password',
            description=f'Password for {form.website_name.data} was edited.',
            website_name=password_record.website_name,
            website_url=password_record.website_url,
            username=password_record.username,
            password=original_decrypted_password  
        )

        db.session.commit()

        log_activity(
            user_id=current_user.user_id,
            activity_type='Edit Password',
            description=f'Password for {form.website_name.data} updated.',
            website_name=form.website_name.data,
            website_url=form.website_url.data,
            username=form.username.data,
            password=form.password.data 
        )

        db.session.commit()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('passwords.manage'))

    decrypted_password = decrypt_password(password_record.encrypted_password, password_record.encryption_key)
    return render_template('passwords/edit_password.html', form=form, password=password_record, password_plaintext=decrypted_password)




@passwords.route('/delete-password/<int:id>', methods=['POST'])
@unified_login_required
@cross_origin()
def delete_password(id):
    password = Password.query.get_or_404(id)
    if password.user_id != current_user.user_id:
        return jsonify({'error': 'Unauthorized to delete this password.'}), 403
    
    decrypted_password = decrypt_password(password.encrypted_password, password.encryption_key)
    log_activity(
        user_id=current_user.user_id,
        activity_type='Delete Password',
        description=f'Deleted password for {password.website_name}',
        website_name=password.website_name,
        website_url=password.website_url,
        username=password.username,
        password=decrypted_password 
    )
    
    db.session.delete(password)
    db.session.commit()
    return jsonify({'success': 'Password deleted successfully!', 'id': id}), 200