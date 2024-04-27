from flask import render_template, jsonify, request, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from . import main
from app.token_decorator import token_required
from flask_cors import cross_origin
from app.models.activity_logs import ActivityLog
from app.models.users import User  
from app import db
from app.models.passwords import Password
from app.password_utils import decrypt_password
from app.models.activity_logs import ActivityLog
from sqlalchemy import asc, desc
from flask import jsonify, request
from flask import current_app
from flask_login import login_required, current_user
from . import main
from app.models.activity_logs import ActivityLog
from app.models.users import User
from app.models.passwords import Password
from app.password_utils import decrypt_password
from app import db
from sqlalchemy import asc, desc
from flask import make_response, Response
from io import StringIO
import csv




@main.route('/')
@cross_origin()
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return render_template('main/index.html')


@main.route('/export-activity-log')
@login_required
def export_activity_log():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('main.index'))

    try:
        # Fetch data for current logs only, similar to activity-log-data fetch
        logs = db.session.query(
            ActivityLog.log_id,
            User.user_id,
            User.email.label('user_email'),
            ActivityLog.snapshot_website_name,
            ActivityLog.snapshot_website_url,
            ActivityLog.snapshot_username,
            ActivityLog.snapshot_password,  # Must handle this securely
            ActivityLog.activity_type,
            ActivityLog.date_time
        ).join(User, User.user_id == ActivityLog.user_id)\
        .order_by(ActivityLog.date_time.desc()).all()

        # Generate CSV data using snapshot data
        def generate(logs):
            data = StringIO()
            cw = csv.writer(data)
            cw.writerow(['Log ID', 'User ID', 'User Email', 'Website Name', 'Website URL', 'Username', 'Password Snapshot', 'Activity Type', 'Date Time'])
            yield data.getvalue()
            data.seek(0)
            data.truncate(0)

            for log in logs:
                cw.writerow([
                    log.log_id, 
                    log.user_id, 
                    log.user_email, 
                    log.snapshot_website_name, 
                    log.snapshot_website_url,
                    log.snapshot_username,
                    log.snapshot_password,  # Assuming this is a secure representation
                    log.activity_type, 
                    log.date_time.strftime("%Y-%m-%d %H:%M:%S")
                ])
                yield data.getvalue()
                data.seek(0)
                data.truncate(0)

        # Stream the response as the data is generated
        response = Response(generate(logs), mimetype='text/csv')
        response.headers.set("Content-Disposition", "attachment", filename="activity_log.csv")
        return response

    except Exception as e:
        current_app.logger.error(f"Error exporting activity log: {e}")
        flash('Error exporting activity log', 'danger')
        return redirect(url_for('main.activity_log'))



@main.route('/user_home')
@login_required
@cross_origin()
def user_home():
    if current_user.is_authenticated:
        # Check if it's an API request (for example, by checking a header)
        if request.headers.get('Accept') == 'application/json':
            # Return a JSON response for an API request
            return jsonify({'message': 'User home data', 'user': current_user.username})
        
        # For regular web requests, render the user home template
        return render_template('main/user_home.html', title='Home', user=current_user)

    # If not authenticated, return an error (either in JSON or as a redirect)
    if request.headers.get('Accept') == 'application/json':
        return jsonify({'error': 'Unauthorized'}), 403

    return redirect(url_for('auth.login'))




@main.route('/activity-log')
@main.route('/activity-log/page/<int:page>')
@login_required
def activity_log(page=1):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('main.index'))

    per_page = 10
    paginated_query = ActivityLog.query.filter_by(user_id=current_user.user_id).order_by(ActivityLog.date_time.desc()).paginate(page=page, per_page=per_page, error_out=False)

    return render_template('main/activity_log.html', logs=paginated_query.items, pagination=paginated_query)



@main.route('/wipe-activity-log', methods=['POST'])
@login_required
def wipe_activity_log():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return jsonify({'error': 'Access denied'}), 403

    try:
        num_deleted = ActivityLog.query.delete()
        db.session.commit()
        return jsonify({'success': f'Successfully wiped {num_deleted} activity log entries'})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error wiping activity log: {e}")
        return jsonify({'error': 'Error wiping activity log'}), 500

    

@main.route('/activity-log-data')
@login_required
def activity_log_data():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    sort_field = request.args.get('sortField', 'date_time')
    sort_order = request.args.get('sortOrder', 'asc')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Determines the sort direction
    direction_func = desc if sort_order == 'desc' else asc

    # Adjusts the query based on the sort field
    if sort_field in ['user_email', 'website_url']:
        base_query = db.session.query(
            ActivityLog.log_id,
            ActivityLog.user_id,
            User.email.label('user_email'),
            ActivityLog.snapshot_website_name,
            ActivityLog.snapshot_website_url,
            ActivityLog.snapshot_username,
            ActivityLog.snapshot_password,
            ActivityLog.activity_type,
            ActivityLog.description,
            ActivityLog.date_time
        ).join(User, User.user_id == ActivityLog.user_id)

        if sort_field == 'user_email':
            query = base_query.order_by(direction_func(User.email))
        elif sort_field == 'website_url':
            query = base_query.order_by(direction_func(ActivityLog.snapshot_website_url))
    else:
        # For other fields directly on ActivityLog
        query = db.session.query(
            ActivityLog.log_id,
            ActivityLog.user_id,
            User.email.label('user_email'),
            ActivityLog.snapshot_website_name,
            ActivityLog.snapshot_website_url,
            ActivityLog.snapshot_username,
            ActivityLog.snapshot_password,
            ActivityLog.activity_type,
            ActivityLog.description,
            ActivityLog.date_time
        ).join(User, User.user_id == ActivityLog.user_id).order_by(direction_func(getattr(ActivityLog, sort_field)))

    paginated_query = query.paginate(page=page, per_page=per_page, error_out=False)

    log_data = [{
        'log_id': log.log_id,
        'user_id': log.user_id,
        'user_email': log.user_email,
        'snapshot_website_name': log.snapshot_website_name,
        'snapshot_website_url': log.snapshot_website_url,
        'snapshot_username': log.snapshot_username,
        'snapshot_password': log.snapshot_password,
        'activity_type': log.activity_type,
        'description': log.description,
        'date_time': log.date_time.strftime("%Y-%m-%d %H:%M:%S")
    } for log in paginated_query.items]

    # Adding pagination data
    pagination_data = {
        'currentPage': paginated_query.page,
        'totalPages': paginated_query.pages,
        'hasNext': paginated_query.has_next,
        'hasPrev': paginated_query.has_prev,
        'nextNum': paginated_query.next_num,
        'prevNum': paginated_query.prev_num,
    }

    return jsonify({
        'logs': log_data,
        'pagination': pagination_data
    })