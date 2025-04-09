import os
import logging
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
import config
import uuid
import datetime
import json

# Initialize logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.config.from_object(config)
app.secret_key = config.SESSION_SECRET

# Configure WSGI app for proper HTTPS forwarding
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.SQLALCHEMY_TRACK_MODIFICATIONS
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = config.SQLALCHEMY_ENGINE_OPTIONS
db.init_app(app)

# Create uploads directory if it doesn't exist
if not os.path.exists(config.UPLOAD_FOLDER):
    os.makedirs(config.UPLOAD_FOLDER)

# Import models (after db init)
from models import User, FileUpload
from utils.auth import verify_firebase_token
from utils.file_handler import allowed_file, get_unique_filename
from utils.security import generate_csrf_token, validate_csrf_token, get_secure_headers
from utils.virus_scan import VirusTotalScanner
import json

# Create database tables
with app.app_context():
    db.create_all()

# Security headers middleware
@app.after_request
def add_security_headers(response):
    # Add security headers to all responses
    headers = get_secure_headers()
    for key, value in headers.items():
        response.headers[key] = value
    return response

@app.route('/')
def index():
    """Render the main index page"""
    return render_template(
        'index.html',
        firebase_api_key=config.FIREBASE_API_KEY,
        firebase_auth_domain=config.FIREBASE_AUTH_DOMAIN,
        firebase_database_url=config.FIREBASE_DATABASE_URL,
        firebase_project_id=config.FIREBASE_PROJECT_ID,
        firebase_storage_bucket=config.FIREBASE_STORAGE_BUCKET,
        firebase_messaging_sender_id=config.FIREBASE_MESSAGING_SENDER_ID,
        firebase_app_id=config.FIREBASE_APP_ID,
        firebase_measurement_id=config.FIREBASE_MEASUREMENT_ID
    )

@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    """Verify Firebase ID token and create/update user in database"""
    data = request.get_json()
    id_token = data.get('idToken')
    
    if not id_token:
        return jsonify({'error': 'No ID token provided'}), 400
    
    try:
        # Verify the Firebase ID token
        user_data = verify_firebase_token(id_token)
        uid = user_data['uid']
        email = user_data['email']
        
        # Check if user exists
        user = User.query.get(uid)
        
        if not user:
            # Create new user
            user = User(id=uid, email=email)
            if 'name' in user_data:
                user.name = user_data['name']
            db.session.add(user)
        
        # Update last login time
        user.last_login = datetime.datetime.utcnow()
        db.session.commit()
        
        # Store user data in session
        session['user_id'] = uid
        session['email'] = email
        
        return jsonify({
            'success': True,
            'user': {
                'uid': uid,
                'email': email,
                'name': user.name
            }
        })
    
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return jsonify({'error': 'Invalid token', 'details': str(e)}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    """Clear session data on logout"""
    session.clear()
    return jsonify({'success': True})

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file uploads for authenticated users with VirusTotal scanning"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Check CSRF token
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return jsonify({'error': 'Invalid CSRF token'}), 403
    
    # Check if file part exists
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    
    file = request.files['file']
    
    # If user does not select file, browser may submit an empty file
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    description = request.form.get('description', '')
    
    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        filename = get_unique_filename(original_filename)
        file_path = os.path.join(config.UPLOAD_FOLDER, filename)
        
        try:
            # Save the file temporarily
            file.save(file_path)
            
            # Create file record in database with pending scan status
            file_upload = FileUpload(
                filename=filename,
                original_filename=original_filename,
                file_path=file_path,
                file_size=os.path.getsize(file_path),
                file_type=file.content_type if hasattr(file, 'content_type') else 'application/octet-stream',
                description=description,
                user_id=session['user_id'],
                is_scanned=False,
                is_safe=None
            )
            
            # Add file to database to get an ID
            db.session.add(file_upload)
            db.session.commit()
            
            # Initialize VirusTotal scanner
            scanner = VirusTotalScanner()
            
            # Scan the file
            logger.info(f"Scanning file: {original_filename}")
            is_safe, scan_results = scanner.scan_file(file_path)
            
            # Update file record with scan results
            file_upload.is_scanned = True
            file_upload.is_safe = is_safe
            file_upload.scan_date = datetime.datetime.utcnow()
            file_upload.scan_result = json.dumps(scan_results)
            
            # If file is malicious, delete it
            if not is_safe:
                logger.warning(f"Malicious file detected: {original_filename}")
                
                # Remove the file from the filesystem
                if os.path.exists(file_path):
                    os.remove(file_path)
                
                # Update file record to mark as deleted
                file_upload.file_path = None
                
                db.session.commit()
                
                return jsonify({
                    'success': False,
                    'error': 'Malicious file detected',
                    'scan_results': scan_results,
                    'file': file_upload.to_dict()
                }), 403
            
            # File is safe, commit the changes
            db.session.commit()
            
            return jsonify({
                'success': True,
                'file': file_upload.to_dict(),
                'scan_results': scan_results
            })
        
        except Exception as e:
            logger.exception(f"File upload error: {str(e)}")
            
            # Clean up the file if it exists
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
            
            return jsonify({'error': 'File upload failed', 'details': str(e)}), 500
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/api/files')
def get_files():
    """Get list of files for the authenticated user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        files = FileUpload.query.filter_by(user_id=session['user_id']).order_by(FileUpload.uploaded_at.desc()).all()
        return jsonify({
            'success': True,
            'files': [file.to_dict() for file in files]
        })
    
    except Exception as e:
        logger.error(f"Error fetching files: {str(e)}")
        return jsonify({'error': 'Failed to fetch files', 'details': str(e)}), 500

@app.route('/api/files/<int:file_id>')
def get_file(file_id):
    """Get details of a specific file"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        file = FileUpload.query.get(file_id)
        
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # Check if user owns this file
        if file.user_id != session['user_id']:
            return jsonify({'error': 'Access denied'}), 403
        
        return jsonify({
            'success': True,
            'file': file.to_dict()
        })
    
    except Exception as e:
        logger.error(f"Error fetching file: {str(e)}")
        return jsonify({'error': 'Failed to fetch file', 'details': str(e)}), 500

@app.route('/api/files/<int:file_id>/download')
def download_file(file_id):
    """Download a specific file"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        file = FileUpload.query.get(file_id)
        
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # Check if user owns this file
        if file.user_id != session['user_id']:
            return jsonify({'error': 'Access denied'}), 403
            
        # Check if file was detected as malicious or was deleted
        if file.is_safe is False or file.file_path is None:
            return jsonify({'error': 'This file was detected as malicious and cannot be downloaded'}), 403
            
        # Check if file exists on disk
        if not os.path.isfile(file.file_path):
            return jsonify({'error': 'File not found on server'}), 404
        
        return send_from_directory(
            os.path.dirname(file.file_path),
            os.path.basename(file.file_path),
            as_attachment=True,
            download_name=file.original_filename
        )
    
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        return jsonify({'error': 'Failed to download file', 'details': str(e)}), 500

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a specific file"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Check CSRF token
    data = request.get_json()
    csrf_token = data.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return jsonify({'error': 'Invalid CSRF token'}), 403
    
    try:
        file = FileUpload.query.get(file_id)
        
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # Check if user owns this file
        if file.user_id != session['user_id']:
            return jsonify({'error': 'Access denied'}), 403
        
        # Delete file from filesystem if it exists
        if file.file_path and os.path.isfile(file.file_path):
            try:
                os.remove(file.file_path)
            except Exception as e:
                logger.warning(f"Failed to delete file from filesystem: {str(e)}")
        
        # Delete file record from database
        db.session.delete(file)
        db.session.commit()
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error deleting file: {str(e)}")
        return jsonify({'error': 'Failed to delete file', 'details': str(e)}), 500

@app.route('/dashboard')
def dashboard():
    """Render dashboard for authenticated users"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    # Generate CSRF token
    csrf_token = generate_csrf_token()
    
    return render_template(
        'dashboard.html',
        csrf_token=csrf_token,
        user_email=session.get('email'),
        firebase_api_key=config.FIREBASE_API_KEY,
        firebase_auth_domain=config.FIREBASE_AUTH_DOMAIN,
        firebase_database_url=config.FIREBASE_DATABASE_URL,
        firebase_project_id=config.FIREBASE_PROJECT_ID,
        firebase_storage_bucket=config.FIREBASE_STORAGE_BUCKET,
        firebase_messaging_sender_id=config.FIREBASE_MESSAGING_SENDER_ID,
        firebase_app_id=config.FIREBASE_APP_ID,
        firebase_measurement_id=config.FIREBASE_MEASUREMENT_ID
    )

@app.route('/login')
def login():
    """Render login page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    return render_template(
        'login.html',
        firebase_api_key=config.FIREBASE_API_KEY,
        firebase_auth_domain=config.FIREBASE_AUTH_DOMAIN,
        firebase_database_url=config.FIREBASE_DATABASE_URL,
        firebase_project_id=config.FIREBASE_PROJECT_ID,
        firebase_storage_bucket=config.FIREBASE_STORAGE_BUCKET,
        firebase_messaging_sender_id=config.FIREBASE_MESSAGING_SENDER_ID,
        firebase_app_id=config.FIREBASE_APP_ID,
        firebase_measurement_id=config.FIREBASE_MEASUREMENT_ID
    )
