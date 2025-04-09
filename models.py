from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    """User model for storing user data"""
    id = db.Column(db.String(128), primary_key=True)  # Firebase UID
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    files = db.relationship('FileUpload', backref='owner', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.email}>'

class FileUpload(db.Model):
    """File upload model for storing file metadata"""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    file_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.String(128), db.ForeignKey('user.id'), nullable=False)
    
    # Virus scan status fields
    is_scanned = db.Column(db.Boolean, default=False)
    is_safe = db.Column(db.Boolean, nullable=True)
    scan_date = db.Column(db.DateTime, nullable=True)
    scan_result = db.Column(db.Text, nullable=True)  # JSON string with detailed scan results
    
    def __repr__(self):
        return f'<FileUpload {self.original_filename}>'
    
    def to_dict(self):
        """Convert object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'description': self.description,
            'uploaded_at': self.uploaded_at.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': self.user_id,
            'is_scanned': self.is_scanned,
            'is_safe': self.is_safe,
            'scan_date': self.scan_date.strftime('%Y-%m-%d %H:%M:%S') if self.scan_date else None,
            'scan_result': self.scan_result,
            'scan_status': self._get_scan_status()
        }
    
    def _get_scan_status(self):
        """Helper to get human-readable scan status"""
        if not self.is_scanned:
            return "Pending"
        elif self.is_safe:
            return "Clean"
        elif self.is_safe is False:  # Explicitly False, not None
            return "Malicious"
        else:
            return "Unknown"
