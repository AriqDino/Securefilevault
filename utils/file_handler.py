import os
import uuid
from werkzeug.utils import secure_filename
from config import ALLOWED_EXTENSIONS, UPLOAD_FOLDER
import datetime

def allowed_file(filename):
    """
    Check if the file extension is allowed
    
    Args:
        filename: The name of the file to check
        
    Returns:
        bool: True if the file extension is allowed, False otherwise
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_unique_filename(filename):
    """
    Generate a unique filename to prevent overwrites
    
    Args:
        filename: Original filename
        
    Returns:
        str: Unique filename
    """
    # Secure the filename first
    secure_name = secure_filename(filename)
    
    # Split filename and extension
    name, ext = os.path.splitext(secure_name)
    
    # Generate unique name with timestamp and uuid
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    unique_id = str(uuid.uuid4().hex[:8])
    
    return f"{name}_{timestamp}_{unique_id}{ext}"

def get_file_size_str(size_in_bytes):
    """
    Convert file size from bytes to human-readable format
    
    Args:
        size_in_bytes: File size in bytes
        
    Returns:
        str: Human-readable file size
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024 or unit == 'GB':
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024
