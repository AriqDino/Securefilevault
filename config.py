import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database configuration
SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///files.db")
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Firebase configuration
FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY", "AIzaSyDpQM0gWq1t6CuTyvtuO1FkiiaA5gv9FEg")
FIREBASE_AUTH_DOMAIN = os.environ.get("FIREBASE_AUTH_DOMAIN", "filefault-38b0e.firebaseapp.com")
FIREBASE_DATABASE_URL = os.environ.get("FIREBASE_DATABASE_URL", "https://filefault-38b0e-default-rtdb.firebaseio.com")
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "filefault-38b0e")
FIREBASE_STORAGE_BUCKET = os.environ.get("FIREBASE_STORAGE_BUCKET", "filefault-38b0e.firebasestorage.app")
FIREBASE_MESSAGING_SENDER_ID = os.environ.get("FIREBASE_MESSAGING_SENDER_ID", "745818373800")
FIREBASE_APP_ID = os.environ.get("FIREBASE_APP_ID", "1:745818373800:web:ea45f3763e6770a1588c9d")
FIREBASE_MEASUREMENT_ID = os.environ.get("FIREBASE_MEASUREMENT_ID", "G-4V61CK85Q2")

# File upload configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size

# Security configuration
SESSION_SECRET = os.environ.get("SESSION_SECRET", "secure_secret_key_for_session")
CSRF_TOKEN_SECRET = os.environ.get("CSRF_TOKEN_SECRET", "secure_secret_for_csrf_token")
