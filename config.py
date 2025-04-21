import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database configuration
SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///files.db")
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_recycle": 300,  # Recycle connections every 5 minutes
    "pool_pre_ping": True,  # Test connection before using
    "pool_size": 10,  # Maximum number of connections to keep
    "max_overflow": 20,  # Maximum number of connections to create beyond pool_size
    "pool_timeout": 30,  # Timeout for getting a connection from the pool
}

# Firebase configuration
FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY")
FIREBASE_AUTH_DOMAIN = os.environ.get("FIREBASE_AUTH_DOMAIN")
FIREBASE_DATABASE_URL = os.environ.get("FIREBASE_DATABASE_URL")
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID")
FIREBASE_STORAGE_BUCKET = os.environ.get("FIREBASE_STORAGE_BUCKET")
FIREBASE_MESSAGING_SENDER_ID = os.environ.get("FIREBASE_MESSAGING_SENDER_ID")
FIREBASE_APP_ID = os.environ.get("FIREBASE_APP_ID")
FIREBASE_MEASUREMENT_ID = os.environ.get("FIREBASE_MEASUREMENT_ID")

# File upload configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size

# Security configuration
SESSION_SECRET = os.environ.get("SESSION_SECRET")
CSRF_TOKEN_SECRET = os.environ.get("CSRF_TOKEN_SECRET")

# Session configuration
PERMANENT_SESSION_LIFETIME = 1800  # 30 menit dalam detik
SESSION_COOKIE_SECURE = True  # Hanya kirim cookie melalui HTTPS
SESSION_COOKIE_HTTPONLY = True  # Tidak dapat diakses melalui JavaScript
SESSION_COOKIE_SAMESITE = 'Lax'  # Melindungi dari CSRF
