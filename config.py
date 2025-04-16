import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database configuration
SQLALCHEMY_DATABASE_URI = "sqlite:///files.db"  # Local SQLite database
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
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
