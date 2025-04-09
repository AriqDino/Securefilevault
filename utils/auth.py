import os
import requests
import json
import logging
from functools import wraps
from flask import session, redirect, url_for, jsonify

logger = logging.getLogger(__name__)

def verify_firebase_token(id_token):
    """
    Verify Firebase ID token and extract user data
    
    This function uses Firebase Auth REST API to verify token
    (Alternative to using firebase_admin SDK)
    """
    api_key = os.environ.get("FIREBASE_API_KEY", "AIzaSyDpQM0gWq1t6CuTyvtuO1FkiiaA5gv9FEg")
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
    
    payload = {
        "idToken": id_token
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code != 200:
        logger.error(f"Firebase token verification failed: {response.text}")
        raise Exception("Invalid token")
    
    data = response.json()
    
    if "users" not in data or len(data["users"]) == 0:
        raise Exception("User not found")
    
    user = data["users"][0]
    
    user_data = {
        "uid": user["localId"],
        "email": user["email"],
    }
    
    # Add additional fields if available
    if "displayName" in user:
        user_data["name"] = user["displayName"]
    
    return user_data

def login_required(f):
    """
    Decorator for views that require login
    Redirects to login page if user is not authenticated
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def api_login_required(f):
    """
    Decorator for API endpoints that require login
    Returns 401 Unauthorized if user is not authenticated
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function
