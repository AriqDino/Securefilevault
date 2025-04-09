import os
import uuid
import hashlib
import time
from flask import session, request
import config

def generate_csrf_token():
    """
    Generate a CSRF token and store it in the session
    
    Returns:
        str: The generated CSRF token
    """
    if 'csrf_token' not in session:
        session['csrf_token'] = str(uuid.uuid4())
    return session['csrf_token']

def validate_csrf_token(token):
    """
    Validate a CSRF token against the one stored in the session
    
    Args:
        token: The CSRF token to validate
        
    Returns:
        bool: True if the token is valid, False otherwise
    """
    stored_token = session.get('csrf_token')
    return stored_token and stored_token == token

def get_secure_headers():
    """
    Generate secure HTTP headers to protect against common web vulnerabilities
    
    Returns:
        dict: Dictionary of security headers
    """
    return {
        'Content-Security-Policy': "default-src 'self'; script-src 'self' https://www.gstatic.com/ https://cdn.jsdelivr.net/ https://cdn.replit.com/ 'unsafe-inline'; style-src 'self' https://cdn.replit.com/ https://cdn.jsdelivr.net/ 'unsafe-inline'; img-src 'self' data: https://www.gstatic.com/; font-src 'self' https://cdn.jsdelivr.net/; connect-src 'self' https://*.googleapis.com https://identitytoolkit.googleapis.com; frame-src https://filefault-38b0e.firebaseapp.com",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }

def sanitize_input(input_str):
    """
    Sanitize input string to prevent XSS attacks
    
    Args:
        input_str: The string to sanitize
        
    Returns:
        str: The sanitized string
    """
    if input_str is None:
        return None
    
    # Replace potentially dangerous characters
    sanitized = input_str.replace('<', '&lt;').replace('>', '&gt;')
    
    return sanitized
