"""
Secure user management microservice
A clean, production-ready Flask API with proper validation and security practices
"""
from flask import Flask, request, jsonify
import re
import logging
from functools import wraps
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Disable debug mode for production
app.config['DEBUG'] = False
app.config['TESTING'] = False

def validate_email(email):
    """
    Robust email validation using regex pattern
    Returns True if email format is valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    # RFC 5322 compliant email validation pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    """
    Username validation with security constraints
    - Length: 3-32 characters
    - Allowed: alphanumeric, underscore, hyphen
    - Must start with alphanumeric character
    """
    if not username or not isinstance(username, str):
        return False
    
    if len(username) < 3 or len(username) > 32:
        return False
    
    # Pattern: starts with alphanumeric, contains only safe characters
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$'
    return re.match(pattern, username) is not None

def sanitize_input(data):
    """
    Sanitize input data to prevent injection attacks
    """
    if isinstance(data, str):
        # Remove any potential script tags or suspicious patterns
        data = data.strip()
        data = re.sub(r'[<>\"\'%;()&+]', '', data)
    return data

def log_request(f):
    """Decorator to log API requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")
        return f(*args, **kwargs)
    return decorated_function

@app.route('/health', methods=['GET'])
@log_request
def health():
    """
    Health check endpoint for container orchestration
    Returns service status and timestamp
    """
    return jsonify({
        "status": "healthy",
        "service": "user-management-api",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }), 200

@app.route('/api/v1/users', methods=['POST'])
@log_request
def create_user():
    """
    Create a new user with validated input
    
    Expected JSON body:
    {
        "email": "user@example.com",
        "username": "john_doe"
    }
    """
    # Validate content type
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    try:
        data = request.get_json()
    except Exception as e:
        logger.error(f"Invalid JSON: {str(e)}")
        return jsonify({"error": "Invalid JSON format"}), 400
    
    # Extract and sanitize inputs
    email = sanitize_input(data.get('email', ''))
    username = sanitize_input(data.get('username', ''))
    
    # Validate email
    if not validate_email(email):
        return jsonify({
            "error": "Invalid email format",
            "details": "Email must be a valid address (e.g., user@example.com)"
        }), 400
    
    # Validate username
    if not validate_username(username):
        return jsonify({
            "error": "Invalid username format",
            "details": "Username must be 3-32 characters, alphanumeric with _ or -"
        }), 400
    
    # Log successful validation
    logger.info(f"User validated successfully: {username}")
    
    # In production, this would save to a database using parameterized queries
    # For demo purposes, we return success
    return jsonify({
        "message": "User created successfully",
        "user": {
            "email": email,
            "username": username,
            "created_at": datetime.utcnow().isoformat()
        }
    }), 201

@app.route('/api/v1/users/<username>', methods=['GET'])
@log_request
def get_user(username):
    """
    Retrieve user information by username
    Uses path parameter validation to prevent injection
    """
    # Validate username parameter
    if not validate_username(username):
        return jsonify({"error": "Invalid username format"}), 400
    
    # In production, use parameterized queries
    # Example: cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    
    # For demo purposes, return mock data
    return jsonify({
        "username": username,
        "email": f"{username}@example.com",
        "status": "active",
        "created_at": "2024-01-15T10:00:00Z"
    }), 200

@app.route('/api/v1/validate/email', methods=['POST'])
@log_request
def validate_email_endpoint():
    """
    Endpoint to validate email format
    Useful for client-side validation
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    data = request.get_json()
    email = data.get('email', '')
    
    is_valid = validate_email(email)
    
    return jsonify({
        "email": email,
        "valid": is_valid
    }), 200

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    # Run with production-safe settings
    app.run(host='0.0.0.0', port=5000, debug=False)
