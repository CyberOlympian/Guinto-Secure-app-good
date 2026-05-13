"""
Comprehensive unit tests for user management service
Tests cover validation logic, API endpoints, and security constraints
"""
import pytest
import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.main import app, validate_email, validate_username, sanitize_input

@pytest.fixture
def client():
    """Create a test client for the Flask application"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

class TestHealthEndpoint:
    """Tests for health check endpoint"""
    
    def test_health_check_status(self, client):
        """Test health endpoint returns 200 OK"""
        response = client.get('/health')
        assert response.status_code == 200
    
    def test_health_check_content(self, client):
        """Test health endpoint returns correct structure"""
        response = client.get('/health')
        data = response.get_json()
        assert data['status'] == 'healthy'
        assert data['service'] == 'user-management-api'
        assert 'version' in data
        assert 'timestamp' in data

class TestEmailValidation:
    """Tests for email validation function"""
    
    def test_valid_emails(self):
        """Test that valid email formats pass"""
        valid_emails = [
            'user@example.com',
            'admin@company.org',
            'test.user@domain.co.uk',
            'first.last+tag@example.com',
            'user123@test-domain.com'
        ]
        for email in valid_emails:
            assert validate_email(email) == True, f"Failed for {email}"
    
    def test_invalid_emails(self):
        """Test that invalid email formats fail"""
        invalid_emails = [
            'notanemail',
            'missing.at.symbol.com',
            '@nodomain.com',
            'user@',
            'user @example.com',  # space
            'user@.com',
            '',
            None,
            123,  # non-string type
            'user@domain',  # missing TLD
            'user..name@example.com'  # double dots
        ]
        for email in invalid_emails:
            assert validate_email(email) == False, f"Should fail for {email}"

class TestUsernameValidation:
    """Tests for username validation function"""
    
    def test_valid_usernames(self):
        """Test that valid usernames pass"""
        valid_usernames = [
            'john_doe',
            'user123',
            'test-user',
            'abc',  # minimum length
            'a' * 32  # maximum length
        ]
        for username in valid_usernames:
            assert validate_username(username) == True, f"Failed for {username}"
    
    def test_invalid_usernames(self):
        """Test that invalid usernames fail"""
        invalid_usernames = [
            'ab',  # too short
            'a' * 33,  # too long
            '-user',  # starts with hyphen
            '_user',  # starts with underscore
            'user@name',  # invalid character
            'user name',  # space
            '',
            None,
            'user<script>',  # XSS attempt
            "user'; DROP TABLE--"  # SQL injection attempt
        ]
        for username in invalid_usernames:
            assert validate_username(username) == False, f"Should fail for {username}"

class TestSanitization:
    """Tests for input sanitization"""
    
    def test_sanitize_removes_dangerous_chars(self):
        """Test that dangerous characters are removed"""
        dangerous_inputs = [
            ('<script>alert("xss")</script>', 'scriptalert"xss"/script'),
            ('user"; DROP TABLE users;--', 'user DROP TABLE users--'),
            ('test<>value', 'testvalue'),
            ('data&param=value', 'dataparamvalue')
        ]
        for input_str, expected in dangerous_inputs:
            result = sanitize_input(input_str)
            assert result == expected, f"Failed to sanitize {input_str}"

class TestCreateUserEndpoint:
    """Tests for user creation endpoint"""
    
    def test_create_user_success(self, client):
        """Test successful user creation"""
        response = client.post('/api/v1/users',
                              json={'email': 'test@example.com', 'username': 'testuser'},
                              content_type='application/json')
        assert response.status_code == 201
        data = response.get_json()
        assert data['message'] == 'User created successfully'
        assert data['user']['email'] == 'test@example.com'
        assert data['user']['username'] == 'testuser'
    
    def test_create_user_invalid_email(self, client):
        """Test user creation with invalid email"""
        response = client.post('/api/v1/users',
                              json={'email': 'invalid-email', 'username': 'testuser'},
                              content_type='application/json')
        assert response.status_code == 400
        data = response.get_json()
        assert 'Invalid email format' in data['error']
    
    def test_create_user_invalid_username(self, client):
        """Test user creation with invalid username"""
        response = client.post('/api/v1/users',
                              json={'email': 'test@example.com', 'username': 'ab'},
                              content_type='application/json')
        assert response.status_code == 400
        data = response.get_json()
        assert 'Invalid username format' in data['error']
    
    def test_create_user_missing_fields(self, client):
        """Test user creation with missing required fields"""
        response = client.post('/api/v1/users',
                              json={'email': 'test@example.com'},
                              content_type='application/json')
        assert response.status_code == 400
    
    def test_create_user_wrong_content_type(self, client):
        """Test user creation with wrong content type"""
        response = client.post('/api/v1/users',
                              data='not json',
                              content_type='text/plain')
        assert response.status_code == 400
        data = response.get_json()
        assert 'Content-Type must be application/json' in data['error']
    
    def test_create_user_invalid_json(self, client):
        """Test user creation with invalid JSON"""
        response = client.post('/api/v1/users',
                              data='{"invalid": json}',
                              content_type='application/json')
        assert response.status_code == 400

class TestGetUserEndpoint:
    """Tests for get user endpoint"""
    
    def test_get_user_success(self, client):
        """Test successful user retrieval"""
        response = client.get('/api/v1/users/testuser')
        assert response.status_code == 200
        data = response.get_json()
        assert data['username'] == 'testuser'
        assert 'email' in data
    
    def test_get_user_invalid_username(self, client):
        """Test user retrieval with invalid username"""
        response = client.get('/api/v1/users/invalid@user')
        assert response.status_code == 400
        data = response.get_json()
        assert 'Invalid username format' in data['error']

class TestValidateEmailEndpoint:
    """Tests for email validation endpoint"""
    
    def test_validate_email_valid(self, client):
        """Test email validation endpoint with valid email"""
        response = client.post('/api/v1/validate/email',
                              json={'email': 'test@example.com'},
                              content_type='application/json')
        assert response.status_code == 200
        data = response.get_json()
        assert data['valid'] == True
    
    def test_validate_email_invalid(self, client):
        """Test email validation endpoint with invalid email"""
        response = client.post('/api/v1/validate/email',
                              json={'email': 'not-an-email'},
                              content_type='application/json')
        assert response.status_code == 200
        data = response.get_json()
        assert data['valid'] == False

class TestErrorHandlers:
    """Tests for error handlers"""
    
    def test_404_handler(self, client):
        """Test 404 error handler"""
        response = client.get('/nonexistent/endpoint')
        assert response.status_code == 404
        data = response.get_json()
        assert 'Resource not found' in data['error']
