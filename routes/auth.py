from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from models.user import User, db
import re

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('login.html')
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password are required'
            }), 400
        
        # Find user by username or email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'Invalid credentials'
            }), 401
        
        if not user.is_active:
            return jsonify({
                'success': False,
                'error': 'Account is inactive. Please contact support.'
            }), 403
        
        # Verify password
        if not check_password_hash(user.password_hash, password):
            return jsonify({
                'success': False,
                'error': 'Invalid credentials'
            }), 401
        
        # Log user in
        login_user(user, remember=data.get('remember', False))
        
        # Check if biometrics are enabled but not setup
        redirect_url = '/dashboard'
        if not user.biometric_enabled:
            redirect_url = '/biometrics/setup'
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'redirect': redirect_url,
            'biometric_enabled': user.biometric_enabled
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'An error occurred during login'
        }), 500

@auth_bp.route('/biometric_login', methods=['POST'])
def biometric_login():
    """Complete login after biometric verification"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({
                'success': False,
                'error': 'User ID required'
            }), 400
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        if not user.is_active:
            return jsonify({
                'success': False,
                'error': 'Account is inactive'
            }), 403
        
        if not user.biometric_enabled:
            return jsonify({
                'success': False,
                'error': 'Biometric authentication not enabled'
            }), 403
        
        # Log user in
        login_user(user, remember=True)
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'redirect': '/dashboard'
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'An error occurred during login'
        }), 500

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('register.html')
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'username', 'password', 'first_name', 'last_name', 'phone']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'error': f'{field.replace("_", " ").title()} is required'
                }), 400
        
        email = data['email'].strip().lower()
        username = data['username'].strip().lower()
        password = data['password']
        first_name = data['first_name'].strip()
        last_name = data['last_name'].strip()
        phone = data['phone'].strip()
        
        # Validate email
        if not validate_email(email):
            return jsonify({
                'success': False,
                'error': 'Invalid email format'
            }), 400
        
        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({
                'success': False,
                'error': 'Email already registered'
            }), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({
                'success': False,
                'error': 'Username already taken'
            }), 400
        
        # Create new user
        user = User(
            email=email,
            username=username,
            password_hash=generate_password_hash(password),
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            is_active=True,
            biometric_enabled=False
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log user in
        login_user(user)
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'redirect': '/biometrics/setup'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': 'An error occurred during registration'
        }), 500

@auth_bp.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    """Handle user logout"""
    logout_user()
    return redirect(url_for('auth.login'))

@auth_bp.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({
                'success': False,
                'error': 'Current and new password are required'
            }), 400
        
        user = current_user
        
        # Verify current password
        if not check_password_hash(user.password_hash, current_password):
            return jsonify({
                'success': False,
                'error': 'Current password is incorrect'
            }), 401
        
        # Validate new password
        is_valid, message = validate_password(new_password)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
        # Update password
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': 'An error occurred while changing password'
        }), 500

@auth_bp.route('/check_username', methods=['POST'])
def check_username():
    """Check if username is available"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip().lower()
        
        if not username:
            return jsonify({
                'available': False,
                'error': 'Username is required'
            })
        
        exists = User.query.filter_by(username=username).first() is not None
        
        return jsonify({
            'available': not exists
        })
    
    except Exception as e:
        return jsonify({
            'available': False,
            'error': 'An error occurred'
        }), 500

@auth_bp.route('/check_email', methods=['POST'])
def check_email():
    """Check if email is available"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({
                'available': False,
                'error': 'Email is required'
            })
        
        if not validate_email(email):
            return jsonify({
                'available': False,
                'error': 'Invalid email format'
            })
        
        exists = User.query.filter_by(email=email).first() is not None
        
        return jsonify({
            'available': not exists
        })
    
    except Exception as e:
        return jsonify({
            'available': False,
            'error': 'An error occurred'
        }), 500