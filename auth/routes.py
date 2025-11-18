"""
Authentication routes: register, login, logout, verification, and biometric setup.
Handles user authentication flow and account verification.

FIXED VERSION - Database query issues resolved
"""

from flask import render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from datetime import datetime
import logging
from extensions import db
from sqlalchemy import or_

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Import blueprint (create if doesn't exist)
try:
    from auth import auth_bp
except ImportError:
    from flask import Blueprint
    auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
    logger.info("Created auth blueprint")

# Import forms with error handling
try:
    from auth.forms import (
        RegistrationForm, 
        LoginForm, 
        VerificationForm, 
        BiometricSetupForm, 
        SecurityQuestionRecoveryForm
    )
except ImportError as e:
    logger.error(f"Forms import error: {e}")
    # Create dummy forms if import fails (for debugging)
    from flask_wtf import FlaskForm
    RegistrationForm = LoginForm = VerificationForm = BiometricSetupForm = SecurityQuestionRecoveryForm = FlaskForm

# Import models with error handling
try:
    from models.user import User
except ImportError:
    try:
        from models import User
    except ImportError:
        logger.error("Could not import User model")
        User = None

try:
    from models.account import Account
except ImportError:
    try:
        from models import Account
    except ImportError:
        logger.warning("Could not import Account model")
        Account = None

try:
    from models.notification import Notification
except ImportError:
    try:
        from models import Notification
    except ImportError:
        logger.warning("Could not import Notification model")
        Notification = None

# Import config with error handling
try:
    from config import Config
except ImportError:
    logger.warning("Could not import Config, using defaults")
    class Config:
        DEFAULT_SECURITY_QUESTIONS = [
            "What is your mother's maiden name?",
            "What was the name of your first pet?",
            "What city were you born in?",
            "What is your favorite color?",
            "What was your first car?"
        ]


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    try:
        if current_user.is_authenticated:
            return redirect(url_for('user.dashboard'))
        
        form = RegistrationForm()
        
        # Populate security question dropdowns
        form.security_question_1.choices = [(q, q) for q in Config.DEFAULT_SECURITY_QUESTIONS]
        form.security_question_2.choices = [(q, q) for q in Config.DEFAULT_SECURITY_QUESTIONS]
        
        if form.validate_on_submit():
            # Create new user
            user = User(
                email=form.email.data.lower(),
                username=form.username.data.lower(),
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                phone=form.phone.data,
                date_of_birth=form.date_of_birth.data,
                address=form.address.data,
                security_question_1=form.security_question_1.data,
                security_answer_1=form.security_answer_1.data.lower(),
                security_question_2=form.security_question_2.data,
                security_answer_2=form.security_answer_2.data.lower(),
                security_question_3=form.security_question_3.data,
                security_answer_3=form.security_answer_3.data.lower()
            )
            user.set_password(form.password.data)
            
            # Generate verification code
            verification_code = user.generate_verification_code()
            
            db.session.add(user)
            db.session.commit()
            
            # In production, send email with verification code
            # For now, display it in flash message (development only)
            flash(f'Account created successfully! Your verification code is: {verification_code}', 'success')
            flash('Please check your email for the verification code.', 'info')
            
            # Store user_id in session for verification
            session['unverified_user_id'] = user.id
            
            return redirect(url_for('auth.verify'))
        
        return render_template('register.html', form=form)
        
    except Exception as e:
        logger.error(f"Registration error: {e}", exc_info=True)
        flash('An error occurred during registration. Please try again.', 'danger')
        return render_template('register.html', form=RegistrationForm())


@auth_bp.route('/verify', methods=['GET', 'POST'])
def verify():
    """Email verification route."""
    try:
        user_id = session.get('unverified_user_id')
        if not user_id:
            flash('Please register first.', 'warning')
            return redirect(url_for('auth.register'))
        
        # ✅ FIXED: Use db.session.get() instead of User.query.get()
        user = db.session.get(User, user_id)
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.register'))
        
        if user.is_verified:
            flash('Account already verified. Please login.', 'info')
            return redirect(url_for('auth.login'))
        
        form = VerificationForm()
        
        if form.validate_on_submit():
            if user.verify_code(form.verification_code.data):
                user.is_verified = True
                user.verification_code = None
                user.verification_code_expires = None
                
                # Create default savings account if Account model exists
                if Account:
                    account = Account(
                        account_number=Account.generate_account_number(),
                        account_type='savings',
                        account_name=f'{user.first_name} {user.last_name} - Savings',
                        user_id=user.id,
                        is_default=True,
                        is_active=False  # Requires admin approval
                    )
                    db.session.add(account)
                
                # Create welcome notification if Notification model exists
                if Notification:
                    notification = Notification(
                        user_id=user.id,
                        title='Welcome to Stanbic Bank Uganda!',
                        message='Your account has been created successfully. Your savings account is pending approval.',
                        notification_type='account',
                        priority='high'
                    )
                    db.session.add(notification)
                
                db.session.commit()
                
                session.pop('unverified_user_id', None)
                
                flash('Email verified successfully! Your account is now active. Please login.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid or expired verification code. Please try again.', 'danger')
        
        return render_template('verify.html', form=form, user=user)
        
    except Exception as e:
        logger.error(f"Verification error: {e}", exc_info=True)
        flash('An error occurred during verification. Please try again.', 'danger')
        return redirect(url_for('auth.register'))


@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification code."""
    try:
        user_id = session.get('unverified_user_id')
        if not user_id:
            return jsonify({'success': False, 'message': 'Session expired'}), 400
        
        # ✅ FIXED: Use db.session.get() instead of User.query.get()
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        verification_code = user.generate_verification_code()
        db.session.commit()
        
        # In production, send email here
        # For development, return code in response
        return jsonify({
            'success': True,
            'message': 'Verification code sent successfully',
            'code': verification_code  # Remove in production!
        })
        
    except Exception as e:
        logger.error(f"Resend verification error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Server error'}), 500


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login route - FIXED VERSION."""
    try:
        logger.debug("=== Login route accessed ===")
        logger.debug(f"Request method: {request.method}")
        logger.debug(f"Current user authenticated: {current_user.is_authenticated}")
        
        # Check if user is already authenticated
        if current_user.is_authenticated:
            logger.info(f"User {current_user.username} already authenticated")
            return redirect(url_for('user.dashboard'))
        
        # Create form instance
        form = LoginForm()
        logger.debug(f"Form created: {form}")
        
        # Handle GET request - render login page
        if request.method == 'GET':
            logger.debug("Rendering login page (GET request)")
            return render_template('login.html', form=form)
        
        # Handle POST request - process login
        logger.debug("Processing login form (POST request)")
        logger.debug(f"Form data received: email={request.form.get('email')}")
        
        if not form.validate_on_submit():
            logger.error(f"Form validation failed: {form.errors}")
            flash('Please correct the errors in the form.', 'danger')
            return render_template('login.html', form=form)
        
        logger.debug(f"Login form validated for: {form.email.data}")
        
        # ✅ FIXED: Use db.session.execute() with select() for SQLAlchemy 2.0
        try:
            from sqlalchemy import select
            
            # Query using SQLAlchemy 2.0 syntax
            stmt = select(User).where(
                or_(
                    User.email == form.email.data.lower(),
                    User.username == form.email.data.lower()
                )
            )
            user = db.session.execute(stmt).scalar_one_or_none()
            
            logger.debug(f"User lookup result: {user.username if user else 'None'}")
            
        except Exception as db_error:
            logger.error(f"Database error during user lookup: {db_error}", exc_info=True)
            flash('Database error. Please try again later.', 'danger')
            return render_template('login.html', form=form)
        
        if not user:
            logger.warning(f"User not found: {form.email.data}")
            flash('Invalid email/username or password.', 'danger')
            return render_template('login.html', form=form)
        
        if not user.check_password(form.password.data):
            logger.warning(f"Invalid password for user: {user.username}")
            flash('Invalid email/username or password.', 'danger')
            return render_template('login.html', form=form)
        
        logger.info(f"Password verified for user: {user.username}")
        
        # Check if email is verified
        if not user.is_verified:
            logger.warning(f"Unverified user login attempt: {user.username}")
            flash('Please verify your email before logging in.', 'warning')
            session['unverified_user_id'] = user.id
            return redirect(url_for('auth.verify'))
        
        # Check if account is active
        if not user.is_active:
            logger.warning(f"Inactive user login attempt: {user.username}")
            flash('Your account has been deactivated. Please contact support.', 'danger')
            return render_template('login.html', form=form)
        
        # Update last login
        try:
            user.last_login = datetime.utcnow()
            db.session.commit()
            logger.debug("Last login timestamp updated")
        except Exception as commit_error:
            logger.warning(f"Could not update last login: {commit_error}")
            db.session.rollback()
        
        # Log user in
        login_user(user, remember=form.remember_me.data)
        logger.info(f"✅ User {user.username} logged in successfully")
        
        flash(f'Welcome back, {user.first_name}!', 'success')
        
        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            logger.debug(f"Redirecting to next page: {next_page}")
            return redirect(next_page)
        
        # Redirect admin to admin panel
        if hasattr(user, 'is_admin') and user.is_admin:
            logger.debug("Redirecting admin to admin dashboard")
            return redirect(url_for('admin.dashboard'))
        
        logger.debug("Redirecting to user dashboard")
        return redirect(url_for('user.dashboard'))
        
    except Exception as e:
        logger.error(f"❌ CRITICAL LOGIN ERROR: {e}", exc_info=True)
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Error details: {str(e)}")
        
        db.session.rollback()
        
        flash('An error occurred during login. Please try again.', 'danger')
        
        # Try to render login page with empty form
        try:
            return render_template('login.html', form=LoginForm())
        except Exception as template_error:
            logger.error(f"Could not render login template: {template_error}", exc_info=True)
            # Return plain HTML error page as last resort
            return f"""
            <!DOCTYPE html>
            <html>
            <head><title>Login Error</title></head>
            <body>
                <h1>Login Error</h1>
                <p>Error: {str(e)}</p>
                <p>Error Type: {type(e).__name__}</p>
                <p>Please contact support or check the server logs.</p>
                <a href="/auth/login">Try Again</a>
            </body>
            </html>
            """, 500


@auth_bp.route('/biometric-login', methods=['POST'])
def biometric_login():
    """Handle biometric authentication login."""
    try:
        data = request.get_json()
        
        if not data or 'token' not in data or 'type' not in data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        biometric_token = data['token']
        biometric_type = data['type']
        
        # ✅ FIXED: Use db.session.execute() with select()
        from sqlalchemy import select
        
        # Find user by biometric token
        if biometric_type == 'fingerprint':
            stmt = select(User).where(User.fingerprint_token == biometric_token)
        elif biometric_type == 'face':
            stmt = select(User).where(User.face_token == biometric_token)
        else:
            return jsonify({'success': False, 'message': 'Invalid biometric type'}), 400
        
        user = db.session.execute(stmt).scalar_one_or_none()
        
        if user and user.biometric_enabled and user.is_active and user.is_verified:
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log user in
            login_user(user, remember=True)
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'redirect': url_for('user.dashboard')
            })
        
        return jsonify({'success': False, 'message': 'Biometric authentication failed'}), 401
        
    except Exception as e:
        logger.error(f"Biometric login error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Server error'}), 500


@auth_bp.route('/setup-biometric', methods=['GET', 'POST'])
@login_required
def setup_biometric():
    """Setup biometric authentication."""
    try:
        form = BiometricSetupForm()
        
        # Handle GET request - render the template
        if request.method == 'GET':
            return render_template('setup_biometric.html', form=form, user=current_user)
        
        # Handle POST request - process form submission
        if form.validate_on_submit():
            # Check if it's an AJAX request
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                if current_user.check_password(form.password.data):
                    token = current_user.enable_biometric(form.biometric_type.data)
                    db.session.commit()
                    
                    return jsonify({
                        'success': True,
                        'message': 'Biometric authentication enabled successfully',
                        'token': token,
                        'type': form.biometric_type.data
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': 'Invalid password'
                    }), 401
            else:
                # Handle regular form submission
                if current_user.check_password(form.password.data):
                    token = current_user.enable_biometric(form.biometric_type.data)
                    db.session.commit()
                    
                    flash(f'{form.biometric_type.data.title()} authentication enabled successfully!', 'success')
                    return redirect(url_for('user.dashboard'))
                else:
                    flash('Invalid password. Please try again.', 'danger')
        
        return render_template('setup_biometric.html', form=form, user=current_user)
        
    except Exception as e:
        logger.error(f"Setup biometric error: {e}", exc_info=True)
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('user.dashboard'))


@auth_bp.route('/disable-biometric', methods=['POST'])
@login_required
def disable_biometric():
    """Disable biometric authentication."""
    try:
        data = request.get_json()
        
        if not data or 'password' not in data:
            return jsonify({'success': False, 'message': 'Password required'}), 400
        
        if current_user.check_password(data['password']):
            current_user.biometric_enabled = False
            current_user.fingerprint_token = None
            current_user.face_token = None
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Biometric authentication disabled'
            })
        
        return jsonify({'success': False, 'message': 'Invalid password'}), 401
        
    except Exception as e:
        logger.error(f"Disable biometric error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Server error'}), 500


@auth_bp.route('/recover-account', methods=['GET', 'POST'])
def recover_account():
    """Account recovery using security questions."""
    try:
        form = SecurityQuestionRecoveryForm()
        user = None
        
        if request.method == 'GET' and request.args.get('email'):
            # Display security questions for the email
            email = request.args.get('email')
            # ✅ FIXED: Use db.session.execute() with select()
            from sqlalchemy import select
            stmt = select(User).where(User.email == email.lower())
            user = db.session.execute(stmt).scalar_one_or_none()
            
            if not user:
                flash('Email not found in our records.', 'danger')
                return redirect(url_for('auth.recover_account'))
        
        if form.validate_on_submit():
            # ✅ FIXED: Use db.session.execute() with select()
            from sqlalchemy import select
            stmt = select(User).where(User.email == form.email.data.lower())
            user = db.session.execute(stmt).scalar_one_or_none()
            
            if user:
                # Verify all three security answers
                if (user.security_answer_1 == form.security_answer_1.data.lower() and
                    user.security_answer_2 == form.security_answer_2.data.lower() and
                    user.security_answer_3 == form.security_answer_3.data.lower()):
                    
                    # Update password
                    user.set_password(form.new_password.data)
                    db.session.commit()
                    
                    flash('Password reset successfully! You can now login with your new password.', 'success')
                    return redirect(url_for('auth.login'))
                else:
                    flash('Security answers do not match. Please try again.', 'danger')
            else:
                flash('Email not found in our records.', 'danger')
        
        return render_template('recover_account.html', form=form, user=user)
        
    except Exception as e:
        logger.error(f"Account recovery error: {e}", exc_info=True)
        flash('An error occurred. Please try again.', 'danger')
        return render_template('recover_account.html', form=SecurityQuestionRecoveryForm())


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout route."""
    try:
        username = current_user.username if hasattr(current_user, 'username') else 'User'
        logout_user()
        session.clear()
        logger.info(f"{username} logged out")
        flash('You have been logged out successfully.', 'info')
        return redirect(url_for('auth.login'))
    except Exception as e:
        logger.error(f"Logout error: {e}", exc_info=True)
        return redirect(url_for('auth.login'))


# Health check endpoint
@auth_bp.route('/health')
def health_check():
    """Check if auth service is running"""
    return jsonify({
        'status': 'ok',
        'service': 'authentication',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


# Error handlers
@auth_bp.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {error}")
    flash('Page not found', 'warning')
    return redirect(url_for('auth.login'))


@auth_bp.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}", exc_info=True)
    db.session.rollback()
    flash('A server error occurred. Please try again later.', 'danger')
    return redirect(url_for('auth.login'))