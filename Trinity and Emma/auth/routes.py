"""
Authentication routes: register, login, logout, verification, and biometric setup.
Handles user authentication flow and account verification.
"""

from flask import render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from auth import auth_bp
from auth.forms import RegistrationForm, LoginForm, VerificationForm, BiometricSetupForm, SecurityQuestionRecoveryForm
from models.user import User
from models.account import Account
from models.notification import Notification
from app import db
from config import Config
from datetime import datetime

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
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


@auth_bp.route('/verify', methods=['GET', 'POST'])
def verify():
    """Email verification route."""
    user_id = session.get('unverified_user_id')
    if not user_id:
        flash('Please register first.', 'warning')
        return redirect(url_for('auth.register'))
    
    user = User.query.get(user_id)
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
            
            # Create default savings account
            account = Account(
                account_number=Account.generate_account_number(),
                account_type='savings',
                account_name=f'{user.first_name} {user.last_name} - Savings',
                user_id=user.id,
                is_default=True,
                is_active=False  # Requires admin approval
            )
            
            db.session.add(account)
            
            # Create welcome notification
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


@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification code."""
    user_id = session.get('unverified_user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Session expired'}), 400
    
    user = User.query.get(user_id)
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


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        return redirect(url_for('user.dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        # Try to find user by email or username
        user = User.query.filter(
            (User.email == form.email.data.lower()) | 
            (User.username == form.email.data.lower())
        ).first()
        
        if user and user.check_password(form.password.data):
            if not user.is_verified:
                flash('Please verify your email before logging in.', 'warning')
                session['unverified_user_id'] = user.id
                return redirect(url_for('auth.verify'))
            
            if not user.is_active:
                flash('Your account has been deactivated. Please contact support.', 'danger')
                return redirect(url_for('auth.login'))
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log user in
            login_user(user, remember=form.remember_me.data)
            
            flash(f'Welcome back, {user.first_name}!', 'success')
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            
            # Redirect admin to admin panel
            if user.is_admin:
                return redirect(url_for('admin.dashboard'))
            
            return redirect(url_for('user.dashboard'))
        else:
            flash('Invalid email/username or password. Please try again.', 'danger')
    
    return render_template('login.html', form=form)


@auth_bp.route('/biometric-login', methods=['POST'])
def biometric_login():
    """Handle biometric authentication login."""
    data = request.get_json()
    
    if not data or 'token' not in data or 'type' not in data:
        return jsonify({'success': False, 'message': 'Invalid request'}), 400
    
    biometric_token = data['token']
    biometric_type = data['type']
    
    # Find user by biometric token
    if biometric_type == 'fingerprint':
        user = User.query.filter_by(fingerprint_token=biometric_token).first()
    elif biometric_type == 'face':
        user = User.query.filter_by(face_token=biometric_token).first()
    else:
        return jsonify({'success': False, 'message': 'Invalid biometric type'}), 400
    
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


@auth_bp.route('/setup-biometric', methods=['GET', 'POST'])
@login_required
def setup_biometric():
    """Setup biometric authentication."""
    form = BiometricSetupForm()
    
    if form.validate_on_submit():
        if current_user.check_password(form.password.data):
            token = current_user.enable_biometric(form.biometric_type.data)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Biometric authentication enabled',
                'token': token,
                'type': form.biometric_type.data
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid password'
            }), 401
    
    return render_template('setup_biometric.html', form=form)


@auth_bp.route('/recover-account', methods=['GET', 'POST'])
def recover_account():
    """Account recovery using security questions."""
    form = SecurityQuestionRecoveryForm()
    user = None
    
    if request.method == 'GET' and request.args.get('email'):
        # Display security questions for the email
        email = request.args.get('email')
        user = User.query.filter_by(email=email.lower()).first()
        if not user:
            flash('Email not found in our records.', 'danger')
            return redirect(url_for('auth.recover_account'))
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        
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


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout route."""
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))