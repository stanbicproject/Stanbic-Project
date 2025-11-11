"""
WTForms for authentication: registration, login, and verification.
Includes validation for email, password strength, and security questions.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, DateField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Regexp
from models.user import User
import re

class RegistrationForm(FlaskForm):
    """User registration form."""
    
    # Personal information
    first_name = StringField('First Name', validators=[
        DataRequired(message='First name is required'),
        Length(min=2, max=50, message='First name must be between 2 and 50 characters')
    ])
    
    last_name = StringField('Last Name', validators=[
        DataRequired(message='Last name is required'),
        Length(min=2, max=50, message='Last name must be between 2 and 50 characters')
    ])
    
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=80, message='Username must be between 3 and 80 characters'),
        Regexp('^[A-Za-z0-9_]+$', message='Username must contain only letters, numbers, and underscores')
    ])
    
    phone = StringField('Phone Number', validators=[
        DataRequired(message='Phone number is required'),
        Regexp('^[0-9+\-\s()]+$', message='Invalid phone number format')
    ])
    
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d', validators=[
        DataRequired(message='Date of birth is required')
    ])
    
    address = TextAreaField('Address', validators=[
        Length(max=200, message='Address must be less than 200 characters')
    ])
    
    # Password
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])
    
    # Security Questions (2 admin-set from dropdown + 1 user-defined)
    security_question_1 = SelectField('Security Question 1', validators=[
        DataRequired(message='Please select a security question')
    ])
    
    security_answer_1 = StringField('Answer 1', validators=[
        DataRequired(message='Please provide an answer'),
        Length(min=2, max=200)
    ])
    
    security_question_2 = SelectField('Security Question 2', validators=[
        DataRequired(message='Please select a security question')
    ])
    
    security_answer_2 = StringField('Answer 2', validators=[
        DataRequired(message='Please provide an answer'),
        Length(min=2, max=200)
    ])
    
    security_question_3 = StringField('Your Custom Security Question', validators=[
        DataRequired(message='Please create your own security question'),
        Length(min=10, max=200, message='Question must be between 10 and 200 characters')
    ])
    
    security_answer_3 = StringField('Answer to Your Question', validators=[
        DataRequired(message='Please provide an answer'),
        Length(min=2, max=200)
    ])
    
    # Terms and conditions
    accept_terms = BooleanField('I accept the Terms and Conditions', validators=[
        DataRequired(message='You must accept the terms and conditions')
    ])
    
    def validate_email(self, email):
        """Check if email already exists."""
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('This email is already registered. Please use a different email or login.')
    
    def validate_username(self, username):
        """Check if username already exists."""
        user = User.query.filter_by(username=username.data.lower()).first()
        if user:
            raise ValidationError('This username is taken. Please choose a different username.')
    
    def validate_password(self, password):
        """Validate password strength."""
        pwd = password.data
        if not re.search(r'[A-Z]', pwd):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', pwd):
            raise ValidationError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', pwd):
            raise ValidationError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd):
            raise ValidationError('Password must contain at least one special character')


class LoginForm(FlaskForm):
    """User login form."""
    
    email = StringField('Email or Username', validators=[
        DataRequired(message='Email or username is required')
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])
    
    remember_me = BooleanField('Remember Me')


class VerificationForm(FlaskForm):
    """Email verification code form."""
    
    verification_code = StringField('Verification Code', validators=[
        DataRequired(message='Verification code is required'),
        Length(min=6, max=6, message='Verification code must be 6 digits')
    ])


class BiometricSetupForm(FlaskForm):
    """Form for setting up biometric authentication."""
    
    biometric_type = SelectField('Biometric Type', choices=[
        ('fingerprint', 'Fingerprint'),
        ('face', 'Face Recognition')
    ], validators=[DataRequired()])
    
    password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Password is required for security')
    ])


class SecurityQuestionRecoveryForm(FlaskForm):
    """Form for account recovery using security questions."""
    
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    
    security_answer_1 = StringField('Answer to Security Question 1', validators=[
        DataRequired(message='Please provide an answer')
    ])
    
    security_answer_2 = StringField('Answer to Security Question 2', validators=[
        DataRequired(message='Please provide an answer')
    ])
    
    security_answer_3 = StringField('Answer to Your Custom Question', validators=[
        DataRequired(message='Please provide an answer')
    ])
    
    new_password = PasswordField('New Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('new_password', message='Passwords must match')
    ])