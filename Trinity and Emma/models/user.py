"""
User model for authentication and user management.
Handles user accounts, passwords, security questions, and biometric settings.
"""

from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets

class User(UserMixin, db.Model):
    """User model for storing user account information."""
    
    __tablename__ = 'users'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Authentication fields
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Personal information
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=True)
    address = db.Column(db.String(200), nullable=True)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Verification
    verification_code = db.Column(db.String(6), nullable=True)
    verification_code_expires = db.Column(db.DateTime, nullable=True)
    
    # Security questions (3 total: 2 admin-set + 1 user-defined)
    security_question_1 = db.Column(db.String(200), nullable=True)  # Admin question 1
    security_answer_1 = db.Column(db.String(200), nullable=True)
    security_question_2 = db.Column(db.String(200), nullable=True)  # Admin question 2
    security_answer_2 = db.Column(db.String(200), nullable=True)
    security_question_3 = db.Column(db.String(200), nullable=True)  # User-defined
    security_answer_3 = db.Column(db.String(200), nullable=True)
    
    # Biometric settings
    biometric_enabled = db.Column(db.Boolean, default=False)
    fingerprint_token = db.Column(db.String(255), nullable=True)
    face_token = db.Column(db.String(255), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    accounts = db.relationship('Account', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and store password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against hash."""
        return check_password_hash(self.password_hash, password)
    
    def generate_verification_code(self):
        """Generate 6-digit verification code."""
        self.verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        from datetime import timedelta
        self.verification_code_expires = datetime.utcnow() + timedelta(hours=24)
        return self.verification_code
    
    def verify_code(self, code):
        """Verify the verification code."""
        if not self.verification_code or not self.verification_code_expires:
            return False
        if datetime.utcnow() > self.verification_code_expires:
            return False
        return self.verification_code == code
    
    def enable_biometric(self, biometric_type='fingerprint'):
        """Enable biometric authentication."""
        self.biometric_enabled = True
        token = secrets.token_urlsafe(32)
        if biometric_type == 'fingerprint':
            self.fingerprint_token = token
        elif biometric_type == 'face':
            self.face_token = token
        return token
    
    def get_total_balance(self):
        """Calculate total balance across all accounts."""
        return sum(account.balance for account in self.accounts if account.is_active)
    
    def get_unread_notifications_count(self):
        """Get count of unread notifications."""
        return self.notifications.filter_by(is_read=False).count()
    
    def __repr__(self):
        return f'<User {self.username}>'