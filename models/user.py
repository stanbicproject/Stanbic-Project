"""
User model for Stanbic Bank Uganda Online Banking System.
Handles user authentication, profile management, and relationships with accounts.
"""

from extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import logging

logger = logging.getLogger(__name__)


class User(UserMixin, db.Model):
    """User model for authentication and profile management."""
    
    __tablename__ = 'users'
    
    # Primary Key
    id = db.Column(db.Integer, primary_key=True)
    
    # Authentication
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Profile Information
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    date_of_birth = db.Column(db.Date)
    address = db.Column(db.Text)
    
    # Account Status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    
    # Email Verification
    verification_code = db.Column(db.String(6))
    verification_code_expires = db.Column(db.DateTime)
    
    # Security Questions (for account recovery)
    security_question_1 = db.Column(db.String(255))
    security_answer_1 = db.Column(db.String(255))
    security_question_2 = db.Column(db.String(255))
    security_answer_2 = db.Column(db.String(255))
    security_question_3 = db.Column(db.String(255))
    security_answer_3 = db.Column(db.String(255))
    
    # Biometric Authentication (WebAuthn)
    biometric_enabled = db.Column(db.Boolean, default=False, nullable=False)
    fingerprint_token = db.Column(db.String(255), unique=True)
    face_token = db.Column(db.String(255), unique=True)
    webauthn_credentials = db.Column(db.Text)  # JSON string of WebAuthn credentials
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    accounts = db.relationship('Account', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    # Password Methods
    def set_password(self, password):
        """Hash and set user password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify user password."""
        return check_password_hash(self.password_hash, password)
    
    # Email Verification Methods
    def generate_verification_code(self):
        """Generate a 6-digit verification code."""
        self.verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        self.verification_code_expires = datetime.utcnow() + timedelta(hours=24)
        return self.verification_code
    
    def verify_code(self, code):
        """Verify the email verification code."""
        if not self.verification_code or not self.verification_code_expires:
            return False
        
        if datetime.utcnow() > self.verification_code_expires:
            return False
        
        return self.verification_code == code
    
    # Biometric Authentication Methods
    def enable_biometric(self, biometric_type='fingerprint'):
        """Enable biometric authentication and generate token."""
        self.biometric_enabled = True
        token = secrets.token_urlsafe(32)
        
        if biometric_type == 'fingerprint':
            self.fingerprint_token = token
        elif biometric_type == 'face':
            self.face_token = token
        
        return token
    
    def disable_biometric(self):
        """Disable biometric authentication."""
        self.biometric_enabled = False
        self.fingerprint_token = None
        self.face_token = None
        self.webauthn_credentials = None
    
    # Security Question Methods
    def verify_security_answers(self, answer1, answer2, answer3):
        """Verify all three security answers."""
        return (
            self.security_answer_1 == answer1.lower() and
            self.security_answer_2 == answer2.lower() and
            self.security_answer_3 == answer3.lower()
        )
    
    # Notification Methods
    def get_unread_notifications_count(self):
        """Get count of unread notifications."""
        try:
            return self.notifications.filter_by(is_read=False).count()
        except Exception as e:
            logger.warning(f"Could not fetch unread notifications count: {e}")
            return 0
    
    def get_unread_notifications(self, limit=10):
        """Get recent unread notifications."""
        try:
            return self.notifications.filter_by(is_read=False).order_by(
                db.desc('created_at')
            ).limit(limit).all()
        except Exception as e:
            logger.warning(f"Could not fetch unread notifications: {e}")
            return []
    
    # Account Methods
    def get_default_account(self):
        """Get user's default account."""
        try:
            return self.accounts.filter_by(is_default=True, is_active=True).first()
        except Exception as e:
            logger.warning(f"Could not fetch default account: {e}")
            return None
    
    def get_total_balance(self):
        """Get total balance across all active accounts."""
        try:
            total = 0
            for account in self.accounts.filter_by(is_active=True).all():
                total += account.balance
            return total
        except Exception as e:
            logger.warning(f"Could not calculate total balance: {e}")
            return 0
    
    # Profile Methods
    def get_full_name(self):
        """Get user's full name."""
        return f"{self.first_name} {self.last_name}"
    
    def update_last_login(self):
        """Update last login timestamp."""
        self.last_login = datetime.utcnow()
        try:
            db.session.commit()
        except Exception as e:
            logger.error(f"Could not update last login: {e}")
            db.session.rollback()
    
    # Status Methods
    def activate(self):
        """Activate user account."""
        self.is_active = True
    
    def deactivate(self):
        """Deactivate user account."""
        self.is_active = False
    
    def verify_email(self):
        """Mark email as verified."""
        self.is_verified = True
        self.verification_code = None
        self.verification_code_expires = None
    
    # Admin Methods
    def make_admin(self):
        """Grant admin privileges."""
        self.is_admin = True
    
    def remove_admin(self):
        """Remove admin privileges."""
        self.is_admin = False
    
    # Flask-Login Required Methods
    def get_id(self):
        """Return user ID as string for Flask-Login."""
        return str(self.id)
    
    @property
    def is_authenticated(self):
        """Return True if user is authenticated."""
        return True
    
    @property
    def is_anonymous(self):
        """Return False as this is not an anonymous user."""
        return False
    
    def to_dict(self):
        """Convert user object to dictionary."""
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.get_full_name(),
            'phone': self.phone,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'is_admin': self.is_admin,
            'biometric_enabled': self.biometric_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }