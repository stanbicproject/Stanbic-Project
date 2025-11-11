"""
Configuration settings for the Stanbic Bank Uganda Online Banking System.
Contains database configuration, secret keys, and mail settings.
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class with all app settings."""
    
    # Secret key for session management (change in production!)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'stanbic-bank-uganda-secret-key-2024'
    
    # Database configuration
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'stanbic.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Mail configuration for email verification
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'noreply@stanbic.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'your-email-password'
    MAIL_DEFAULT_SENDER = ('Stanbic Bank Uganda', 'noreply@stanbic.com')
    
    # Application settings
    BANK_NAME = 'Stanbic Bank Uganda'
    CURRENCY = 'UGX'
    CURRENCY_SYMBOL = 'UGX'
    
    # Security questions (2 default admin questions)
    DEFAULT_SECURITY_QUESTIONS = [
        "What was the name of your first pet?",
        "In which city were you born?",
        "What is your mother's maiden name?",
        "What was the name of your first school?",
        "What is your favorite book?"
    ]
    
    # Transaction limits
    DAILY_WITHDRAWAL_LIMIT = 5000000  # 5 million UGX
    DAILY_PAYMENT_LIMIT = 10000000    # 10 million UGX
    MIN_TRANSACTION_AMOUNT = 1000     # 1,000 UGX
    
    # Pagination
    TRANSACTIONS_PER_PAGE = 20
    USERS_PER_PAGE = 50