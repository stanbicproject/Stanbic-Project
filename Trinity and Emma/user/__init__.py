"""
User blueprint initialization.
Handles user dashboard, transactions, payments, and account management.
"""

from flask import Blueprint

user_bp = Blueprint('user', __name__)

from user import routes