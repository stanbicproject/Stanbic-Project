"""
Admin blueprint initialization.
Handles admin panel for managing users, accounts, and transactions.
"""

from flask import Blueprint

admin_bp = Blueprint('admin', __name__)

from admin import routes