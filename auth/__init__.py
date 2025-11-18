"""
Auth package initialization.
Exports the auth blueprint with all authentication routes.
"""

from flask import Blueprint

# Create the auth blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Import routes after blueprint creation to avoid circular imports
from auth import routes

# Export the blueprint
__all__ = ['auth_bp']