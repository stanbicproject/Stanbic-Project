"""
Main Flask application entry point for Stanbic Bank Uganda Online Banking System.
This file initializes the Flask app, registers blueprints, and configures the database.
"""

from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from config import Config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

def create_app(config_class=Config):
    """
    Application factory pattern to create and configure the Flask app.
    
    Args:
        config_class: Configuration class (default: Config)
    
    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize Flask extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Import and register blueprints
    from auth import auth_bp
    from user import user_bp
    from admin import admin_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    # Home route redirects to dashboard or login
    @app.route('/')
    def index():
        from flask_login import current_user
        if current_user.is_authenticated:
            return redirect(url_for('user.dashboard'))
        return redirect(url_for('auth.login'))
    
    # Create database tables
    with app.app_context():
        db.create_all()
        # Initialize default data
        from models.user import User
        # Create default admin if doesn't exist
        admin = User.query.filter_by(email='admin@stanbic.com').first()
        if not admin:
            admin = User(
                email='admin@stanbic.com',
                username='admin',
                first_name='Admin',
                last_name='User',
                phone='0700000000',
                is_admin=True,
                is_verified=True
            )
            admin.set_password('Admin@123')
            db.session.add(admin)
            db.session.commit()
            print("Default admin created: admin@stanbic.com / Admin@123")
    
    return app

@login_manager.user_loader
def load_user(user_id):
    """
    Load user by ID for Flask-Login.
    
    Args:
        user_id: User's ID
    
    Returns:
        User object or None
    """
    from models.user import User
    return User.query.get(int(user_id))

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)