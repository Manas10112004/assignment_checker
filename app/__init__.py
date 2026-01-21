import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)

    # 1. Secret Key (Security)
    app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key_fallback')

    # 2. Database Configuration
    # Prioritize 'DATABASE_URL' from environment (Docker/Render)
    # Fallback to local SQLite if no URL is found
    database_url = os.environ.get('DATABASE_URL')

    if database_url:
        # Fix for SQLAlchemy requiring 'postgresql://' instead of 'postgres://' (common in Render)
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    else:
        # Local Development Fallback
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assignment_system.db'

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # 3. Initialize Plugins
    db.init_app(app)
    migrate.init_app(app, db)

    # 4. Register Blueprints (Routes)
    from app.routes import routes
    app.register_blueprint(routes)

    # 5. Create Database Tables (if they don't exist)
    with app.app_context():
        db.create_all()

    return app