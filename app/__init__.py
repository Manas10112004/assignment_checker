import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)

    # SECURITY KEY (Required for Sessions)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key_123')

    # DATABASE CONFIG (Auto-detects Render vs Local)
    database_url = os.environ.get('DATABASE_URL')
    if database_url and database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    # Import Routes
    from app.routes import routes
    app.register_blueprint(routes)

    # Create Tables
    with app.app_context():
        db.create_all()

    return app