import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)

    # 1. Secret Key
    app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key_fallback')

    # 2. Database Config
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assignment_system.db'

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # 3. Init Plugins
    db.init_app(app)
    migrate.init_app(app, db)

    # 4. Register Blueprints
    from app.routes import routes
    app.register_blueprint(routes)

    # --- DELETED: with app.app_context(): db.create_all() ---
    # We removed the auto-create logic from here to prevent errors.

    return app