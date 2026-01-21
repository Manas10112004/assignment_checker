from dotenv import load_dotenv
load_dotenv()  # <--- Loads variables from .env before anything else

from app import create_app, db
from flask_migrate import Migrate

# Create the application instance
app = create_app()

# Initialize Migration Engine (Important for Database Updates)
migrate = Migrate(app, db)

if __name__ == '__main__':
    # Running in debug mode for local development
    # In production (Docker), Gunicorn handles this, so this block is skipped.
    app.run(debug=True, port=5000)