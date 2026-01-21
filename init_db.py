# File: init_db.py
from app import create_app, db

def init_database():
    app = create_app()
    with app.app_context():
        try:
            # --- THE FIX IS HERE ---
            print("⚠️ FORCE RESETTING DATABASE...")
            db.drop_all()  # <--- This deletes the broken tables
            db.create_all() # <--- This creates fresh, correct tables
            print("✅ Database reset and recreated successfully.")
        except Exception as e:
            print(f"⚠️ Database error: {e}")

if __name__ == "__main__":
    init_database()