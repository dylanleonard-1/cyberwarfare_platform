from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from server import app, db, User  # Ensure your server.py and db are properly imported

# Define the new strong password
new_password = "&F7m#z9$Xp@Qv!d3rL2N"
hashed_password = generate_password_hash(new_password)

def update_admin_password():
    with app.app_context():  # This ensures the database context is available
        admin_user = User.query.filter_by(email="dmleonard5125@gmail.com").first()
        if admin_user:&F7m#z9$Xp@Qv!d3rL2N
            admin_user.password = hashed_password
            db.session.commit()
            print("✅ Admin password updated successfully!")
        else:
            print("❌ Admin user not found!")

if __name__ == "__main__":
    update_admin_password()

