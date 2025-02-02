from werkzeug.security import generate_password_hash
from server import db, User  # Ensure your server.py and db are properly imported

# Create the admin user
def create_admin():
    # Admin details (You can change the password or email as needed)
    email = 'dmleonard5125@gmail.com'
    username = 'admin'
    password = '!9V3gS!2bxzQ#1m5KzLz'  # Secure password
    hashed_password = generate_password_hash(password)
    
    # Check if the user already exists to avoid duplicates
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        print(f"Admin user already exists with email: {email}")
        return
    
    admin_user = User(email=email, username=username, password=hashed_password, team='red')  # Admin can have red team access, or any team
    db.session.add(admin_user)
    db.session.commit()
    print("Admin user created successfully!")

# Run the create_admin function
if __name__ == '__main__':
    create_admin()

