from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
import re
from flask_mail import Mail, Message

app = Flask(__name__)

import os
import secrets
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Generate a new SECRET_KEY if it's not set in the environment
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///instance/users.db')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.sendgrid.net')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))  # Default 587
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'apikey')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'your_email@example.com')

# Print secret key (only for debugging - remove in production)
print(f"Loaded SECRET_KEY: {app.config['SECRET_KEY'][:10]}... (hidden for security)")

# Database configuration
db_path = os.path.join(app.instance_path, 'users.db')
os.makedirs(app.instance_path, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key_here')

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Change for other providers
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'your-email-password')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'your-email@gmail.com')

mail = Mail(app)
db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    team = db.Column(db.String(20), nullable=False)  # 'red', 'blue', 'admin'
    verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(36), unique=True, nullable=True)

# Ensure database is created
with app.app_context():
    db.create_all()

    # Create admin user if not exists
    admin_email = "dmleonard5125@gmail.com"
    admin_user = User.query.filter_by(email=admin_email).first()
    if not admin_user:
        admin_password = "&F7m#z9$Xp@Qv!d3rL2N"
        hashed_password = generate_password_hash(admin_password)
        new_admin = User(
            email=admin_email,
            username="admin",
            password=hashed_password,
            team="admin",
            verified=True,
            verification_code=None
        )
        db.session.add(new_admin)
        db.session.commit()
        print("✅ Admin user created successfully!")

# Helper Functions
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

def send_verification_email(user_email, verification_code):
    verification_link = url_for('verify_email', code=verification_code, _external=True)
    subject = "Verify Your Email - Cyber Warfare Platform"
    body = f"""
    Welcome to Cyber Warfare Platform!
    
    Please verify your email by clicking the link below:
    {verification_link}
    
    If you did not request this, please ignore this email.
    """
    msg = Message(subject, recipients=[user_email], body=body)
    mail.send(msg)
    print(f"✅ Verification email sent to {user_email}")

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    team = request.args.get('team', 'red')
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        if not is_valid_email(email) or User.query.filter_by(email=email).first():
            flash('Invalid or already registered email!', 'danger')
            return redirect(url_for('register', team=team))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken!', 'danger')
            return redirect(url_for('register', team=team))
        
        hashed_password = generate_password_hash(password)
        verification_code = str(uuid.uuid4())
        new_user = User(email=email, username=username, password=hashed_password, team=team, verified=False, verification_code=verification_code)
        
        db.session.add(new_user)
        db.session.commit()
        send_verification_email(email, verification_code)

        flash('Registration successful! Check your email for verification.', 'success')
        return redirect(url_for('login', team=team))

    return render_template('register.html', team=team)

# Email Verification Route
@app.route('/verify/<code>')
def verify_email(code):
    user = User.query.filter_by(verification_code=code).first()
    if user:
        user.verified = True
        user.verification_code = None
        db.session.commit()
        flash('✅ Email verified! You can now log in.', 'success')
        return redirect(url_for('login'))
    flash('❌ Invalid verification link.', 'danger')
    return redirect(url_for('home'))

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    team = request.args.get('team', 'red')
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.verified:
                flash('Your email is not verified! Check your inbox.', 'danger')
                return redirect(url_for('login', team=team))
            session['user_id'] = user.id
            session['username'] = user.username
            session['team'] = user.team
            session['email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for(f"{user.team}_dashboard"))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html', team=team)

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Dashboards & Features
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/red_attack')
def red_attack():
    return render_template('red_attack.html')

@app.route('/blue_defense')
def blue_defense():
    return render_template('blue_defense.html')

# Tool Routes
tool_pages = ["brute_force", "vuln_scan", "xss_sql", "phishing", "reverse_shell", "c2_panel", "firewall_ids", "log_monitoring", "threat_intelligence", "incident_response", "forensic_analysis", "secure_communication", "c2_detection", "defense_strategy"]
for tool in tool_pages:
    app.add_url_rule(f"/{tool}", tool, lambda tool=tool: render_template(f"{tool}.html"))

if __name__ == '__main__':
    app.run(debug=True)

