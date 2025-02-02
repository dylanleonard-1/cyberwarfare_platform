import os
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database & migrations
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Set up logging for debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create database tables (if not already created)
with app.app_context():
    db.create_all()

# Home / Index Route
@app.route('/')
def index():
    return render_template('index.html')

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            logger.warning(f"Registration attempt with existing username: {username}")
        else:
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now login.', 'success')
            logger.info(f"New user registered: {username}")
            return redirect(url_for('login'))
    
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            logger.info(f"User logged in: {username}")
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            logger.warning(f"Failed login attempt for: {username}")

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'info')
    logger.info("User logged out")
    return redirect(url_for('login'))

# Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('You must be logged in!', 'warning')
        logger.warning("Unauthorized admin access attempt")
        return redirect(url_for('login'))
    
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

# Security & Hacking Modules (Accessible to logged-in users only)
def protected_route(template_name):
    if 'user_id' not in session:
        flash('You must be logged in!', 'warning')
        logger.warning(f"Unauthorized access attempt to {template_name}")
        return redirect(url_for('login'))
    
    return render_template(template_name)

@app.route('/brute_force') 
def brute_force(): return protected_route('brute_force.html')

@app.route('/forensic_analysis') 
def forensic_analysis(): return protected_route('forensic_analysis.html')

@app.route('/secure_communication') 
def secure_communication(): return protected_route('secure_communication.html')

@app.route('/threat_intelligence') 
def threat_intelligence(): return protected_route('threat_intelligence.html')

@app.route('/log_monitoring') 
def log_monitoring(): return protected_route('log_monitoring.html')

@app.route('/firewall_ids') 
def firewall_ids(): return protected_route('firewall_ids.html')

@app.route('/defense_strategy') 
def defense_strategy(): return protected_route('defense_strategy.html')

@app.route('/incident_response') 
def incident_response(): return protected_route('incident_response.html')

@app.route('/c2_detection') 
def c2_detection(): return protected_route('c2_detection.html')

@app.route('/blue_defense') 
def blue_defense(): return protected_route('blue_defense.html')

@app.route('/xss_sql') 
def xss_sql(): return protected_route('xss_sql.html')

@app.route('/vuln_scan') 
def vuln_scan(): return protected_route('vuln_scan.html')

@app.route('/reverse_shell') 
def reverse_shell(): return protected_route('reverse_shell.html')

@app.route('/phishing') 
def phishing(): return protected_route('phishing.html')

@app.route('/c2_panel') 
def c2_panel(): return protected_route('c2_panel.html')

@app.route('/teamchat') 
def teamchat(): return protected_route('teamchat.html')

@app.route('/red_attack') 
def red_attack(): return protected_route('red_attack.html')

# Scoreboards
@app.route('/red_scoreboard') 
def red_scoreboard(): return protected_route('red_scoreboard.html')

@app.route('/blue_scoreboard') 
def blue_scoreboard(): return protected_route('blue_scoreboard.html')

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    logger.error("404 Error - Page Not Found")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error("500 Error - Internal Server Error")
    return render_template('500.html'), 500

# Run Flask App
if __name__ == '__main__':
    app.run(debug=True)

