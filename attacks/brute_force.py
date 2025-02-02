from flask import render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
import time

from server import app, db, User  # Import database and app context

@app.route('/brute_force', methods=['GET', 'POST'])
def brute_force():
    if 'user_id' not in session:
        flash('You must be logged in!', 'warning')
        return redirect(url_for('login'))

    result = None

    if request.method == 'POST':
        username = request.form['username']
        wordlist_type = request.form['wordlist']

        # Retrieve target user's real hashed password from the database
        target_user = User.query.filter_by(username=username).first()
        if not target_user:
            result = "❌ No such user found."
            return render_template('brute_force.html', result=result)

        stored_hashed_password = target_user.password  # This is the real stored hash

        # Simulated wordlists
        wordlists = {
            "small": ["123456", "password", "admin", "welcome", "letmein", "pass123"],
            "large": ["qwerty", "monkey", "dragon", "football", "password123", "superman", "letmein123", "test123"]
        }

        attempts = wordlists.get(wordlist_type, [])
        log = []

        for word in attempts:
            log.append(f"🔄 Trying: {word} ...")
            time.sleep(0.5)  # Simulated delay

            # Check if the guessed password matches the real stored hash
            if check_password_hash(stored_hashed_password, word):
                log.append(f"✅ SUCCESS! Password found: {word}")  # Shows the real found password
                break
        else:
            log.append("❌ Attack failed! No matching password found.")

        result = "<br>".join(log)  # Format for display
        print(result)  # Debugging output

    return render_template('brute_force.html', result=result)

