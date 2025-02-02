import os
import secrets
from flask import Flask
from dotenv import load_dotenv

# Initialize Flask app
app = Flask(__name__)

# Load environment variables from .env
load_dotenv()

# Check if SECRET_KEY exists, otherwise generate a new secure one
secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Ensure .env exists and store the secret key persistently
if not os.path.exists('.env'):
    with open('.env', 'w') as env_file:
        env_file.write(f"SECRET_KEY={secret_key}\n")
else:
    with open('.env', 'r') as env_file:
        env_contents = env_file.read()
    
    if 'SECRET_KEY' not in env_contents:
        with open('.env', 'a') as env_file:
            env_file.write(f"\nSECRET_KEY={secret_key}\n")

# Add .env to .gitignore to prevent exposing secrets
if not os.path.exists('.gitignore'):
    with open('.gitignore', 'w') as gitignore:
        gitignore.write(".env\n")
else:
    with open('.gitignore', 'r') as gitignore:
        gitignore_contents = gitignore.read()
    
    if ".env" not in gitignore_contents:
        with open('.gitignore', 'a') as gitignore:
            gitignore.write("\n.env\n")

# Set the Flask secret key
app.config['SECRET_KEY'] = secret_key

# Debugging - Print only a part of the secret key (REMOVE in production)
print(f"✅ Flask SECRET_KEY set: {secret_key[:10]}... (hidden for security)")

# Run the Flask app (if needed)
if __name__ == '__main__':
    app.run(debug=True)

