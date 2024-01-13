# main.py
from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies

from pymongo import MongoClient
from werkzeug.security import check_password_hash

import os

app = Flask(__name__)
load_dotenv()

# Set the secret key for session management
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_default_secret_key')

# MongoDB connection details
mongo_user = os.getenv('MONGODB_USER')
mongo_password = os.getenv('MONGODB_PASSWORD')
mongo_server = "localhost"
mongo_port = os.getenv('MONGODB_PORT')
mongo_db = os.getenv('MONGODB_DATABASE')

# MongoDB URI
#mongo_uri = f'mongodb://{mongo_user}:{mongo_password}@{mongo_server}:{mongo_port}'

# MongoDB URI without authentication
mongo_uri = f'mongodb://{mongo_server}:{mongo_port}/'

# Connect to MongoDB
client = MongoClient(mongo_uri)


# Create a database
db = client[mongo_db]

# Initialize Flask-JWT-Extended
jwt = JWTManager(app)

# Configure Flask-JWT-Extended
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False  # Should be true in production with HTTPS
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Enable CSRF protection in production

@app.route('/')
@jwt_required(optional=True)
def index():
    current_user = get_jwt_identity()
    if current_user:
        flash(f'Logged in as {current_user}', 'info')  # For debugging, remove this later
    else:
        flash('Not logged in.', 'warning')  # For debugging, remove this later
    return render_template('index.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
         # Get the CAPTCHA response
        captcha_response = request.form['captcha_response']
        # Check if the CAPTCHA response is correct (for example, '5' for the above math question)
        if captcha_response == '7':
            # Proceed with login
            pass
        else:
            # Reload the login page with an error message
            return render_template('login.html', error="Incorrect CAPTCHA.")
        username = request.form.get('username')
        password = request.form.get('password')
        print(username, password)
        # Retrieve user from MongoDB based on the username
        user = db.users.find_one({'username': username})
        print(user)
        if user and check_password_hash(user['password'], password):
            # Authentication successful, create JWT
            access_token = create_access_token(identity=username, expires_delta=timedelta(days=1))

            # Set JWT as a cookie
            response = redirect(url_for('index'))
            response.set_cookie('access_token_cookie', value=access_token, httponly=True, secure=False)

            # Flash a success message
            flash('Login successful!', 'success')

            return response

        # Authentication failed, show an error message
        flash('Invalid credentials. Please try again.', 'error')
        return render_template('login.html')

    # If it's a GET request, render the login page
    return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    response = redirect(url_for('login'))
    unset_jwt_cookies(response)  # This will remove the JWT cookies
    flash('You have been logged out.', 'info')
    return response

if __name__ == '__main__':
    app.run(debug=True, port=8000)