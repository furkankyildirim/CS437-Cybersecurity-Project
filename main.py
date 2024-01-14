# main.py
from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies, get_jwt
from bson.objectid import ObjectId
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
# mongo_uri = f'mongodb://{mongo_user}:{mongo_password}@{mongo_server}:{mongo_port}'

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

#@app.route('/')
#@jwt_required(optional=True)
#def index():
    #current_user = get_jwt_identity()
    #return render_template('index.html', user=current_user)

@app.route('/')
@jwt_required(optional=True)
def index():
    current_user_id = get_jwt_identity()
    print(f"Current User ID: {current_user_id}")
    current_user = None
    if current_user_id:
        user = db.users.find_one({"_id": ObjectId(current_user_id)})
        if user:
            current_user = user.get("username")
    print(f"Current User Name: {current_user}")
    return render_template('index.html', user=current_user)  # Pass only the username


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

        # Retrieve user from MongoDB based on the username
        user = db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password) and not user['isAdmin']:
            # Authentication successful, create JWT
            user_id = str(user['_id'])
            access_token = create_access_token(identity=user_id, expires_delta=timedelta(days=1))
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

# Admin login route
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        # ... [your CAPTCHA validation logic here] ...
        username = request.form.get('username')
        password = request.form.get('password')

        # Retrieve the admin user from MongoDB based on the username
        admin_user = db.users.find_one({'username': username, 'isAdmin': True})
        if admin_user and check_password_hash(admin_user['password'], password):
            # Authentication successful, create JWT with admin claims
            access_token = create_access_token(
                identity=str(admin_user['_id']),
                expires_delta=timedelta(days=1),
                additional_claims={"is_admin": True}
            )

            # Set JWT as a cookie
            response = redirect(url_for('admin_dashboard'))
            response.set_cookie('access_token_cookie', value=access_token, httponly=True, secure=False)

            # Flash a success message
            flash('Admin login successful!', 'success')
            return response

        # Authentication failed, show an error message
        flash('Invalid admin credentials. Please try again.', 'error')
        return render_template('admin_login.html')

    # If it's a GET request, render the admin login page
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
@jwt_required()
def admin_dashboard():
    claims = get_jwt()
    user_id = get_jwt_identity()  # Assuming this retrieves the user ID

    # Retrieve admin's username from the database using user_id
    # Replace 'username_field' with the actual field name for the username in your database
    admin_user = db.users.find_one({'_id': ObjectId(user_id)})
    username = admin_user.get('username', 'Unknown') if admin_user else 'Unknown'

    if claims.get("is_admin"):
        return render_template('admin_dashboard.html', user_id=user_id, username=username)
    else:
        flash("You do not have permission to access the admin dashboard.", "error")
        return redirect(url_for('index'))


@app.route('/logout', methods=['GET'])
def logout():
    response = redirect(url_for('login'))
    unset_jwt_cookies(response)  # This will remove the JWT cookies
    flash('You have been logged out.', 'info')
    return response


@app.route('/comments', methods=['GET'])
def comments():
    # Retrieve all comments from MongoDB by content id
    content_id = request.args.get('content_id')
    data = db.comments.find({'content_id': content_id})

    # Return comments in JSON format
    return data


@app.route('/comment', methods=['POST', 'DELETE'])
@jwt_required()
def comment():
    if request.method == 'POST':
        # Get the content id and comment from the request body
        content_id = request.json['content_id']
        data = request.json['comment']

        # Get the user id from the JWT
        user_id = get_jwt_identity()
        user = db.users.find_one({'_id': user_id})

        if not user:
            # Return an error message
            return {'message': 'You must be logged in to comment.'}, 403

        # Insert the comment into MongoDB
        db.comments.insert_one({'user_id': user_id, 'username': user['username'],
                                'content_id': content_id, 'comment': data})

        # Return a success message
        return {'message': 'Comment added successfully.'}

    if request.method == 'DELETE':
        # Get the comment id from the request body
        comment_id = request.json['comment_id']

        # Get the user from the JWT
        user_id = get_jwt_identity()
        user = db.users.find_one({'_id': user_id})

        # Check if user is admin or the comment owner
        if user['isAdmin'] or db.comments.find_one({'_id': comment_id})['user_id'] == user_id:
            # Delete the comment from MongoDB
            db.comments.delete_one({'_id': comment_id})
        else:
            # Return an error message
            return {'message': 'You do not have permission to delete this comment.'}, 403

            # Return a success message
        return {'message': 'Comment deleted successfully.'}


if __name__ == '__main__':
    app.run(debug=True, port=8000)
