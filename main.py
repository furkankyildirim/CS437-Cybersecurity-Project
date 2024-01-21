# main.py
import random
from datetime import timedelta, datetime

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies, \
    get_jwt
from bson.objectid import ObjectId
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash

from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os, requests, pyotp, time
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length

app = Flask(__name__)
load_dotenv()

# Initialize Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,  # Rate limiting by IP address
    storage_uri='memory://',  # In-memory storage (for testing, use a persistent storage in production)
)

# Set the secret key for session management
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_default_secret_key')
app.config['RECAPTCHA_SECRET_KEY'] = 'your_secret_key_here'

# Configure Flask-Mail for sending emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'cs437mfa@gmail.com'  # Your Gmail email address
app.config['MAIL_PASSWORD'] = 'kvsg mabn dmnd xgcp'  # Application password generated for Gmail
# app.config['MAIL_DEBUG'] = True
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Initialize Flask-Mail
mail = Mail(app)

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
    return render_template('index.html', user=current_user, data_list=db.contents.find({}))  # Pass only the username


@app.route('/verify_recaptcha', methods=['POST'])
def verify_recaptcha():
    recaptcha_response = request.form.get('g-recaptcha-response')
    secret = app.config['RECAPTCHA_SECRET_KEY']
    payload = {'secret': secret, 'response': recaptcha_response}
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()

    if result['success']:
        return "Captcha Verified Successfully"
    else:
        return "Captcha Verification Failed", 400
        flash('Not logged in.', 'warning')  # For debugging, remove this later


# Define the form for entering the email
class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')


# Define the form for entering the OTP and new password
class VerifyCodeForm(FlaskForm):
    code = StringField('Verify Code', validators=[DataRequired(), Length(min=6, max=6)])
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8, max=20)])
    submit = SubmitField('Submit')


@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("2 per minute")  # Apply rate limit to this route
def forgot_password():
    form = ForgotPasswordForm()
    print(f"Session: {session}")
    if request.method == 'POST' and 'recovery_code' not in session:
        email = form.email.data
        # [Check if email exists in the database]
        # This is where you would check if the email exists in the database.
        # If it doesn't, you can show an error message to the user.
        user = db.users.find_one({'email': email})
        if user:
            # Generate a random recovery code and timestamp
            recovery_code = random.randint(100000, 999999)
            timestamp = int(time.time())

            # Delete any existing recovery codes for the user
            db.verifications.delete_many({'email': email})

            # Store the recovery code and timestamp in the database
            db.verifications.insert_one({'email': email, 'recovery_code': recovery_code, 'timestamp': timestamp})

            # Set email session variable
            session['reset_email'] = email

            # Store the recovery code and timestamp in the session
            subject = 'Password Reset Code'
            body = f'Your password reset code is: {recovery_code}'
            msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = body

            try:
                mail.send(msg)
                return redirect(url_for('verify_code'))
            except Exception as e:
                flash(f'Error sending the email: {str(e)}', 'error')
        else:
            flash('User not found.', 'error')

    return render_template('forgot_password.html', form=form)


# New route for requesting OTP
@app.route('/verify-code', methods=['GET', 'POST'])
def verify_code():
    form = VerifyCodeForm()
    if request.method == 'POST':
        recovery_code = form.code.data
        new_password = form.password.data

        verification = db.verifications.find_one({'email': session.get('reset_email')})

        if verification:
            # Check if the recovery code is correct
            if verification['recovery_code'] == int(recovery_code):
                # Check if the recovery code is expired (2 minutes)
                if int(time.time()) - verification['timestamp'] > 120:
                    flash('The recovery code has expired. Please try again.', 'error')
                    return redirect(url_for('forgot_password'))
                else:
                    # Update the user's password
                    db.users.update_one({'email': session.get('reset_email')},
                                        {'$set': {'password': generate_password_hash(new_password)}})

                    # Delete the verification document from the database
                    db.verifications.delete_one({'email': session.get('reset_email')})
                    # Delete the email session variable
                    session.pop('reset_email', None)

                    flash('Your password has been updated.', 'success')
                    return redirect(url_for('login'))
            else:
                flash('Invalid recovery code.', 'error')
                return redirect(url_for('forgot_password'))
        else:
            flash('Invalid recovery code.', 'error')
            return redirect(url_for('forgot_password'))

    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))

    return render_template('verify_code.html', form=form)


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
            response.set_cookie('user_id', value=user_id, httponly=True, secure=False)
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
        username = request.form.get('username')
        password = request.form.get('password')

        # Get the reCAPTCHA response from the form
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Please complete the reCAPTCHA.', 'error')
            return render_template('admin_login.html')

        # Verify the reCAPTCHA response with Google
        data = {
            'secret': '6Ld8r1ApAAAAAGbqlk-ng5kzyCMRk5nKEUGz0oxS',
            'response': recaptcha_response
        }
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = r.json()
        if not result.get('success'):
            flash('Invalid reCAPTCHA. Please try again.', 'error')
            return render_template('admin_login.html')

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


def get_users():
    # Retrieve all users from MongoDB
    data = list(db.users.find({}))

    # Remove the password field from each user
    for user in data:
        del user['password']

    # Remove admin users from the list
    data = [user for user in data if not user['isAdmin']]
    # Return users in JSON format
    return data


@app.route('/users', methods=['GET', 'POST', 'DELETE'])
@jwt_required()
def users():
    if request.method == 'GET':
        user = db.users.find_one({'_id': ObjectId(get_jwt_identity())})
        if not user or not user['isAdmin']:
            # Return an error message
            return {'message': 'You do not have permission to view users.'}, 403

        return get_users()

    if request.method == 'POST':
        # Get the username, email, password, and isAdmin from the request body
        current_user = get_jwt_identity()
        user = db.users.find_one({'_id': ObjectId(current_user)})

        if not user or not user['isAdmin']:
            # Return an error message
            return {'message': 'You do not have permission to add a user.'}, 403

        username = request.json['username']
        email = request.json['email']
        password = request.json['password']

        # Insert the user into MongoDB
        db.users.insert_one({'username': username, 'email': email,
                             'password': generate_password_hash(password), 'isAdmin': False})

        # Return a success message
        return jsonify({'message': 'User added successfully.'})

    if request.method == 'DELETE':
        # Get the user id from the request body
        current_user = get_jwt_identity()
        user = db.users.find_one({'_id': ObjectId(current_user)})

        if not user or not user['isAdmin']:
            # Return an error message
            return {'message': 'You do not have permission to delete a user.'}, 403

        user_id = request.args.get('user_id')

        db.users.delete_one({'_id': ObjectId(user_id)})

        # Return a success message
        return jsonify({'message': 'User deleted successfully.'})


@app.route('/admin_dashboard')
@jwt_required()
def admin_dashboard():
    claims = get_jwt()
    user_id = get_jwt_identity()  # Assuming this retrieves the user ID

    # Retrieve admin's username from the database using user_id
    # Replace 'username_field' with the actual field name for the username in your database
    admin_user = db.users.find_one({'_id': ObjectId(user_id)})
    username = admin_user.get('username', 'Unknown') if admin_user else 'Unknown'

    if not claims.get("is_admin"):
        flash("You do not have permission to access the admin dashboard.", "error")
        return redirect(url_for('index'))

    # Call the users API to get all users
    user_data = get_users()
    comments = list(db.comments.find({}))
    return render_template('admin_dashboard.html', user_id=user_id, username=username,
                           users=user_data, comments=comments)


@app.route('/logout', methods=['GET'])
def logout():
    response = redirect(url_for('index'))
    unset_jwt_cookies(response)  # This will remove the JWT cookies
    # delete the user_id cookie
    response.set_cookie('access_token_cookie', '', expires=0)
    response.set_cookie('user_id', '', expires=0)
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
        user = db.users.find_one({'_id': ObjectId(user_id)})

        if not user:
            # Return an error message
            return {'message': 'You must be logged in to comment.'}, 403

        # Insert the comment into MongoDB
        db.comments.insert_one({'user_id': user_id, 'username': user['username'],
                                'date': datetime.now(),
                                'content_id': content_id, 'comment': data})

        # Return a success message
        return {'message': 'Comment added successfully.'}

    if request.method == 'DELETE':
        # Get the comment id from the request body
        comment_id = request.args.get('comment_id')

        # Get the user from the JWT
        user_id = get_jwt_identity()
        user = db.users.find_one({'_id': ObjectId(user_id)})
        # Check if user is admin or the comment owner
        if (user and user['isAdmin']) or str(db.comments.find_one({'_id': ObjectId(comment_id)})['user_id']) == user_id:
            # Delete the comment from MongoDB
            db.comments.delete_one({'_id': ObjectId(comment_id)})
        else:
            # Return an error message
            return {'message': 'You do not have permission to delete this comment.'}, 403

            # Return a success message
        return {'message': 'Comment deleted successfully.'}


@app.route('/content/<int:id>')
@jwt_required(optional=True)
def content(id):
    # Your content handling logic here
    data = db.contents.find_one({'_id': id})
    user_id = request.cookies.get('user_id')
    comments = list(db.comments.find({'content_id': id}))
    current_user_id = get_jwt_identity()

    for row in comments:
        if str(row['user_id']) == str(user_id):
            row['isOwner'] = True
        else:
            row['isOwner'] = False
    return render_template('content.html', content=data, comments=comments,
                           is_logged_in=current_user_id)


if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=8000)
