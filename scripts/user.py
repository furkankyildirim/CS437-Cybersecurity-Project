# mongo_script.py

import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MongoDB connection details
mongo_server = "localhost"  # Use localhost if running MongoDB locally
mongo_port = os.getenv('MONGODB_PORT', '27017')  # Default MongoDB port is 27017
mongo_db = os.getenv('MONGODB_DATABASE', 'CS437Project')  # Default to 'myDatabase' if not specified

# MongoDB URI without authentication
mongo_uri = f'mongodb://{mongo_server}:{mongo_port}/'

# Connect to MongoDB
client = MongoClient(mongo_uri)

# Access the database
db = client[mongo_db]

# Create two sample users
user1 = {
    'username': 'user1',
    'email': 'user1@example.com',
    'password': generate_password_hash('password1'),
    'isAdmin': False
}

user2 = {
    'username': 'user2',
    'email': 'user2@example.com',
    'password': generate_password_hash('password2'),
    'isAdmin': False
}

admin = {
    'username': 'admin',
    'email': 'admin@example.com',
    'password': generate_password_hash('admin'),
    'isAdmin': True
}

# Insert users into the database
db.users.insert_many([user1, user2, admin])

print('Sample users added successfully!')
