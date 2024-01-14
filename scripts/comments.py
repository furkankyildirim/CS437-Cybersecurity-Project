import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from datetime import datetime
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

user = db.users.find_one({'username': 'user1'})
content_id = db.contents.find_one({'country': 'Argentina'})['_id']
# Create comments

comment1 = {
    'user_id': user['_id'],
    'username': user['username'],
    'comment': 'This is a comment',
    'date': datetime.now(),
    'content_id': content_id
}

comment2 = {
    'user_id': user['_id'],
    'username': user['username'],
    'comment': 'This is another comment',
    'date': datetime.now(),
    'content_id': content_id
}

# Insert comments into the database
db.comments.insert_many([comment1, comment2])

print('Sample comments added successfully!')