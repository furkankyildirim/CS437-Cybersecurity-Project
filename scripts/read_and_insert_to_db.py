# mongo_script.py

import os
import json
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from fetch_feed import get_dynamic_data

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


def read_data():
    get_dynamic_data()
    with open('data.txt', 'r') as f:
        data_list = json.loads(f.read())
        for data in data_list:
            db.travel_advisories.insert_one(data)
