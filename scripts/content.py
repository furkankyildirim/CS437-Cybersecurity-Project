# mongo_script.py

import os
import json
from pymongo import MongoClient
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

# Delete all contents in the database
db.contents.delete_many({})

file = open('../static/data.txt', 'r')
data_list = json.loads(file.read())
db.contents.insert_many(data_list)
print('Sample data added successfully!')
file.close()
