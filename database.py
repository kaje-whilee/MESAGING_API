from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ServerSelectionTimeoutError, ConfigurationError
import os

# MongoDB URI with an environment variable fallback
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")

# Initialize the MongoDB client
try:
    client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000)  # 5-second timeout
except ConfigurationError as e:
    raise RuntimeError(f"Invalid MongoDB configuration: {e}")

# Database and collections setup
db = client.get_database("secure_messaging")  # Replace with your database name
users_collection = db.get_collection("users")
messages_collection = db.get_collection("messages")
rate_limit_collection = db.get_collection("rate_limits")

async def test_connection():
    """
    Tests the connection to the MongoDB server.

    Raises:
        ServerSelectionTimeoutError: If the connection to MongoDB cannot be established.
    """
    try:
        # Attempt to retrieve server info
        await client.server_info()
        print("MongoDB connection established.")
    except ServerSelectionTimeoutError:
        print("Failed to connect to MongoDB. Ensure MongoDB is running.")
        raise
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise
