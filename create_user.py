from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field, ValidationError
from datetime import datetime
from passlib.hash import bcrypt
from database import users_collection
from KeyManager import KeyManager
from cryptography.hazmat.primitives import serialization
import uuid
from rate_limiter import rate_limiter  # Import the rate_limiter module

router = APIRouter()
km = KeyManager()

class CreateUserRequest(BaseModel):
    user_id: str = None
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=50)
    full_name: str = Field(None, min_length=2, max_length=100)

@router.post("/create-user")
async def create_user(request: CreateUserRequest):
    """
    Create a new user with a unique user ID, hashed password, and generated key pair.

    Args:
        request (CreateUserRequest): The user creation request containing email, password, and full name.

    Returns:
        dict: A message confirming user creation and the generated user ID.

    Raises:
        HTTPException: If the email is already registered or any error occurs during user creation.
    """
    try:
        # Apply rate limiting (e.g., 5 requests per minute per email address)
        await rate_limiter(user_id=request.email, limit=100, period=60)

        # Generate user ID if not provided
        user_id = request.user_id or str(uuid.uuid4())

        # Check if the email already exists
        existing_user = await users_collection.find_one({"email": request.email})
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already exists")

        # Hash the user's password
        hashed_password = bcrypt.hash(request.password)

        # Generate private and public key pair
        private_key, public_key = km.generate_key_pair()

        # Prepare user data for storage
        user_data = {
            "user_id": user_id,
            "email": request.email,
            "password": hashed_password,
            "private_key": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            "public_key": km.serialize_public_key(public_key).decode(),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        # Insert user data into the database
        await users_collection.insert_one(user_data)

        return {"message": "User created successfully", "user_id": user_id}

    except ValidationError:
        raise HTTPException(status_code=422, detail="Invalid input data")

    except HTTPException:
        raise  # Re-raise HTTP exceptions to preserve status codes

    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
