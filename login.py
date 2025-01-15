import os
from fastapi import APIRouter, HTTPException, Response, Request
from pydantic import BaseModel, EmailStr
from datetime import timedelta, datetime
from jose import jwt
from passlib.hash import bcrypt
from database import users_collection
from rate_limiter import rate_limiter

router = APIRouter()

# Load environment variables using os
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")  # Default key for development
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@router.post("/login")
async def login(request: LoginRequest, response: Response):
    # Validate user credentials
    await rate_limiter(user_id=request.email, limit=100, period=60)
    user = await users_collection.find_one({"email": request.email})
    if not user or not bcrypt.verify(request.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Create a new token
    access_token = create_access_token(data={"user_id": user["user_id"], "email": user["email"]})

    # Set the new token in the cookie, overwriting any existing one
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=True,    # Use HTTPS in production
        samesite="Strict"
    )
    return {"message": "Login successful"}

