from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from create_user import router as create_user_router
from login import router as login_router
from send_message import router as send_message_router
from receive_message import router as receive_message_router
from profile_1 import router as profile_router
from create_friend import router as create_friend_router
from database import test_connection
from rate_limiter import rate_limiter
from contextlib import asynccontextmanager

# Define lifespan for app startup and shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic: Ensure database connection
    await test_connection()
    yield
    # Shutdown logic: Add any cleanup code if needed

# Initialize FastAPI app with lifespan
app = FastAPI(title="Secure Messaging API", lifespan=lifespan)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root endpoint with rate limiting applied
@app.get("/")
async def index(request: Request):
    """
    Root endpoint with rate limiting applied.
    """
    client_ip = request.client.host  # Extract client IP address
    await rate_limiter(user_id=client_ip, limit=1000, period=60)  # 1000 requests per minute

    return {"message": "Welcome to Secure Messaging!"}

# Include routers for modular endpoints
app.include_router(create_user_router, prefix="/api", tags=["User Management"])
app.include_router(login_router, prefix="/api", tags=["Authentication"])
app.include_router(send_message_router, prefix="/api", tags=["Messaging"])
app.include_router(receive_message_router, prefix="/api", tags=["Messaging"])
app.include_router(profile_router, prefix="/api", tags=["User Profile"])
app.include_router(create_friend_router, prefix="/api", tags=["Friend Management"])
