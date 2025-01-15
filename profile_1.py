from fastapi import APIRouter, Depends, HTTPException, status
from database import users_collection
from dependencies import get_current_user  # Ensure dependency is correctly implemented
from rate_limiter import rate_limiter

router = APIRouter()

@router.get("/profile", status_code=200)
async def get_profile(current_user: str = Depends(get_current_user)):
    """
    Retrieve the profile information of the authenticated user.
    """
    await rate_limiter(user_id=current_user, limit=100, period=60)
    user = await users_collection.find_one({"user_id": current_user})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "full_name": user.get("full_name", "N/A"),
        "created_at": user["created_at"],
        "updated_at": user["updated_at"]
    }
