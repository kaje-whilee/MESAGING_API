from fastapi import HTTPException
from datetime import datetime, timedelta
from database import rate_limit_collection

async def rate_limiter(user_id: str, limit: int, period: int):
    """
    Enforce rate limiting based on user ID or IP.
    :param user_id: The unique identifier for the user (or IP address).
    :param limit: Maximum number of requests allowed.
    :param period: Period in seconds for the limit.
    :raises HTTPException: If the rate limit is exceeded.
    """
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=period)

    # Check existing requests in the time window
    count = await rate_limit_collection.count_documents({
        "user_id": user_id,
        "timestamp": {"$gte": window_start}
    })

    if count >= limit:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later."
        )

    # Log the current request
    await rate_limit_collection.insert_one({
        "user_id": user_id,
        "timestamp": now
    })
