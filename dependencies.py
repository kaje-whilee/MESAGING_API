from fastapi import HTTPException, Request, status
from jose import jwt, JWTError

SECRET_KEY = "your_jwt_secret_key"
ALGORITHM = "HS256"

async def get_current_user(request: Request) -> str:
    """
    Extract and validate the user ID from the JWT token in cookies.

    Args:
        request (Request): The HTTP request containing cookies.

    Returns:
        str: The user ID if the token is valid.

    Raises:
        HTTPException: If the token is missing, invalid, or expired.
    """
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: User ID missing",
                headers={"WWW-Authenticate": "Bearer"}
            )
        return user_id
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )
