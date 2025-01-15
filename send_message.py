from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from datetime import datetime
from database import messages_collection, users_collection
from Encryptor import Encryptor
from IntegrityChecker import IntegrityChecker
from KeyManager import KeyManager
import base64
from dependencies import get_current_user
from slowapi.util import get_remote_address
from slowapi import Limiter
from rate_limiter import rate_limiter

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
encryptor = Encryptor()
checker = IntegrityChecker()
km = KeyManager()

class SendMessageRequest(BaseModel):
    recipient_id: str
    message: str = Field(..., max_length=1000, description="Message must be 1000 characters or less")

@router.post("/send-message", status_code=200)
@limiter.limit("1000/minute")
async def send_message(request: SendMessageRequest, current_user: str = Depends(get_current_user)):
    """
    Send an encrypted message to another user.
    """
    await rate_limiter(user_id=current_user, limit=100, period=60)
    sender = await users_collection.find_one({"user_id": current_user})
    recipient = await users_collection.find_one({"user_id": request.recipient_id})

    if not sender:
        raise HTTPException(status_code=404, detail="Sender not found")
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    sender_private_key = km.deserialize_private_key(sender["private_key"].encode())
    recipient_public_key = km.deserialize_public_key(recipient["public_key"].encode())

    shared_secret = km.derive_shared_secret(sender_private_key, recipient_public_key)
    encrypted_message = encryptor.encrypt(request.message, shared_secret)
    mac = checker.generate_mac(encrypted_message, shared_secret)

    message_data = {
        "sender_id": current_user,
        "recipient_id": request.recipient_id,
        "message": base64.b64encode(encrypted_message).decode("utf-8"),
        "mac": base64.b64encode(mac).decode("utf-8"),
        "created_at": datetime.utcnow(),
    }

    await messages_collection.insert_one(message_data)
    return {"status": "Message sent successfully"}
