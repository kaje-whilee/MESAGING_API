from fastapi import APIRouter, HTTPException, Depends
from database import messages_collection, users_collection
from Encryptor import Encryptor
from IntegrityChecker import IntegrityChecker
from KeyManager import KeyManager
import base64
from dependencies import get_current_user
from rate_limiter import rate_limiter

router = APIRouter()
encryptor = Encryptor()
checker = IntegrityChecker()
km = KeyManager()

@router.get("/receive-message", status_code=200)
async def receive_message(current_user: str = Depends(get_current_user)):
    """
    Retrieve all encrypted messages for the authenticated user.
    """
    await rate_limiter(user_id=current_user, limit=100, period=60)
    recipient = await users_collection.find_one({"user_id": current_user})
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    recipient_private_key = km.deserialize_private_key(recipient["private_key"].encode())
    messages = messages_collection.find({"recipient_id": current_user})
    decrypted_messages = []

    async for msg in messages:
        sender = await users_collection.find_one({"user_id": msg["sender_id"]})
        if not sender:
            continue

        sender_public_key = km.deserialize_public_key(sender["public_key"].encode())
        shared_secret = km.derive_shared_secret(recipient_private_key, sender_public_key)

        encrypted_message = base64.b64decode(msg["message"])
        mac = base64.b64decode(msg["mac"])

        if not checker.verify_mac(encrypted_message, shared_secret, mac):
            continue

        decrypted_message = encryptor.decrypt(encrypted_message, shared_secret)
        decrypted_messages.append({"sender_id": msg["sender_id"], "message": decrypted_message})

    return {"messages": decrypted_messages}
