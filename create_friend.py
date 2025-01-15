from fastapi import APIRouter, HTTPException
from typing import List
from database import users_collection

router = APIRouter()

# Send Friend Request
@router.post("/send_friend_request")
async def send_friend_request(sender_id: str, receiver_id: str):
    sender = await users_collection.find_one({"_id": sender_id})
    receiver = await users_collection.find_one({"_id": receiver_id})

    if not sender or not receiver:
        raise HTTPException(status_code=404, detail="User not found.")
    
    if sender_id in receiver.get("friend_requests", []):
        raise HTTPException(status_code=400, detail="Friend request already sent.")
    
    if sender_id in receiver.get("friends", []):
        raise HTTPException(status_code=400, detail="Already friends.")
    
    # Add the sender's ID to the receiver's friend requests
    await users_collection.update_one(
        {"_id": receiver_id},
        {"$addToSet": {"friend_requests": sender_id}}
    )
    return {"message": "Friend request sent."}

# Get Friend Requests
@router.get("/get_friend_requests")
async def get_friend_requests(user_id: str) -> List[str]:
    user = await users_collection.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user.get("friend_requests", [])

# Accept Friend Request
@router.post("/accept_friend_request")
async def accept_friend_request(user_id: str, sender_id: str):
    user = await users_collection.find_one({"_id": user_id})
    sender = await users_collection.find_one({"_id": sender_id})

    if not user or not sender:
        raise HTTPException(status_code=404, detail="User or sender not found.")

    if sender_id not in user.get("friend_requests", []):
        raise HTTPException(status_code=400, detail="No friend request found from this user.")

    # Add each other to friends list
    await users_collection.update_one(
        {"_id": user_id},
        {"$addToSet": {"friends": sender_id}, "$pull": {"friend_requests": sender_id}}
    )
    await users_collection.update_one(
        {"_id": sender_id},
        {"$addToSet": {"friends": user_id}}
    )
    return {"message": f"You are now friends with {sender_id}."}

# Get Friends List
@router.get("/get_friends")
async def get_friends(user_id: str) -> List[str]:
    user = await users_collection.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user.get("friends", [])