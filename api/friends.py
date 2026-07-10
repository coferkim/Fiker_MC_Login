from fastapi import APIRouter, HTTPException

router = APIRouter()

@router.get("/all-friends")
async def get_all_friends():
    