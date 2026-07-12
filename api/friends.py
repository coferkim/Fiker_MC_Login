from fastapi import APIRouter, HTTPException

from utils.client_sender import sender

router = APIRouter()

@router.get("/all-friends")
async def get_all_friends():
    data = {"with_game_state": False, "with_dynamic_head_img": 1}
    response = sender.post("/user-allfriends", data)
    return response

@router.get("/all-friends-detail")
async def get_all_friends_detail():
    data = {}
    response = sender.post("/user-allfriends-with-detail", data)
    return response

@router.get("/search-by-name")
async def search_friends_by_name(name: str):
    if name is None:
        return {"message": "请输入玩家名字！"}
    data = {"name_or_mail": name}

    response = sender.post("/user-search-friend", data)
    return response

@router.get("/search-by-id")
async def search_friends_by_id(user_id: int):
    if user_id is None:
        return {"message": "请输入玩家编号！"}
    data = {"name_or_mail": str(user_id), "role_id": user_id}

    response = sender.post("/user-search-friend", data)
    return response

