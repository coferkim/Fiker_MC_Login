import json
from typing import Dict, Any

from fastapi import APIRouter, HTTPException

from utils.client_sender import sender
from utils.config_manager import set_config
from utils.pe_auth import Pe_Auth

router = APIRouter()

@router.post("/login-mc")
async def login_mc(data: Dict[str, Any]):
    try:
        pe_auth = Pe_Auth(data)
        sead, user_id = pe_auth.get_sead_and_id()

        data = {
            "user_id": user_id,
            "sead": sead,
        }

        set_config(data)
        sender.set()

        return {
            "statusCode": 200,
            "user_id": user_id,
            "sead": sead
        }
    except Exception as e:
        return {
            "statusCode": 400,
            "message": "当前登录已经过期，请重新登录。",
            "error": str(e)
        }
