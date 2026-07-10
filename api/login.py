from typing import Dict, Any

from fastapi import APIRouter, HTTPException

from utils.config_manager import set_config
from utils.pe_auth import Pe_Auth

router = APIRouter()

@router.post("/login-mc")
async def login_mc(data: Dict[str, Any]):
    try:
        pe_auth = Pe_Auth(data)
        sead, id = pe_auth.get_sead_and_id()

        data = {
            "id": id,
            "sead": sead,
            "sauth": data
        }

        set_config(data)

        return {
            "statusCode": 200,
            "sead": sead,
            "id": id
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))