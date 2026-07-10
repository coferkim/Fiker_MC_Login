from fastapi import FastAPI
from typing import Optional

from api import login

app = FastAPI()

@app.get("/")
def root():
    return {"message": "API版本：，运行正常"}

app.include_router(login.router)