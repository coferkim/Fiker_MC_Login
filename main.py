from fastapi import FastAPI

from api import login, friends
from utils.client_sender import sender

app = FastAPI()
sender.set()

@app.get("/")
def root():
    return {"message": "API版本：，运行正常"}

app.include_router(login.router)
app.include_router(friends.router, prefix="/friends")