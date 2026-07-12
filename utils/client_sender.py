import requests

from utils.config_manager import get_config
from utils.mc_auth_toolkit import UserTokenCodec


class Sender:
    def __init__(self):
        self.user_id = None
        self.sead = None
        self.api = "https://g79mclobt.minecraft.cn"

    def set(self):
        self.user_id = get_config()["user_id"]
        self.sead = get_config()["sead"]

    def __get_user_token_and_data(self, path, payload):
        return UserTokenCodec.generate_for_json(self.sead, path, payload)

    def post(self, path, data):
        user_token, data = self.__get_user_token_and_data(path, payload=data)
        headers = {
            "user-token": user_token,
            "user-id": self.user_id
        }
        response = requests.post(self.api + path, headers=headers, data=data).json()

        return response

sender = Sender()