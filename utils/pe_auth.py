import json
import requests
import uuid
import base64
from .auth_tools import *

ENGINE_VERSION = "3.8.43.296051"
PATCH_VERSION = "3.8.44.296250"
ENGINE_MAGIC = "e0cd6efb2c8e2260ac1a4f226277538f"
PATCH_MAGIC = "a39e7f98b9c673b52f74e5c24c8aa5902b3e7ca013bb30a74d822579860c042b"

class Pe_Auth:
    def __init__(self, data: dict):
        self.__aim_info = None
        self.__data = json.loads(data["sauth_json"])
        self.__client_login_sn = self.__data["client_login_sn"]
        self.__udid = self.__data["udid"]
        self.__device_id = self.__data["deviceid"]
        self.__sdkuid = self.__data["sdkuid"]
        self.__ip = ""



    def __get_ticket(self):
        url = "https://service.mkey.163.com/mpay/api/users/create_ticket"

        form_data = {
            "device_id": self.__device_id,
            "game_id": "aecglf6ee4aaaarz-g-a50",
            "token": self.__data["sessionid"],
        }

        response = requests.post(url, data=form_data).json()
        return response["ticket"]

    def __get_a50_token(self):
        url = "https://service.mkey.163.com/mpay/api/users/login/ticket"

        form_data = {
            "cv": "c4.16.0",
            "app_channel": "a50_sdk_cn",
            "device_id": self.__device_id,
            "game_id": "aecfrxodyqaaaajp-g-x19",
            "ticket": self.__get_ticket(),
        }

        response = requests.post(url, data=form_data).json()
        self.__ip = response["user"]["pc_ext_info"]["src_client_ip"]
        return response["user"]["token"]

    def __get_x19_uni_sauth(self):
        url = "https://mgbsdk.matrix.netease.com/x19/sdk/uni_sauth"

        session_id = self.__get_a50_token()

        self.__aim_info = {
            "aim": self.__ip,
            "country": "CN",
            "tz": "+0800",
            "tzid": ""
        }

        data = {
            "gameid": "x19",
            "login_channel": "netease",
            "app_channel": "a50_sdk_cn",
            "platform": "pc",
            "sdkuid": self.__sdkuid,
            "sessionid": session_id,
            "sdk_version": "4.16.0",
            "udid": self.__udid,
            "deviceid": self.__device_id,
            "client_login_sn": self.__client_login_sn,
            "gas_token": "",
            "source_platform": "pc",
            "ip": self.__ip,
            "get_access_token": "1",
            "aim_info": json.dumps(self.__aim_info),
            "lang": "zh"
        }

        response = requests.post(url, data=data).json()
        text_json = json.loads(base64.b64decode(response["unisdk_login_json"]))
        return text_json["oauth2"]["access_token"], session_id

    def __make_pe_auth_base(self):
        seed = str(uuid.uuid4())
        message = f"{ENGINE_VERSION}{ENGINE_MAGIC}{PATCH_VERSION}{PATCH_MAGIC}{seed}"

        access_token, session_id = self.__get_x19_uni_sauth()

        sa_data = {
            "app_channel": "a50_sdk_cn",
            "app_ver": PATCH_VERSION,
            "device_model": "Win32",
            "emulator": 0,
            "first_udid": self.__udid,
            "is_guest": 0,
            "launcher_type": "PE_C++",
            "network": "",
            "os_name": "windows",
            "os_ver": "10.0.26200",
            "root": False,
            "sdk_ver": "4.16.0",
            "start_type": "default",
            "tdid": "",
            "udid": self.__udid,
        }

        base_data = {
            "engine_version": ENGINE_VERSION,
            "extra_param": "extra",
            "message": message,
            "patch_version": PATCH_VERSION,
            "pay_channel": "netease",
            "sa_data": json.dumps(sa_data),
            "sauth_json": {
                "access_token": access_token,
                "aim_info": json.dumps(self.__aim_info),
                "app_channel": "a50_sdk_cn",
                "client_login_sn": self.__client_login_sn,
                "deviceid": self.__device_id,
                "gameid": "x19",
                "gas_token": "",
                "get_access_token": "1",
                "ip": self.__ip,
                "login_channel": "netease",
                "platform": "pc",
                "sdk_version": "4.16.0",
                "sdkuid": self.__sdkuid,
                "sessionid": session_id,
                "source_platform": "pc",
                "tdid": "",
                "udid": self.__udid,
            },
            "seed": seed,
            "sign": get_pe_auth_sign(message),
        }

        return base_data

    def __auth(self):
        url = "https://g79obtapigtcoregray.minecraft.cn/pe-authentication"
        data = encrypt_pe_auth(self.__make_pe_auth_base())
        response = requests.post(url, data)
        return decrypt_pe_auth(response.text)

    def get_sead_and_id(self):
        response = self.__auth()
        sead = response["entity"]["token"]
        id = response["entity"]["entity_id"]
        return sead, id
