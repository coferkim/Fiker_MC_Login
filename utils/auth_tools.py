from typing import Any
from .mc_auth_toolkit import PeAuthCodec, PeAuthSignCodec


def get_pe_auth_sign(message: str, mode: int = 4, rounds: int = 7) -> str:
    return PeAuthSignCodec.generate(message, mode=mode, rounds=rounds)

def encrypt_pe_auth(plain_json: dict[str, Any] | str) -> str:
    return PeAuthCodec.encrypt(plain_json)

def decrypt_pe_auth(hex_body: str) -> dict[str, Any] | str:
    packet = PeAuthCodec.decrypt(hex_body)

    if packet.plain_json is not None:
        return packet.plain_json

    if packet.plain_text is not None:
        return packet.plain_text

    return packet.plain_raw.hex()
