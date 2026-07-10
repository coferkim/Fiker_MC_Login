import argparse
import base64
import hashlib
import json
import os
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


RANDOM_CHARS = b"abdcefghijklmnprqstuvwzyx0123456789ABCDEFGHIJKLMNQPRTSVUWXYZ"
USER_TOKEN_SALT = "0eGsBkhl"

PE_AUTH_KEYS = [
    bytes.fromhex("1c8d9cad811f2f1e3f7b3b5d208dbe83"),
    bytes.fromhex("96271eae017f444b342eb8c53ae106ba"),
    bytes.fromhex("6b5ff1292c60237e776923cf4c49ed9a"),
    bytes.fromhex("f020969c883f9c7adc2c5a130fd1a9cc"),
    bytes.fromhex("607eb25e875e8c9b5c1c5d08648f2d8f"),
    bytes.fromhex("e67d0b4397ccb39c97a78f03315fbe03"),
    bytes.fromhex("3f8f5f7cc35950bf5c9e2b56b20a1f1b"),
    bytes.fromhex("7b8d1d7d674d7d8d917f7d0f2a4d9b48"),
    bytes.fromhex("78289b0c06234b2a2a7d9d7c3c1c1cd3"),
    bytes.fromhex("180928c6af6c703fbd1a1c8c7eb06c8f"),
    bytes.fromhex("9d2b5d4d0c843e445c4e2a3e19cccc3f"),
    bytes.fromhex("ed33b9ef6dcc3d2d45428af516f80a4a"),
    bytes.fromhex("7b6cbc5c215e3e4b7e2f5f5a206823dd"),
    bytes.fromhex("7932137d6a2e1b7e204d6d891ed55d95"),
    bytes.fromhex("0e516bf59bee9eb6712f5e5d63ac89d2"),
    bytes.fromhex("ed8bbb2d808a0d8f353f3f7b0e486be5"),
]


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a: int, n: int) -> int:
    out = 1
    while n:
        if n & 1:
            out = _gmul(out, a)
        a = _gmul(a, a)
        n >>= 1
    return out


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _make_sboxes() -> tuple[list[int], list[int]]:
    sbox = []
    inv = [0] * 256
    for x in range(256):
        y = 0 if x == 0 else _gf_pow(x, 254)
        s = y ^ _rotl8(y, 1) ^ _rotl8(y, 2) ^ _rotl8(y, 3) ^ _rotl8(y, 4) ^ 0x63
        s &= 0xFF
        sbox.append(s)
        inv[s] = x
    return sbox, inv


SBOX, INV_SBOX = _make_sboxes()
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _key_expand(key: bytes) -> list[int]:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i - 1].copy()
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[x] for x in temp]
            temp[0] ^= RCON[i // 4]
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])
    return [b for w in words for b in w]


def _add_round_key(s: list[int], rk: list[int], round_no: int) -> None:
    start = round_no * 16
    for i in range(16):
        s[i] ^= rk[start + i]


def _sub_bytes(s: list[int]) -> None:
    for i, x in enumerate(s):
        s[i] = SBOX[x]


def _inv_sub_bytes(s: list[int]) -> None:
    for i, x in enumerate(s):
        s[i] = INV_SBOX[x]


def _shift_rows(s: list[int]) -> None:
    t = s.copy()
    for r in range(4):
        for c in range(4):
            s[r + 4 * c] = t[r + 4 * ((c + r) & 3)]


def _inv_shift_rows(s: list[int]) -> None:
    t = s.copy()
    for r in range(4):
        for c in range(4):
            s[r + 4 * c] = t[r + 4 * ((c - r) & 3)]


def _mix_columns(s: list[int]) -> None:
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = s[i : i + 4]
        s[i] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        s[i + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        s[i + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        s[i + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)


def _inv_mix_columns(s: list[int]) -> None:
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = s[i : i + 4]
        s[i] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        s[i + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        s[i + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        s[i + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)


def aes128_encrypt_block(block: bytes, key: bytes) -> bytes:
    s = list(block)
    rk = _key_expand(key)
    _add_round_key(s, rk, 0)
    for rnd in range(1, 10):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, rk, rnd)
    _sub_bytes(s)
    _shift_rows(s)
    _add_round_key(s, rk, 10)
    return bytes(s)


def aes128_decrypt_block(block: bytes, key: bytes) -> bytes:
    s = list(block)
    rk = _key_expand(key)
    _add_round_key(s, rk, 10)
    for rnd in range(9, 0, -1):
        _inv_shift_rows(s)
        _inv_sub_bytes(s)
        _add_round_key(s, rk, rnd)
        _inv_mix_columns(s)
    _inv_shift_rows(s)
    _inv_sub_bytes(s)
    _add_round_key(s, rk, 0)
    return bytes(s)


def aes128_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("CBC input must be 16-byte aligned")
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i : i + 16], prev))
        enc = aes128_encrypt_block(block, key)
        out.extend(enc)
        prev = enc
    return bytes(out)


def aes128_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("CBC input must be 16-byte aligned")
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        dec = aes128_decrypt_block(block, key)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)


def compact_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def random16() -> bytes:
    return bytes(random.choice(RANDOM_CHARS) for _ in range(16))


def pe_auth_key(key_index: int) -> bytes:
    if not 0 <= key_index < len(PE_AUTH_KEYS):
        raise ValueError("key_index must be 0..15")
    return bytes(b ^ 0x7C for b in PE_AUTH_KEYS[key_index])


@dataclass(frozen=True)
class PeAuthPacket:
    key_index: int
    iv: bytes
    plain_raw: bytes
    plain_text: str | None
    plain_json: Any | None


class PeAuthCodec:
    @staticmethod
    def encrypt(obj_or_text: Any, key_index: int | None = None, iv: bytes | None = None) -> str:
        if isinstance(obj_or_text, str):
            text = obj_or_text
        else:
            text = compact_json(obj_or_text)
        if key_index is None:
            key_index = random.randrange(16)
        if iv is None:
            iv = random16()
        if len(iv) != 16:
            raise ValueError("iv must be 16 bytes")

        plain = text.encode("utf-8") + random16()
        plain += b"\x00" * ((16 - len(plain) % 16) % 16)
        cipher = aes128_cbc_encrypt(plain, pe_auth_key(key_index), iv)
        control = bytes([(key_index << 4) | 0x0C])
        return (iv + cipher + control).hex()

    @staticmethod
    def decrypt(hex_text: str) -> PeAuthPacket:
        raw = bytes.fromhex(re.sub(r"\s+", "", hex_text))
        if len(raw) < 33 or (len(raw) - 17) % 16:
            raise ValueError(f"bad pe-auth packet length: {len(raw)}")

        control = raw[-1]
        if (control & 0x0F) != 0x0C:
            raise ValueError(f"bad control byte: 0x{control:02x}")

        key_index = (control >> 4) & 0x0F
        iv = raw[:16]
        plain_raw = aes128_cbc_decrypt(raw[16:-1], pe_auth_key(key_index), iv)
        plain_text = _extract_json_text(plain_raw)
        plain_json = None
        if plain_text is not None:
            try:
                plain_json = json.loads(plain_text)
            except json.JSONDecodeError:
                pass
        return PeAuthPacket(key_index, iv, plain_raw, plain_text, plain_json)


class UserTokenCodec:
    @staticmethod
    def generate(login_token: str, path: str, body_text: str = "") -> str:
        seed_md5 = hashlib.md5(login_token.encode()).hexdigest()
        h = hashlib.md5((seed_md5 + body_text + USER_TOKEN_SALT + path).encode()).hexdigest()
        bits = "".join(format(ord(ch), "08b") for ch in h)
        bits = bits[6:] + bits[:6]
        raw = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))
        xored = bytes(b ^ ord(h[i]) for i, b in enumerate(raw))
        token = base64.b64encode(xored).decode()[:16]
        token = token.replace("+", "m").replace("/", "o").replace("=", "")
        return token + "1"

    @staticmethod
    def generate_for_json(login_token: str, path: str, body_obj: Any, spaced: bool = False) -> tuple[str, str]:
        separators = (", ", ": ") if spaced else (",", ":")
        body_text = json.dumps(body_obj, ensure_ascii=False, separators=separators)
        return UserTokenCodec.generate(login_token, path, body_text), body_text


class PeAuthSignCodec:
    @staticmethod
    def generate(message: str, mode: int = 4, rounds: int = 7) -> str:
        data = bytearray(message.encode("utf-8"))

        # The game pads message to a 4-byte boundary with ASCII "0".
        padding = (4 - (len(data) & 3)) & 3
        if padding:
            data.extend(b"0" * padding)

        words = [int.from_bytes(data[i : i + 4], "big") for i in range(0, len(data), 4)]
        while len(words) % 64:
            words.append(0xABCDE987)

        constants = [
            0xF61E2562,
            0xC040B340,
            0x265E5A51,
            0xE9B6C7AA,
            0xA4BEEA44,
            0x4BDECFA9,
            0xF6BB4B60,
            0xBEBFBC70,
            0x655B59C3,
            0x8F0CCC92,
            0xFFEFF47D,
            0x85845DD1,
            0x289B7EC6,
            0xEAA127FA,
            0xD4EF3085,
            0x04881D05,
            0x21E1CDE6,
            0xC33707D6,
            0xF4D50D87,
            0x455A14ED,
        ]
        shift_words = [0x0D0A0601, 0x0E090502, 0x030B0704, 0x050B0803, 0x0E0B0701]

        if not 0 <= mode <= 4:
            raise ValueError("mode must be 0..4")

        k0, k1, k2, k3 = constants[mode * 4 : mode * 4 + 4]
        s0, s1, s2, s3 = shift_words[mode].to_bytes(4, "little")

        mask = 0xFFFFFFFFFFFFFFFF
        a = 0x67452301
        b = 0xEFCDAB89
        c = 0x98BADCFE
        d = 0x10325476

        for _ in range(rounds):
            i = 0
            while i < len(words):
                w = words[i]

                t = ((~b & d) | (c & b)) & mask
                a = (a + t + k0 + w) & mask
                a = (((a << s0) & mask) + b) & mask

                t = ((~d & c) | (d & b)) & mask
                t = (t + k1 + w + a) & mask
                b = (b + ((t << s1) & mask)) & mask

                c = (c ^ d ^ b) & mask
                c = (c + k2 + w + a) & mask
                c = (((c << s2) & mask) + b) & mask

                d = ((d | b) ^ c) & mask
                d = (d + k3 + w + a) & mask
                d = (((d << s3) & mask) + b) & mask

                i += 4

        raw = b"".join((x & 0xFFFFFFFF).to_bytes(4, "little") for x in (a, b, c, d))
        return base64.b64encode(raw).decode("ascii")


def _extract_json_text(data: bytes) -> str | None:
    start_obj = data.find(b"{")
    start_arr = data.find(b"[")
    starts = [x for x in (start_obj, start_arr) if x >= 0]
    if not starts:
        return None

    # pe-auth 明文格式是：JSON + 16 字节随机串 + 0 填充。
    # 随机串里偶尔也可能出现 } 或 ]，所以不能简单用 rfind 截到最后一个括号。
    # 这里让 Python 的 JSONDecoder 从第一个 { 或 [ 开始解析，解析到完整 JSON 就停。
    start = min(starts)
    candidate = data[start:].decode("utf-8", errors="replace")
    try:
        _, end = json.JSONDecoder().raw_decode(candidate)
        return candidate[:end]
    except json.JSONDecodeError:
        return None


def extract_pe_auth_from_httpdebugger_xml(xml_path: str) -> tuple[str, str]:
    text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
    m = re.search(r'<Http\b[^>]*Url="https://g79obtapigtcoregray\.minecraft\.cn/pe-authentication"[\s\S]*?</Http>', text)
    if not m:
        raise RuntimeError("XML not found: /pe-authentication")
    cdatas = re.findall(r"<!\[CDATA\[([\s\S]*?)\]\]>", m.group(0))
    if len(cdatas) < 4:
        raise RuntimeError("pe-authentication CDATA count is invalid")
    return cdatas[1].strip(), cdatas[3].strip()


def self_test() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes128_encrypt_block(pt, key) == ct
    assert aes128_decrypt_block(ct, key) == pt


def _load_json_arg(value: str) -> Any:
    text = Path(value).read_text(encoding="utf-8") if os.path.exists(value) else value
    return json.loads(text)


def _print_packet(packet: PeAuthPacket, as_json: bool = False) -> None:
    print("key_index:", packet.key_index)
    print("iv:", packet.iv.hex())
    if packet.plain_json is not None and as_json:
        print(json.dumps(packet.plain_json, ensure_ascii=False, indent=2))
    elif packet.plain_text is not None:
        print(packet.plain_text)
    else:
        print(packet.plain_raw.hex())


def main() -> None:
    parser = argparse.ArgumentParser(description="NetEase Minecraft pe-authentication and user-token toolkit")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("pe-enc", help="encrypt pe-authentication plaintext JSON to hex body")
    enc.add_argument("json", help="JSON file path or literal JSON text")
    enc.add_argument("--key-index", type=int, help="force key index 0..15")
    enc.add_argument("--iv-hex", help="force 16-byte iv hex for debugging")

    dec = sub.add_parser("pe-dec", help="decrypt pe-authentication hex body/response")
    dec.add_argument("hex", help="hex text, or a file containing hex text")
    dec.add_argument("--json", action="store_true", help="pretty-print JSON")

    xml = sub.add_parser("pe-xml", help="decode pe-authentication request and response from HTTPDebugger XML")
    xml.add_argument("xml")
    xml.add_argument("--json", action="store_true", help="pretty-print JSON")

    tok = sub.add_parser("token", help="generate business API user-token")
    tok.add_argument("--token", help="16-char pe-authentication response entity.token/login_token")
    tok.add_argument(
        "--sead",
        help="compatibility alias for --token; do not pass the 256-char entity.sead",
    )
    tok.add_argument("--path", required=True, help="request path, for example /user-detail/query/other")
    tok.add_argument("--body", default="", help="exact request body text; GET usually uses empty string")
    tok.add_argument("--body-json", help="JSON file path or literal JSON; converted before signing")
    tok.add_argument("--spaced-json", action="store_true", help='use separators ", " and ": " for body-json')

    sign = sub.add_parser("pe-sign", help="generate pe-authentication plaintext sign field")
    sign.add_argument("message", help="message field text, or a file containing it")

    args = parser.parse_args()
    self_test()

    if args.cmd == "pe-enc":
        obj = _load_json_arg(args.json)
        iv = bytes.fromhex(args.iv_hex) if args.iv_hex else None
        print(PeAuthCodec.encrypt(obj, key_index=args.key_index, iv=iv))
        return

    if args.cmd == "pe-dec":
        hex_text = Path(args.hex).read_text(encoding="utf-8") if os.path.exists(args.hex) else args.hex
        _print_packet(PeAuthCodec.decrypt(hex_text), as_json=args.json)
        return

    if args.cmd == "pe-xml":
        req_hex, resp_hex = extract_pe_auth_from_httpdebugger_xml(args.xml)
        for name, hex_text in (("request", req_hex), ("response", resp_hex)):
            print(f"\n[{name}]")
            _print_packet(PeAuthCodec.decrypt(hex_text), as_json=args.json)
        return

    if args.cmd == "token":
        body_text = args.body
        login_token = args.token or args.sead
        if not login_token:
            raise SystemExit("token command needs --token, or legacy --sead with the 16-char entity.token")
        if args.body_json:
            token, body_text = UserTokenCodec.generate_for_json(
                login_token,
                args.path,
                _load_json_arg(args.body_json),
                spaced=args.spaced_json,
            )
        else:
            token = UserTokenCodec.generate(login_token, args.path, body_text)
        print("body:", body_text)
        print("user-token:", token)
        return

    if args.cmd == "pe-sign":
        message = Path(args.message).read_text(encoding="utf-8").strip() if os.path.exists(args.message) else args.message
        print(PeAuthSignCodec.generate(message))
        return


if __name__ == "__main__":
    main()
