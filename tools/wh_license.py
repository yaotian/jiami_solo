#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一机一码离线注册码（与 C++/C# 对齐）"""
import base64
import hmac
import hashlib
import struct
import time

LICENSE_MAGIC = b"REG\x00"
LICENSE_VERSION = 1


def _machine_hash_from_code(machine_code: str) -> bytes:
    """将 Base32 机器码字符串还原为 16 字节哈希。"""
    # Python base32 只接受大写并需要补齐到 8 的倍数
    s = machine_code.upper()
    pad = (8 - len(s) % 8) % 8
    s += "=" * pad
    return base64.b32decode(s, casefold=True)


def _machine_hash_from_raw(data: bytes) -> bytes:
    """任意输入生成 16 字节机器码哈希。"""
    return hashlib.sha256(data).digest()[:16]


def _compute_signature(master_key: bytes, machine_hash: bytes, expire_unix: int, flags: int) -> bytes:
    buf = struct.pack("<B", LICENSE_VERSION)
    buf += machine_hash[:8]
    buf += struct.pack("<q", expire_unix)
    buf += struct.pack("<B", flags)
    return hmac.new(master_key, buf, hashlib.sha256).digest()[:16]


def license_generate(master_key: bytes, machine_code: str, expire_unix: int, flags: int = 0) -> str:
    """根据机器码字符串生成离线注册码。"""
    machine_hash = _machine_hash_from_code(machine_code)
    signature = _compute_signature(master_key, machine_hash, expire_unix, flags)
    buf = LICENSE_MAGIC
    buf += struct.pack("<B", LICENSE_VERSION)
    buf += machine_hash[:8]
    buf += struct.pack("<q", expire_unix)
    buf += struct.pack("<B", flags)
    buf += signature
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")


def license_parse(license_key: str) -> dict:
    """解析注册码，返回 dict 或抛出 ValueError。"""
    s = license_key.replace(" ", "").replace("\n", "").replace("\r", "")
    pad = (4 - len(s) % 4) % 4
    raw = base64.urlsafe_b64decode(s + "=" * pad)
    if len(raw) != 38:
        raise ValueError(f"bad license length {len(raw)}")
    if raw[:4] != LICENSE_MAGIC:
        raise ValueError("bad license magic")
    if raw[4] != LICENSE_VERSION:
        raise ValueError("bad license version")
    return {
        "machine_hash": raw[5:13],
        "expire_unix": struct.unpack_from("<q", raw, 13)[0],
        "flags": raw[21],
        "signature": raw[22:38],
    }


def license_verify(master_key: bytes, license_key: str, machine_code: str, now_utc: int = None) -> bool:
    """验证注册码是否匹配当前机器且未过期。"""
    if now_utc is None:
        now_utc = int(time.time())
    try:
        lic = license_parse(license_key)
    except Exception:
        return False
    machine_hash = _machine_hash_from_code(machine_code)
    expected = _compute_signature(master_key, machine_hash, lic["expire_unix"], lic["flags"])
    if expected != lic["signature"]:
        return False
    if machine_hash[:8] != lic["machine_hash"]:
        return False
    if lic["expire_unix"] > 0 and now_utc > lic["expire_unix"]:
        return False
    return True


def selftest():
    import secrets
    master = secrets.token_bytes(32)
    # 模拟一个机器码
    fake_hash = secrets.token_bytes(16)
    machine_code = base64.b32encode(fake_hash).decode("ascii").rstrip("=")
    key = license_generate(master, machine_code, 0)
    assert license_verify(master, key, machine_code), "永久注册码验证失败"

    expired = license_generate(master, machine_code, 1)
    assert not license_verify(master, expired, machine_code), "应已过期"

    wrong_machine = base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
    assert not license_verify(master, key, wrong_machine), "机器码不匹配应失败"

    print("[OK] wh_license selftest passed")


if __name__ == "__main__":
    selftest()
