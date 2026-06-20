#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WHPKG v1 参考实现（与 C++/C# 对齐）"""
import argparse
import hashlib
import hmac as hmac_mod
import json
import secrets
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PKG_MAGIC = b"WHPKG\x00\x01\x00"
PKG_VERSION = 2
SALT_PAYLOAD = b"WH-PAYLOAD"
PRODUCT_T8_WH8 = 1
PRODUCT_NAMES = {1: "T8/WH8", 2: "WH6", 3: "WH7"}
PAYLOAD_DELIVERY_SOURCE = 0
PAYLOAD_DELIVERY_XTRD_RAW = 1


def xtrd_is_password_protected(data: bytes) -> bool:
    if len(data) < 16 or b"<HEAD>" not in data:
        return False
    text = data.decode("latin1", errors="ignore")
    s = text.find("<CODE>")
    e = text.find("</CODE>")
    if s < 0 or e < 0:
        return False
    body = text[s + 6 : e]
    hex_chars = [c for c in body if c not in "\r\n"]
    return len(hex_chars) >= 32 and all(c in "0123456789ABCDEFabcdef" for c in hex_chars)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def _payload_serialize(source: str, note: str, xtrd_raw: bytes = b"") -> bytes:
    sb = source.encode("utf-8")
    nb = note.encode("utf-8")
    out = struct.pack("<I", len(sb)) + sb + struct.pack("<H", len(nb)) + nb
    if xtrd_raw:
        out += bytes([PAYLOAD_DELIVERY_XTRD_RAW])
        out += struct.pack("<I", len(xtrd_raw)) + xtrd_raw
    else:
        out += bytes([PAYLOAD_DELIVERY_SOURCE])
    return out


def _payload_deserialize(data: bytes):
    off = 0
    (slen,) = struct.unpack_from("<I", data, off)
    off += 4
    source = data[off : off + slen].decode("utf-8")
    off += slen
    (nlen,) = struct.unpack_from("<H", data, off)
    off += 2
    note = data[off : off + nlen].decode("utf-8")
    off += nlen
    xtrd_raw = b""
    if off < len(data):
        mode = data[off]
        off += 1
        if mode == PAYLOAD_DELIVERY_XTRD_RAW and off + 4 <= len(data):
            (xlen,) = struct.unpack_from("<I", data, off)
            off += 4
            xtrd_raw = data[off : off + xlen]
    return source, note, xtrd_raw


def package_build(
    master_key: bytes,
    product_id: int,
    expire_unix: int,
    user: str,
    contact: str,
    indicator_version: str,
    software_name: str,
    source: str,
    note: str,
    nonce: bytes = None,
    xtrd_raw: bytes = b"",
) -> bytes:
    assert len(master_key) == 32
    ub = user.encode("utf-8")
    ivb = indicator_version.encode("utf-8")
    snb = software_name.encode("utf-8")
    pt = _payload_serialize(source, note, xtrd_raw)
    if nonce is None:
        nonce = secrets.token_bytes(12)

    derived = hkdf_sha256(master_key, SALT_PAYLOAD, ub, 32)
    aad = (
        struct.pack("<I", product_id)
        + struct.pack("<q", expire_unix)
        + struct.pack("<H", len(ub))
        + ub
    )
    ct_and_tag = AESGCM(derived).encrypt(nonce, pt, aad)
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    pkg = bytearray()
    pkg += PKG_MAGIC
    pkg += struct.pack("<I", PKG_VERSION)
    hdr_start = len(pkg)
    pkg += struct.pack("<I", 0)

    cb = contact.encode("utf-8")
    pkg += struct.pack("<I", product_id)
    pkg += struct.pack("<q", expire_unix)
    pkg += struct.pack("<H", len(ub))
    pkg += ub
    pkg += struct.pack("<H", len(cb))
    pkg += cb
    pkg += struct.pack("<H", len(ivb))
    pkg += ivb
    pkg += struct.pack("<H", len(snb))
    pkg += snb
    pkg += bytes([12])
    pkg += nonce
    pkg += tag
    pkg += struct.pack("<I", len(ct))
    pkg += ct

    hdr_len = len(pkg) - hdr_start - 4
    struct.pack_into("<I", pkg, hdr_start, hdr_len)
    return bytes(pkg)


def package_parse(blob: bytes, master_key: bytes):
    if blob[:8] != PKG_MAGIC:
        raise ValueError("bad magic")
    (version,) = struct.unpack_from("<I", blob, 8)
    if version != PKG_VERSION:
        raise ValueError(f"unsupported version {version}")
    off = 16
    (product_id,) = struct.unpack_from("<I", blob, off)
    off += 4
    (expire_unix,) = struct.unpack_from("<q", blob, off)
    off += 8
    (ulen,) = struct.unpack_from("<H", blob, off)
    off += 2
    user = blob[off : off + ulen].decode("utf-8")
    off += ulen
    (clen,) = struct.unpack_from("<H", blob, off)
    off += 2
    contact = blob[off : off + clen].decode("utf-8")
    off += clen
    (ivlen,) = struct.unpack_from("<H", blob, off)
    off += 2
    indicator_version = blob[off : off + ivlen].decode("utf-8")
    off += ivlen
    (snlen,) = struct.unpack_from("<H", blob, off)
    off += 2
    software_name = blob[off : off + snlen].decode("utf-8")
    off += snlen
    nlen = blob[off]
    off += 1
    assert nlen == 12
    nonce = blob[off : off + 12]
    off += 12
    tag = blob[off : off + 16]
    off += 16
    (ctlen,) = struct.unpack_from("<I", blob, off)
    off += 4
    ct = blob[off : off + ctlen]

    derived = hkdf_sha256(master_key, SALT_PAYLOAD, user.encode("utf-8"), 32)
    aad = (
        struct.pack("<I", product_id)
        + struct.pack("<q", expire_unix)
        + struct.pack("<H", len(user.encode("utf-8")))
        + user.encode("utf-8")
    )
    pt = AESGCM(derived).decrypt(nonce, ct + tag, aad)
    source, note, xtrd_raw = _payload_deserialize(pt)
    return {
        "product_id": product_id,
        "product_name": PRODUCT_NAMES.get(product_id, "?"),
        "expire_unix": expire_unix,
        "user": user,
        "contact": contact,
        "indicator_version": indicator_version,
        "software_name": software_name,
        "source": source,
        "note": note,
        "xtrd_raw_len": len(xtrd_raw),
        "xtrd_password_protected": xtrd_is_password_protected(xtrd_raw) if xtrd_raw else False,
    }


def selftest():
    fails = []

    def chk(name, got, want):
        ok = got == want
        print(f"[{'OK' if ok else 'FAIL'}] {name}")
        if not ok:
            fails.append(name)

    chk(
        "sha256(abc)",
        hashlib.sha256(b"abc").hexdigest(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    key = b"\x00" * 32
    nonce = b"\x00" * 12
    ct0 = AESGCM(key).encrypt(nonce, b"", None)
    chk("gcm-empty-tag", ct0.hex(), "530f8afbc74536b9a963b4f1c4cb738b")

    master = secrets.token_bytes(32)
    blob = package_build(master, 1, 0, "u", "c", "1.0", "赢鑫看盘", "src", "n")
    info = package_parse(blob, master)
    assert info["source"] == "src"
    assert info["software_name"] == "赢鑫看盘"
    print("[OK] roundtrip")

    print(f"\n==== {'ALL PASSED' if not fails else 'HAS FAILURES'} ====")
    return 0 if not fails else 1


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest").set_defaults(
        func=lambda _: selftest()
    )

    pb = sub.add_parser("build")
    pb.add_argument("--master", required=True)
    pb.add_argument("--user", required=True)
    pb.add_argument("--contact", required=True)
    pb.add_argument("--indicator-version", default="1.0.0")
    pb.add_argument("--software-name", default="WH8Crypto")
    pb.add_argument("--expire", type=int, default=0)
    pb.add_argument("--product", type=int, default=PRODUCT_T8_WH8)
    pb.add_argument("--src", help="plain .myl source (legacy)")
    pb.add_argument("--xtrd", help="password-protected .XTRD from WH8")
    pb.add_argument("--note", default="")
    pb.add_argument("-o", "--output", required=True)

    def cmd_build(a):
        master = bytes.fromhex(a.master)
        xtrd_raw = b""
        source = ""
        if a.xtrd:
            xtrd_raw = open(a.xtrd, "rb").read()
            if not xtrd_is_password_protected(xtrd_raw):
                print("ERROR: XTRD must have <HEAD> and encrypted <CODE> (set view password in WH8 first)")
                return 1
            source = ""
        elif a.src:
            source = open(a.src, encoding="utf-8").read()
        else:
            print("ERROR: specify --src or --xtrd")
            return 1
        blob = package_build(
            master, a.product, a.expire, a.user, a.contact,
            a.indicator_version, a.software_name, source, a.note or "", xtrd_raw=xtrd_raw,
        )
        open(a.output, "wb").write(blob)
        print(f"OK: {len(blob)} bytes -> {a.output}")
        return 0

    pb.set_defaults(func=cmd_build)

    pp = sub.add_parser("parse")
    pp.add_argument("--master", required=True)
    pp.add_argument("-i", "--input", required=True)

    def cmd_parse(a):
        info = package_parse(open(a.input, "rb").read(), bytes.fromhex(a.master))
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0

    pp.set_defaults(func=cmd_parse)
    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
