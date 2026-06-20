#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""管理端 + 客户端联调脚本（无 GUI，自动化）"""
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from wh_pack import package_build, package_parse, PKG_MAGIC
from build_client import build_bundle, parse_bundle, BUNDLE_MAGIC
from wh_license import license_generate, license_verify

BUILD_SCRIPT = ROOT / "tools" / "build_client.py"
TEST_SRC = ROOT / "build" / "test_indicator.myl"
TEST_SRC2 = ROOT / "build" / "test_indicator2.myl"
DIST = ROOT / "dist" / "integration_client.exe"
MANAGER_EXE = ROOT / "src" / "manager" / "bin" / "Release" / "指标加密工具管理端.exe"


def step(name, ok, detail=""):
    mark = "PASS" if ok else "FAIL"
    line = f"[{mark}] {name}" + (f" - {detail}" if detail else "")
    try:
        print(line)
    except UnicodeEncodeError:
        print(line.encode("ascii", errors="replace").decode("ascii"))
    return ok


def main():
    fails = 0
    print("=== WH8 联调 ===\n")

    # 准备第二个测试指标文件
    if not TEST_SRC2.exists():
        src = TEST_SRC.read_text(encoding="utf-8") if TEST_SRC.exists() else "MA1:MA(CLOSE,5);"
        TEST_SRC2.write_text(src + "\n// secondary", encoding="utf-8")

    # 1) 模拟管理端调用 build_client.py（多指标）
    master = secrets.token_bytes(32)
    out = subprocess.run(
        [
            sys.executable, str(BUILD_SCRIPT),
            "--src", str(TEST_SRC),
            "--src", f"SECOND={TEST_SRC2}",
            "--software-name", "WH8CryptoMulti",
            "--user", "联调用户",
            "--contact", "微信:integration_test",
            "--indicator-version", "1.0.1",
            "--expire", "0",
            "--master", master.hex(),
            "--app-name", "WH8CryptoMulti",
            "-o", str(DIST),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if not step("管理端链路 build_client.py", out.returncode == 0, out.stdout.strip().split("\n")[-1] if out.stdout else out.stderr):
        print(out.stderr)
        fails += 1
    elif not step("产物存在", DIST.is_file(), f"{DIST.stat().st_size} bytes"):
        fails += 1

    # 2) 验证 exe 内嵌 bundle（可能命中代码里的 magic 常量，需遍历找合法包）
    if DIST.is_file():
        data = DIST.read_bytes()
        idx = data.find(BUNDLE_MAGIC)
        if not step("exe 内嵌 bundle magic", idx >= 0, f"offset={idx}" if idx >= 0 else "bundle magic not found"):
            fails += 1
        elif idx >= 0:
            found = None
            pos = idx
            while pos >= 0 and pos + 64 <= len(data):
                try:
                    sn, items = parse_bundle(data[pos:])
                    if len(items) == 2:
                        found = (sn, items)
                        break
                except Exception:
                    pass
                pos = data.find(BUNDLE_MAGIC, pos + 1)
            if step("bundle 解析", found is not None,
                    f"software={found[0] if found else '?'}, items={len(found[1]) if found else 0}"):
                for name, pkg in found[1]:
                    pos = 16
                    pos += 4 + 8  # product + expire
                    ulen = struct.unpack_from("<H", pkg, pos)[0]; pos += 2 + ulen
                    clen = struct.unpack_from("<H", pkg, pos)[0]; pos += 2 + clen
                    ivlen = struct.unpack_from("<H", pkg, pos)[0]; pos += 2
                    ver = pkg[pos : pos + ivlen].decode("utf-8", errors="replace")
                    step(f"indicator_version in {name}", ver == "1.0.1", f"ver={ver}")
            else:
                fails += 1

    # 3) WHPKG roundtrip
    src = TEST_SRC.read_text(encoding="utf-8") if TEST_SRC.exists() else "MA1:MA(CLOSE,5);"
    blob = package_build(master, 1, 0, "u", "c", "1.0.1", "WH8CryptoMulti", src, "")
    info = package_parse(blob, master)
    if not step("WHPKG 加解密", info["source"] == src.strip() or src in info["source"]):
        fails += 1

    # 4) bundle roundtrip
    pkg1 = package_build(master, 1, 0, "u", "c", "1.0.1", "WH8CryptoMulti", src, "")
    pkg2 = package_build(master, 1, 0, "u", "c", "1.0.1", "WH8CryptoMulti", "MA2:MA(CLOSE,10);", "")
    bundle = build_bundle("WH8CryptoMulti", [("A.XTRD", pkg1), ("B.XTRD", pkg2)])
    sn, items = parse_bundle(bundle)
    step("bundle 加解密", sn == "WH8CryptoMulti" and len(items) == 2 and items[0][0] == "A.XTRD")

    # 5) 一机一码离线注册码
    fake_machine = "ROKZ3AIAJ6OY6QYNAA7UBKCCME"
    lic = license_generate(master, fake_machine, 0)
    ok = license_verify(master, lic, fake_machine)
    if not step("注册码生成与验证", ok, f"key={lic[:24]}..."):
        fails += 1
    bad = license_generate(master, fake_machine, 1)
    if not step("过期注册码应失败", not license_verify(master, bad, fake_machine)):
        fails += 1

    # 6) 编译带机器码绑定的客户端
    dist_bind = ROOT / "dist" / "integration_client_bound.exe"
    out_bind = subprocess.run(
        [
            sys.executable, str(BUILD_SCRIPT),
            "--src", str(TEST_SRC),
            "--software-name", "WH8CryptoLicense",
            "--user", "联调用户",
            "--contact", "微信:integration_test",
            "--indicator-version", "1.0.2",
            "--expire", "0",
            "--master", master.hex(),
            "--machine-code", fake_machine,
            "--app-name", "WH8CryptoLicense",
            "-o", str(dist_bind),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if not step("编译一机一码客户端", out_bind.returncode == 0,
                out_bind.stdout.strip().split("\n")[-1] if out_bind.stdout else out_bind.stderr):
        fails += 1

    # 7) 管理端 exe 存在
    step("管理端 exe 已编译", MANAGER_EXE.is_file(), str(MANAGER_EXE))

    # 6) 启动客户端（无 WT8 时应快速失败或弹窗）
    print("\n--- 启动客户端（5 秒超时，无 WT8 时预期弹窗/报错）---")
    if DIST.is_file():
        try:
            proc = subprocess.Popen([str(DIST)], cwd=str(DIST.parent))
            time.sleep(3)
            rc = proc.poll()
            if rc is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                step("客户端启动", True, "进程运行中（可能在等 WT8 或 SmartScreen/文件对话框）")
            else:
                codes = {0: "成功", 1: "授权过期", 2: "注入/WT8失败", 3: "校验失败"}
                step("客户端退出", True, f"exit={rc} ({codes.get(rc, '未知')})")
        except OSError as e:
            step("客户端启动", False, str(e))
            fails += 1

    print(f"\n=== 联调结束: {'全部通过' if fails == 0 else f'{fails} 项失败'} ===")
    print("\n手动步骤:")
    print(f"  1. 双击管理端: {MANAGER_EXE}")
    print(f"  2. 填写信息后点「生成客户端 exe」")
    print(f"  3. 安装 WT8 后运行: {DIST}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
