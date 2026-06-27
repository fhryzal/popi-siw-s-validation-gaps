# popi.wtf — SIWS message validation gaps

4 things popi's /api/auth/verify doesn't check in the SIWS message.

## 1. Chain field

Nonce request sends `chainId`, but verify doesn't compare it to the `Chain`
field in the signed message. Both directions:

    nonce chainId=mainnet-beta, msg Chain=devnet → 200
    nonce chainId=devnet, msg Chain=mainnet-beta → 200

## 2. Domain (first line)

Wallet shows the first line as the requesting domain. Server doesn't check
if it matches popi.wtf:

    "popi.wtf wants you to sign in" → "evil.com wants you..." → 200

## 3. Extra fields

Anything appended after the standard fields is silently accepted:

    msg + "\nBonus: 50000 TOKENS\nAirdrop: CLAIM_NOW" → 200

## 4. Origin header

Both /api/auth/nonce and /api/auth/verify accept cross-origin requests
with no Origin check:

    POST /api/auth/verify {Origin: "https://evil.com"} → 200 OK + JWT

## Full phishing flow

All four gaps together: evil.com fetches nonce from popi, rewrites the
message (fake domain, fake chain, fake bonus), victim signs, popi issues
a valid JWT. `poc_phishing_flow.py` walks through the full flow.

## What the server does check

URI (must match https://popi.wtf), Version, Wallet, Issued At, Nonce
(single-use), Signature. All six validated correctly — confirmed.

## Run

    pip install solders base58
    python3 poc_phishing_flow.py
    python3 poc_siws_field_injection.py