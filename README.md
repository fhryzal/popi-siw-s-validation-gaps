# popi.wtf — SIWS Validation Gaps (Round 2)

**Researcher:** Bores · **Date:** 2026-06-27
**Repo:** https://github.com/fhryzal/popi-siw-s-validation-gaps

---

## Summary

Three SIWS message validation gaps in popi.wtf's `/api/auth/verify`, plus two supporting weaknesses, enable a cross-origin phishing flow that misleads victims into signing wallet messages.

---

## Finding 1: Chain field not validated (10/10)

The `Chain` field in the SIWS message is not checked against the `chainId`
parameter from the nonce request. Any chain value is accepted.

```
/api/auth/nonce {chainId: "mainnet-beta"} → message "Chain: mainnet-beta"
Change Chain to "devnet" → sign → verify → 200 OK
Also: devnet nonce → "Chain: mainnet-beta" → 200 OK (reverse confirmed)
```

---

## Finding 2: Domain line not validated (10/10)

The first line of the SIWS message sets the domain the wallet displays.
It is not validated against popi.wtf.

```
"popi.wtf wants you to sign in" → change to "evil.com wants you..." → 200 OK
```

Victim's wallet shows "evil.com" but the JWT binds to popi backend.

---

## Finding 3: Extra fields silently accepted (10/10)

Arbitrary fields appended to the SIWS message are accepted without
rejection. Server does not validate the message structure beyond the
standard required fields.

```
Append "Bonus: 50000 TOKENS\nAirdrop: CLAIM_NOW" → sign → verify → 200 OK
```

---

## Finding 4: No Origin validation on auth endpoints

`/api/auth/nonce` and `/api/auth/verify` respond to requests with
any `Origin` header, including `https://evil.com`. There is no CORS
policy enforcement on these endpoints.

```
POST /api/auth/nonce {Origin: "https://evil.com"} → 200 OK
POST /api/auth/verify {Origin: "https://evil.com"} → 200 OK + JWT
```

---

## Compound impact — full phishing flow

All four gaps combine into a working cross-origin phishing flow:

1. evil.com fetches a nonce from popi.wtf (no CORS block)
2. evil.com modifies the message (domain → evil.com, chain → devnet,
   appends fake bonus/airdrop fields)
3. Victim signs — wallet shows "evil.com wants you to sign in" with
   bonus fields, but the nonce is from popi
4. evil.com submits to popi → 200 OK → JWT issued
5. evil.com uses JWT to call `/api/auth/me` → victim's wallet exposed

**PoC:** `poc_phishing_flow.py`

In a real browser, SameSite=lax limits cross-site cookie usage to
top-level navigations only, and HttpOnly prevents JS from reading the
session cookie. But the victim can be redirected to popi.wtf with an
already-active session, or social-engineered into performing actions
on a popi page where the attacker controls what they see.

---

## What IS validated correctly

| Field | Status | Notes |
|-------|--------|-------|
| URI | ✅ | Must match `https://popi.wtf` |
| Version | ✅ | Must be present |
| Wallet | ✅ | Must match signing key |
| Issued At | ✅ | Must be present |
| Nonce | ✅ | Single-use, replay blocked |
| Signature | ✅ | Must match message + key |

## What is NOT validated

| Field | Status | Impact |
|-------|--------|--------|
| Chain | ❌ | Any chain accepted |
| Domain (line 1) | ❌ | Any domain shown in wallet |
| Extra fields | ❌ | Fake bonus/airdrop text |
| Origin header | ❌ | Cross-origin requests work |

---

## Negative findings (reconfirmed)

- URI validation is strict (any change = 401)
- Nonce is single-use with replay protection
- Nonce rate limit prevents flooding
- JWT Ed25519 signed, HttpOnly, Secure, SameSite=lax
- CSRF token on bind endpoint
- No XSS reflection found on search/404/API error pages
- CSP prevents inline script execution
- Cookie HttpOnly prevents direct JS theft

---

## Fix recommendations

1. Validate `Chain` field against `chainId` from nonce request
2. Validate first-line domain against server hostname
3. Reject messages with unrecognized fields (strict SIWS parsing)
4. Add `Access-Control-Allow-Origin` with explicit allowlist (or reject
   requests with unexpected `Origin` headers)

---

## Run

```bash
pip install solders base58
python3 poc_phishing_flow.py
python3 poc_siws_field_injection.py
```