# popi.wtf — Round 2 Findings

**Researcher:** Bores · **Date:** 2026-06-27 · **Round:** 2 (supplementary)

---

## Finding: SIWS field injection

`/api/auth/verify` accepts SIWS messages with arbitrary extra fields
appended beyond the standard SIWS fields. The server validates the standard
fields (URI, Version, Wallet, Issued At, Nonce) but does not reject messages
with unrecognized additional lines.

### Reproduction

1. Request nonce: `POST /api/auth/nonce` with valid wallet + chainId
2. Append fake field: `FakeField: injected_value` to the message
3. Sign the modified message (which includes the extra field)
4. `POST /api/auth/verify` → **200 OK**, JWT issued

```
$ python3 poc_siws_field_injection.py
Chain confusion: 5/5 VULNERABLE
Domain non-validation: 5/5 VULNERABLE
Field injection (new): 5/5 VULNERABLE
URI validation (control): SECURE
```

### Impact

Phishing vector. Attacker appends misleading fields to the SIWS prompt:
```
evil.com wants you to sign in
Wallet: ...
Bonus: 1000 SOL
Airdrop: 50000 tokens
...
```

Victim sees the fake bonus/airdrop text in their wallet's sign prompt and
is more likely to sign. The JWT that results binds to popi's backend
regardless of the fake fields.

The three findings (chain confusion, domain non-validation, field injection)
compound: attacker can change the domain to evil.com, set chain to devnet,
and append fake bonus fields — all accepted.

### Validation

10/10 runs confirmed (2026-06-27). Requires brief cooldown between
batches due to nonce rate limiting (~30s for 10 requests).

### What IS validated correctly

| Field | Validated | Notes |
|-------|-----------|-------|
| URI | ✅ | Must match `https://popi.wtf` |
| Version | ✅ | Must be present |
| Wallet | ✅ | Must match signing key |
| Issued At | ✅ | Must be present |
| Nonce | ✅ | Single-use, replay blocked |

### Not validated

| Field | Status |
|-------|--------|
| Chain | ❌ Any value accepted |
| Domain (line 1) | ❌ Any domain accepted |
| Extra fields | ❌ Silently accepted |

### Negative findings (reconfirmed)

- URI, Version, Wallet, Issued At validated correctly
- Nonce is single-use, replay blocked
- Nonce rate limit prevents flooding (>8 pending nonces = "Too many outstanding nonces")
- JWT Ed25519 signed, HttpOnly+Secure+SameSite=lax
- CSRF token on bind endpoint