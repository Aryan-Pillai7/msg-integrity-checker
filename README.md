# Message Integrity Checker using HMAC-SHA256

Information and Network Security course project.

## Problem Statement

A message sent over a network can be changed or faked by an attacker (Mallory) sitting between
the sender (Alice) and the receiver (Bob). Bob needs a way to tell whether the message he received
is exactly what Alice sent, and that it really came from someone who knows their shared secret key.

## Algorithm Used

**HMAC-SHA256**: a keyed hash, `HMAC(K, m) = SHA256((K ⊕ opad) ‖ SHA256((K ⊕ ipad) ‖ m))`, giving a 256-bit (64 hex character) tag.

## How It Works

1. **Sign:** Alice computes `tag = HMAC-SHA256(key, message)` and sends `(message, tag)`.
2. **Transmit:** The pair travels over the network, where Mallory can read or modify it but does not know the key.
3. **Verify:** Bob recomputes `HMAC-SHA256(key, received_message)` and compares it with the received tag
   (constant-time). Equal tags mean **VERIFIED**; anything else means **REJECTED**.

## Scenarios and Results

Key `secret123`, message `Pay Bob $100` (output of `python integrity.py`):

| Scenario  | What Mallory does                              | Message Bob receives | Result   |
|-----------|------------------------------------------------|----------------------|----------|
| Normal    | Nothing, forwards the packet unchanged         | `Pay Bob $100`       | VERIFIED |
| Tampering | Changes one character, keeps Alice's tag       | `Xay Bob $100`       | REJECTED |
| Forgery   | Sends her own message with a random 256-bit tag | `Pay Mallory $1000`  | REJECTED |

Changing a single character produces a completely different tag (avalanche effect), and guessing a valid
tag without the key has a chance of 1 in 2^256.

Cross-check: `HMAC-SHA256("secret123", "hello")` =
`6edb7e533ff92551f967bc02167127b93850a6ba3433efaca8bcfd24783b160d` in both Python and the browser.

## Applications

- API request signing (AWS Signature v4, webhook signatures from GitHub and Stripe)
- JSON Web Tokens signed with HS256
- TLS and IPsec record integrity
- Tamper-proof cookies and session tokens
- One-time passwords (HOTP/TOTP are built on HMAC)

## Conclusion

HMAC-SHA256 detects any change to a message and stops forgery by anyone who does not hold the shared key.
It gives integrity and authentication with only a hash function, but it does not hide the message
(no confidentiality) and cannot prove to a third party who sent it (no non-repudiation, since both sides share the key).

## Running the Project

No external packages or server are needed. Python 3.8+ and any modern browser.

```bash
python integrity.py          # prints the results table
python -m pytest -q          # runs the tests (needs pytest)
```

Open `index.html` directly in a browser (double-click it; `file://` works). Click **Send**, then
**Tamper** or **Forge** under Mallory and watch Bob's result.

| File                | Contents                                                    |
|---------------------|-------------------------------------------------------------|
| `integrity.py`      | `make_tag`, `verify`, and the three scenarios               |
| `test_integrity.py` | pytest tests                                                |
| `index.html`        | Visual demo using the Web Crypto API (`crypto.subtle`)      |
