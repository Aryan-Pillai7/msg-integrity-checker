"""Message Integrity Checker using HMAC-SHA256 (Python standard library only)."""
import hashlib
import hmac
import secrets


def make_tag(key: str, message: str) -> str:
    """Return the HMAC-SHA256 tag of `message` under `key` as 64 hex characters."""
    # Step 1: encode key and message as UTF-8 bytes (the browser does the same).
    key_bytes = key.encode("utf-8")
    msg_bytes = message.encode("utf-8")
    # Step 2: HMAC = SHA256((K ^ opad) || SHA256((K ^ ipad) || message)).
    mac = hmac.new(key_bytes, msg_bytes, hashlib.sha256)
    # Step 3: output the 32-byte digest as 64 lowercase hex characters.
    return mac.hexdigest()


def verify(key: str, message: str, tag: str) -> bool:
    """Recompute the tag and compare it with the received one."""
    expected = make_tag(key, message)
    # Constant-time comparison so an attacker cannot learn the tag byte by byte.
    return hmac.compare_digest(expected, tag.lower())


def tamper(message: str) -> str:
    """Mallory changes exactly one character of the message."""
    if not message:
        return "X"
    first = message[0]
    return ("X" if first != "X" else "Y") + message[1:]


def run_scenarios(key: str = "secret123", message: str = "Pay Bob $100"):
    """Run Normal, Tampering and Forgery; return a list of result rows."""
    tag = make_tag(key, message)  # Alice computes the tag and sends (message, tag).
    rows = []

    # 1. Normal: message and tag arrive unchanged.
    rows.append(("Normal", message, tag, verify(key, message, tag)))

    # 2. Tampering: Mallory edits the message but cannot recompute the tag (no key).
    changed = tamper(message)
    rows.append(("Tampering", changed, tag, verify(key, changed, tag)))

    # 3. Forgery: Mallory sends her own message with a random 256-bit tag.
    forged_msg = "Pay Mallory $1000"
    forged_tag = secrets.token_hex(32)
    rows.append(("Forgery", forged_msg, forged_tag, verify(key, forged_msg, forged_tag)))
    return rows


def print_table(rows, key: str) -> None:
    """Print the scenario results as a plain-text table."""
    print(f"Shared secret key: {key!r}\n")
    header = f"{'Scenario':<10} | {'Message received':<18} | {'Tag (first 16 hex)':<18} | Result"
    print(header)
    print("-" * len(header))
    for name, msg, tag, ok in rows:
        result = "VERIFIED" if ok else "REJECTED"
        print(f"{name:<10} | {msg:<18} | {tag[:16]:<18} | {result}")


if __name__ == "__main__":
    KEY = "secret123"
    print_table(run_scenarios(KEY), KEY)
    # Reference value: the browser demo must show the same tag for this input.
    print(f"\nmake_tag('secret123', 'hello') = {make_tag('secret123', 'hello')}")
