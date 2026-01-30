import base64
import json
import time
import re
import binascii

def b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def decode_jwt(token: str):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format (must have 3 parts)")

    header_b64, payload_b64, signature_b64 = parts

    header_bytes = b64url_decode(header_b64)
    payload_bytes = b64url_decode(payload_b64)
    signature_bytes = b64url_decode(signature_b64)

    header = json.loads(header_bytes)
    payload = json.loads(payload_bytes)

    return header, payload, signature_bytes

def validate_steam_jwt(payload: dict):
    now = int(time.time())
    issues = []

    if payload.get("iss") != "steam":
        issues.append("Issuer is not 'steam'")

    sub = payload.get("sub", "")
    if not re.fullmatch(r"7656119\d{10}", sub):
        issues.append("sub does not look like a SteamID64")

    if "exp" in payload and now > payload["exp"]:
        issues.append("Token is expired")

    if "nbf" in payload and now < payload["nbf"]:
        issues.append("Token is not yet valid (nbf)")

    return issues

def pause():
    input("\nPress ENTER to exit...")

if __name__ == "__main__":
    token = input("Paste JWT:\n").strip()

    try:
        header, payload, signature_bytes = decode_jwt(token)
    except Exception as e:
        print("❌ Failed to decode JWT:", e)
        pause()
        exit(1)

    print("\n=== HEADER (decoded) ===")
    print(json.dumps(header, indent=2))

    print("\n=== PAYLOAD (decoded) ===")
    print(json.dumps(payload, indent=2))

    print("\n=== SIGNATURE (decoded bytes) ===")
    print(f"Length: {len(signature_bytes)} bytes")
    print("Hex preview:")
    print(binascii.hexlify(signature_bytes).decode()[:80] + "...")

    print("\n=== SIGNATURE MEANING ===")
    print("- This is NOT encrypted data")
    print("- It is a cryptographic signature (Ed25519)")
    print("- It proves the token was signed by Steam")
    print("- It cannot be decrypted, only verified with Steam's public key")

    issues = validate_steam_jwt(payload)

    print("\n=== VALIDATION ===")
    if issues:
        for i in issues:
            print("⚠️", i)
    else:
        print("✅ Structure and claims look valid")

    print("\nℹ️ FINAL NOTES")
    print("- JWTs are fully readable by design")
    print("- Security comes from signature verification, not secrecy")
    print("- Modifying ANY decoded field breaks the signature")

    pause()
