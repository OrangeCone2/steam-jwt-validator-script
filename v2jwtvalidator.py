import base64
import json
import time
import re

def b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def decode_jwt(token: str):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format (must have 3 parts)")

    header_b64, payload_b64, signature_b64 = parts

    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))

    return header, payload, signature_b64

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
        header, payload, signature = decode_jwt(token)
    except Exception as e:
        print("❌ Failed to decode JWT:", e)
        pause()
        exit(1)

    print("\n=== HEADER ===")
    print(json.dumps(header, indent=2))

    print("\n=== PAYLOAD ===")
    print(json.dumps(payload, indent=2))

    print("\n=== SIGNATURE ===")
    print(signature[:1024])")

    issues = validate_steam_jwt(payload)

    print("\n=== VALIDATION ===")
    if issues:
        for i in issues:
            print("⚠️", i)
    else:
        print("✅ Structure and claims look valid")

    print("\nℹ️ Notes:")
    print("- JWTs are signed, not encrypted")
    print("- Signature not verified (Steam public keys are private)")
    print("- Treat real tokens like passwords")

    pause()
