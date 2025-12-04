from app.totp_utils import generate_totp_code, verify_totp_code, get_seconds_remaining

hex_seed = input("Enter your 64-char hex seed: ")

code = generate_totp_code(hex_seed)
print("Generated code:", code)
print("Seconds remaining:", get_seconds_remaining())

print("Verification:", verify_totp_code(hex_seed, code))
