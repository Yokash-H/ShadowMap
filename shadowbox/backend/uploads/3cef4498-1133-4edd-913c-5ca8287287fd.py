import secrets
import string
num = secrets.randbelow(100)
token = secrets.token_bytes(16)
url_token = secrets.token_urlsafe(16)
alphabet = string.ascii_letters + string.digits
password = ''.join(secrets.choice(alphabet) for _ in range(10))
print(f"Random number: {num}")
print(f"Random token (bytes): {token}")
print(f"Random token (URL-safe): {url_token}")
print(f"Random password: {password}")
