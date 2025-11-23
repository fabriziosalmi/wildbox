import hmac
import hashlib
import os

# Your test API key - loaded from environment variable
api_key = os.getenv('TEST_API_KEY')
if not api_key:
    raise ValueError("TEST_API_KEY environment variable is not set")

# Real JWT secret from Identity service
jwt_secret = 'generate-a-secure-random-jwt-secret-key-here'

# Calculate HMAC-SHA256 hash
hashed_key = hmac.new(
    jwt_secret.encode(),
    api_key.encode(),
    hashlib.sha256
).hexdigest()

print(f'Expected hash: {hashed_key}')
print(f'Database hash starts with: 47559e35920b2d706872')
print(f'Match: {hashed_key.startswith("47559e35920b2d706872")}')
