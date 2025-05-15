import base64

PORT = 4000

MONGODB_HOST = {
    'host': 'localhost',
    'port': 27017
}

MONGODB_DBNAME = 'cyberStudents'

WORKERS = 32

# AES key and pepper (base64-encoded 16-byte secrets)
# these are not normally stored in a file. YOU SHOULD NEVER HARD CODE SECRETS
# they should be in an environment variable or a secret manager
# for now for this purpose I made them both the same value (not like in the real world) and stored them in here (again not like in the real world)
AES_KEY_B64 = 'F8a3RJIMMsCnZeUN0Rmpyg=='
PEPPER_B64 = 'F8a3RJIMMsCnZeUN0Rmpyg=='

# Decoded (ready to use in app)
AES_KEY = base64.b64decode(AES_KEY_B64)
PEPPER = base64.b64decode(PEPPER_B64)