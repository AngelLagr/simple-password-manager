import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 16
KEY_SIZE = 32

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def encrypt(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext

def decrypt(token: bytes, password: str) -> bytes:
    salt = token[:SALT_SIZE]
    nonce = token[SALT_SIZE:SALT_SIZE+12]
    ciphertext = token[SALT_SIZE+12:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)