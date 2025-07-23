import hashlib

def hash_master_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()
