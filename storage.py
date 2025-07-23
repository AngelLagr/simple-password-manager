import os
import json
from crypto_utils import encrypt, decrypt
from auth import hash_master_password

VAULT_FILE = 'data/vault.enc'

def create_new_vault(master_pwd: str):
    # Structure initiale avec check
    data = {
        "check": hash_master_password(master_pwd),
        "entries": {}
    }
    save_vault(data, master_pwd)

def load_vault(master_pwd: str) -> dict:
    if not os.path.exists(VAULT_FILE):
        raise FileNotFoundError("Vault not found. Please create it first.")
    with open(VAULT_FILE, 'rb') as f:
        encrypted = f.read()
    raw = decrypt(encrypted, master_pwd)
    data = json.loads(raw.decode())
    if data.get("check") != hash_master_password(master_pwd):
        raise ValueError("Incorrect master password")
    return data["entries"]

def save_vault(entries: dict, master_pwd: str):
    # On charge l'ancien check ou on crée un nouveau si vault absent
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, 'rb') as f:
            encrypted = f.read()
        try:
            raw = decrypt(encrypted, master_pwd)
            data = json.loads(raw.decode())
            check = data.get("check", hash_master_password(master_pwd))
        except Exception:
            # si erreur on reset check
            check = hash_master_password(master_pwd)
    else:
        check = hash_master_password(master_pwd)

    data = {
        "check": check,
        "entries": entries
    }
    raw = json.dumps(data).encode()
    encrypted = encrypt(raw, master_pwd)
    os.makedirs('data', exist_ok=True)
    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypted)
