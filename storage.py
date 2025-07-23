import os
import json
import shutil
from crypto_utils import encrypt, decrypt
from auth import hash_master_password

VAULT_FILE = 'data/vault.enc'

def create_new_vault(master_pwd: str):
    data = {
        "check": hash_master_password(master_pwd),
        "entries": {}
    }
    save_vault(data, master_pwd)

def load_vault(master_pwd: str, file_path: str = None) -> dict:
    vault_file = file_path if file_path else VAULT_FILE
    if not os.path.exists(vault_file):
        raise FileNotFoundError("Vault not found. Please create it first.")
    
    with open(vault_file, 'rb') as f:
        encrypted = f.read()
    raw = decrypt(encrypted, master_pwd)
    data = json.loads(raw.decode())
    if data.get("check") != hash_master_password(master_pwd):
        raise ValueError("Incorrect master password")
    
    new_entries = data["entries"]
    
    # Si on charge un fichier externe et qu'un vault local existe déjà
    if file_path and file_path != VAULT_FILE and os.path.exists(VAULT_FILE):
        try:
            # Charger le vault existant
            with open(VAULT_FILE, 'rb') as f:
                existing_encrypted = f.read()
            existing_raw = decrypt(existing_encrypted, master_pwd)
            existing_data = json.loads(existing_raw.decode())
            existing_entries = existing_data["entries"]
            
            # Si le vault existant n'est pas vide, retourner les nouvelles entrées pour traitement
            if existing_entries:
                return {"new_entries": new_entries, "existing_entries": existing_entries, "needs_merge": True}
        except Exception:
            # Si erreur avec le vault existant, on continue normalement
            pass
    
    # Si on charge un fichier externe, on le copie dans data/
    if file_path and file_path != VAULT_FILE:
        os.makedirs('data', exist_ok=True)
        shutil.copy2(file_path, VAULT_FILE)
        print(f"Vault copied from {file_path} to {VAULT_FILE}")
    
    return new_entries

def merge_vaults(new_entries: dict, existing_entries: dict, master_pwd: str, merge_strategy: str = "merge"):
    if merge_strategy == "replace":
        save_vault(new_entries, master_pwd)
        return new_entries
    
    elif merge_strategy == "backup":
        # Créer une sauvegarde de l'ancien vault
        backup_file = f"data/vault_backup_{int(os.path.getmtime(VAULT_FILE))}.enc"
        shutil.copy2(VAULT_FILE, backup_file)
        save_vault(new_entries, master_pwd)
        return new_entries
    
    elif merge_strategy == "merge":
        # Fusionner les entrées
        merged_entries = existing_entries.copy()
        conflicts = []
        
        for site, creds in new_entries.items():
            if site in merged_entries:
                conflicts.append(site)
            merged_entries[site] = creds
        
        save_vault(merged_entries, master_pwd)
        return {"entries": merged_entries, "conflicts": conflicts}
    
    return existing_entries

def save_vault(entries: dict, master_pwd: str):
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
