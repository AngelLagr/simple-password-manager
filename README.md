# Password Manager

---

## Description

**Password Manager** is a simple graphical interface using `customtkinter` to manage locally your password.

It allows you to store, generate, display, and delete passwords locally encrypted with AES-GCM 256-bit encryption.

The master password is directly used to protect the encrypted vault, ensuring that without this password, it is impossible to access the data. No sensitive data is stored in plain text on disk or in the code.

---

## Features

- Create a secure master password on first launch
- Strong encryption with AES-GCM and key derivation via Scrypt
- add, delete paswords, clipboard copy
- Built-in robust password generator
- very simple interface
- Single encrypted vault storage in `data/vault.enc`

---

## Prerequisites

- Python 3.8+
- Python packages:
``` 
pip install cryptography customtkinter pyperclip
```

---

## Development Usage

1. Clone or download this project
2. Install dependencies (see above)
3. Run the application:
```
python main.py
```
4. On first launch, set a master password
5. Easily add, delete, or copy passwords
6. Vault is securely stored encrypted in `data/vault.enc`

---

## Building a Standalone Application

To create an executable (e.g. `.exe` on Windows) and distribute the app without requiring Python installed:

1. Install PyInstaller:
```
pip install pyinstaller
```
2. From the project folder, run the build:
```
pyinstaller --noconsole --onefile main.py
```
3. Executable will be generated in the `dist/` folder
4. Copy and distribute this file directly
5. The `data/` folder will be created automatically on the executable’s first run

---

## Important Security Notes

- **The master password is the unique key to your vault.** If lost, you will no longer access your passwords.
- Deleting or modifying `data/vault.enc` will make your data unrecoverable.
- Encryption is local; no data is sent to any server.

I'm definitely not an expert in cybersecurity or anything like that, so any contributions are more than welcome! I just wanted to share this tool publicly because I found it useful.
---

## Licence

Apache2.0 Licence
