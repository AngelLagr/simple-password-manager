import customtkinter as ctk
from tkinter import messagebox
from storage import load_vault, save_vault, create_new_vault
from password_generator import generate_password

master_pwd = ''
vault_data = {}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Vault Login")
        self.geometry("400x200")
        self.label = ctk.CTkLabel(self, text="Enter Master Password")
        self.label.pack(pady=20)
        self.entry = ctk.CTkEntry(self, show="*")
        self.entry.pack()
        self.button = ctk.CTkButton(self, text="Login", command=self.login)
        self.button.pack(pady=10)

        # Check vault presence
        import os
        if not os.path.exists('data/vault.enc'):
            self.label.configure(text="Set New Master Password")

    def login(self):
        global master_pwd, vault_data
        pwd = self.entry.get()
        import os

        try:
            if not os.path.exists('data/vault.enc'):
                # First launch, create vault
                create_new_vault(pwd)
                vault_data = {}
            else:
                vault_data = load_vault(pwd)
        except FileNotFoundError:
            messagebox.showerror("Error", "Vault file missing or corrupted.")
            return
        except ValueError:
            messagebox.showerror("Error", "Incorrect master password")
            return
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")
            return

        master_pwd = pwd
        self.withdraw()
        MainApp().mainloop()

class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("600x500")

        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=580, height=400)
        self.scrollable_frame.pack(pady=10)

        self.add_btn = ctk.CTkButton(self, text="Add Entry", command=self.add_entry_popup)
        self.add_btn.pack(pady=10)

        self.refresh_list()

    def refresh_list(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        for site, creds in vault_data.items():
            frame = ctk.CTkFrame(self.scrollable_frame)
            frame.pack(pady=5, padx=10, fill='x')
            ctk.CTkLabel(frame, text=site, width=100).pack(side='left')
            ctk.CTkLabel(frame, text=creds['username'], width=120).pack(side='left')
            ctk.CTkEntry(frame, show="*", width=150, placeholder_text=creds['password']).pack(side='left')
            ctk.CTkButton(frame, text="Copy", command=lambda p=creds['password']: self.clip(p)).pack(side='left')
            ctk.CTkButton(frame, text="Delete", command=lambda s=site: self.delete_entry(s)).pack(side='left')

    def clip(self, pwd):
        import pyperclip
        pyperclip.copy(pwd)
        self.after(5000, lambda: pyperclip.copy(''))

    def delete_entry(self, site):
        if site in vault_data:
            if messagebox.askyesno("Confirm Delete", f"Delete entry for '{site}'?"):
                del vault_data[site]
                save_vault(vault_data, master_pwd)
                self.refresh_list()

    def add_entry_popup(self):
        win = ctk.CTkToplevel(self)
        win.title("New Entry")
        win.geometry("350x300")

        site = ctk.CTkEntry(win, placeholder_text="Site")
        site.pack(pady=5)
        username = ctk.CTkEntry(win, placeholder_text="Username")
        username.pack(pady=5)
        password = ctk.CTkEntry(win, placeholder_text="Password")
        password.pack(pady=5)

        def autofill():
            password.delete(0, 'end')
            password.insert(0, generate_password())

        ctk.CTkButton(win, text="Generate", command=autofill).pack(pady=5)

        def save():
            if not site.get() or not username.get() or not password.get():
                messagebox.showerror("Error", "All fields must be filled")
                return
            vault_data[site.get()] = {
                'username': username.get(),
                'password': password.get()
            }
            save_vault(vault_data, master_pwd)
            self.refresh_list()
            win.destroy()

        ctk.CTkButton(win, text="Save", command=save).pack(pady=10)

def launch_app():
    LoginWindow().mainloop()
