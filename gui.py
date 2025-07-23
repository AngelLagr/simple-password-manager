import os
import customtkinter as ctk
from tkinter import messagebox, filedialog
from storage import load_vault, save_vault, create_new_vault
from password_generator import generate_password
import difflib
import atexit
import signal
import sys

master_pwd = ''
vault_data = {}

def cleanup_on_exit():
    global master_pwd, vault_data
    
    master_pwd = ''
    vault_data.clear()
    
    try:
        import pyperclip
        pyperclip.copy('')
    except:
        pass

def signal_handler(signum, frame):
    cleanup_on_exit()
    sys.exit(0)

atexit.register(cleanup_on_exit)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

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
        
        self.load_button = ctk.CTkButton(self, text="Load Vault File", command=self.load_vault_file)
        self.load_button.pack(pady=5)

        # Gérer la fermeture de fenêtre
        self.protocol("WM_DELETE_WINDOW", self.quit_login)

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
        try:
            MainApp().mainloop()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start main application: {e}")
            self.deiconify() 

    def load_vault_file(self):
        global master_pwd, vault_data
        pwd = self.entry.get()
        if not pwd:
            messagebox.showerror("Error", "Please enter master password first")
            return
            
        file_path = filedialog.askopenfilename(
            title="Select Vault File",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            loaded_data = load_vault(pwd, file_path)
            
            if isinstance(loaded_data, dict) and "needs_merge" in loaded_data:
                new_entries = loaded_data["new_entries"]
                existing_entries = loaded_data["existing_entries"]
                
                choice = self.show_merge_dialog(len(new_entries), len(existing_entries))
                
                if choice == "cancel":
                    return
                elif choice == "replace":
                    from storage import merge_vaults
                    vault_data = merge_vaults(new_entries, existing_entries, pwd, "replace")
                elif choice == "backup":
                    from storage import merge_vaults
                    vault_data = merge_vaults(new_entries, existing_entries, pwd, "backup")
                    messagebox.showinfo("Success", "Vault loaded and old vault backed up!")
                elif choice == "merge":
                    from storage import merge_vaults
                    result = merge_vaults(new_entries, existing_entries, pwd, "merge")
                    vault_data = result["entries"]
                    if result.get("conflicts"):
                        conflicts_str = ", ".join(result["conflicts"])
                        messagebox.showwarning("Merge Complete", f"Vault merged successfully!\nOverwritten entries: {conflicts_str}")
                    else:
                        messagebox.showinfo("Success", "Vaults merged successfully!")
            else:
                vault_data = loaded_data
            
            master_pwd = pwd
            self.withdraw()
            try:
                MainApp().mainloop()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start main application: {e}")
                self.deiconify() 
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load vault: {e}")

    def show_merge_dialog(self, new_count, existing_count):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Vault Conflict")
        dialog.geometry("450x300")
        dialog.transient(self)
        dialog.grab_set()
        
        def close_dialog():
            result["choice"] = "cancel"
            dialog.destroy()
        dialog.protocol("WM_DELETE_WINDOW", close_dialog)
        
        result = {"choice": "cancel"}
        
        ctk.CTkLabel(dialog, text="Vault Already Exists!", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        ctk.CTkLabel(dialog, text=f"Local vault: {existing_count} entries\nNew vault: {new_count} entries\n\nWhat would you like to do?").pack(pady=10)
        
        def set_choice(choice):
            result["choice"] = choice
            dialog.destroy()
        
        ctk.CTkButton(dialog, text="Replace (Delete old vault)", 
                     command=lambda: set_choice("replace")).pack(pady=5)
        
        ctk.CTkButton(dialog, text="Backup old & Replace (Recommended)", 
                     command=lambda: set_choice("backup")).pack(pady=5)
        
        ctk.CTkButton(dialog, text="Merge (Combine both vaults)", 
                     command=lambda: set_choice("merge")).pack(pady=5)
        
        ctk.CTkButton(dialog, text="Cancel", 
                     command=lambda: set_choice("cancel")).pack(pady=5)
        
        dialog.wait_window()
        return result["choice"]

    def quit_login(self):
        global master_pwd, vault_data
        
        master_pwd = ''
        vault_data.clear()
        
        try:
            import pyperclip
            pyperclip.copy('')
        except:
            pass
        
        try:
            self.quit()
        except:
            pass
        try:
            self.destroy()
        except:
            pass

class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("600x550")

        global vault_data
        if not isinstance(vault_data, dict):
            vault_data = {}
        self.filtered_data = vault_data.copy()

        self._after_ids = set()

        self.search_frame = ctk.CTkFrame(self)
        self.search_frame.pack(pady=10, padx=10, fill='x')
        ctk.CTkLabel(self.search_frame, text="Search:").pack(side='left', padx=5)
        self.search_entry = ctk.CTkEntry(self.search_frame, placeholder_text="Search sites...")
        self.search_entry.pack(side='left', fill='x', expand=True, padx=5)
        self.search_entry.bind('<KeyRelease>', self.on_search)
        self.clear_btn = ctk.CTkButton(self.search_frame, text="Clear", width=60, command=self.clear_search)
        self.clear_btn.pack(side='right', padx=5)
        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=580, height=350)
        self.scrollable_frame.pack(pady=10)
        self.add_btn = ctk.CTkButton(self, text="Add Entry", command=self.add_entry_popup)
        self.add_btn.pack(pady=10)
        self.quit_btn = ctk.CTkButton(self, text="Quit", fg_color="red", hover_color="darkred", command=self.quit_app)
        self.quit_btn.pack(pady=5)
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        self.refresh_list()

    def on_search(self, event=None):
        search_term = self.search_entry.get().lower()
        if not search_term:
            self.filtered_data = vault_data.copy()
        else:
            self.filtered_data = {}
            if isinstance(vault_data, dict):
                for site, creds in vault_data.items():
                    if not isinstance(creds, dict) or 'username' not in creds:
                        continue
                        
                    site_lower = site.lower()
                    username_lower = creds['username'].lower()
                    
                    if (search_term in site_lower or 
                        search_term in username_lower or
                        any(difflib.get_close_matches(search_term, [site_lower], cutoff=0.6)) or
                        any(difflib.get_close_matches(search_term, [username_lower], cutoff=0.6))):
                        self.filtered_data[site] = creds
        
        self.refresh_list()

    def clear_search(self):
        self.search_entry.delete(0, 'end')
        self.filtered_data = vault_data.copy()
        self.refresh_list()

    def refresh_list(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        if not isinstance(vault_data, dict):
            return
            
        for site, creds in self.filtered_data.items():
            if not isinstance(creds, dict) or 'username' not in creds or 'password' not in creds:
                continue
                
            frame = ctk.CTkFrame(self.scrollable_frame)
            frame.pack(pady=5, padx=10, fill='x')
            ctk.CTkLabel(frame, text=site, width=100).pack(side='left')
            ctk.CTkLabel(frame, text=creds['username'], width=120).pack(side='left')
            ctk.CTkEntry(frame, show="*", width=120, placeholder_text=creds['password']).pack(side='left')
            ctk.CTkButton(frame, text="Copy", width=50, command=lambda p=creds['password']: self.clip(p)).pack(side='left', padx=2)
            ctk.CTkButton(frame, text="Edit", width=50, command=lambda s=site: self.edit_entry(s)).pack(side='left', padx=2)
            ctk.CTkButton(frame, text="Delete", width=60, command=lambda s=site: self.delete_entry(s)).pack(side='left', padx=2)

    def clip(self, pwd):
        import pyperclip
        pyperclip.copy(pwd)
        if hasattr(self, '_clipboard_timer'):
            try:
                self.after_cancel(self._clipboard_timer)
                self._after_ids.discard(self._clipboard_timer)
            except:
                pass
        self._clipboard_timer = self.after(5000, self._clear_clipboard)
        self._after_ids.add(self._clipboard_timer)

    def _clear_clipboard(self):
        try:
            # Vérifier que l'application n'est pas en cours de fermeture
            if self.winfo_exists():
                import pyperclip
                pyperclip.copy('')
        except Exception:
            pass

    def delete_entry(self, site):
        if site in vault_data:
            if messagebox.askyesno("Confirm Delete", f"Delete entry for '{site}'?"):
                del vault_data[site]
                save_vault(vault_data, master_pwd)
                self.filtered_data = vault_data.copy()
                self.refresh_list()

    def edit_entry(self, site):
        if site not in vault_data:
            return
            
        win = ctk.CTkToplevel(self)
        win.title(f"Edit Entry - {site}")
        win.geometry("350x300")
        
        def close_edit_window():
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", close_edit_window)
        
        current_data = vault_data[site]
        
        site_entry = ctk.CTkEntry(win, placeholder_text="Site")
        site_entry.pack(pady=5)
        site_entry.insert(0, site)
        
        username_entry = ctk.CTkEntry(win, placeholder_text="Username")
        username_entry.pack(pady=5)
        username_entry.insert(0, current_data['username'])
        
        password_entry = ctk.CTkEntry(win, placeholder_text="Password")
        password_entry.pack(pady=5)
        password_entry.insert(0, current_data['password'])

        def autofill():
            password_entry.delete(0, 'end')
            password_entry.insert(0, generate_password())

        ctk.CTkButton(win, text="Generate New Password", command=autofill).pack(pady=5)

        def save_changes():
            new_site = site_entry.get()
            new_username = username_entry.get()
            new_password = password_entry.get()
            
            if not new_site or not new_username or not new_password:
                messagebox.showerror("Error", "All fields must be filled")
                return
            
            if new_site != site:
                if new_site in vault_data:
                    if not messagebox.askyesno("Confirm", f"Entry '{new_site}' already exists. Overwrite?"):
                        return
                del vault_data[site]
            
            vault_data[new_site] = {
                'username': new_username,
                'password': new_password
            }
            
            save_vault(vault_data, master_pwd)
            self.filtered_data = vault_data.copy()
            self.refresh_list()
            win.destroy()

        ctk.CTkButton(win, text="Save Changes", command=save_changes).pack(pady=10)

    def add_entry_popup(self):
        win = ctk.CTkToplevel(self)
        win.title("New Entry")
        win.geometry("350x300")
        
        # Gérer la fermeture de la fenêtre modale
        def close_add_window():
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", close_add_window)

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
            self.filtered_data = vault_data.copy()
            self.refresh_list()
            win.destroy()

        ctk.CTkButton(win, text="Save", command=save).pack(pady=10)

    def quit_app(self):
        global master_pwd, vault_data
        # Cancel all scheduled tkinter callbacks
        for after_id in list(getattr(self, '_after_ids', [])):
            try:
                self.after_cancel(after_id)
            except:
                pass
        self._after_ids.clear()
        # Disable all widgets
        for widget in self.winfo_children():
            try:
                widget.configure(state="disabled")
            except:
                pass
        # Schedule final cleanup
        try:
            self.after_idle(self._final_cleanup)
        except Exception:
            self._final_cleanup()

    def _final_cleanup(self):
        global master_pwd, vault_data
        master_pwd = ''
        vault_data.clear()
        try:
            import pyperclip
            pyperclip.copy('')
        except:
            pass
        # Destroy all toplevel windows and exit
        for child in self.winfo_children():
            if isinstance(child, ctk.CTkToplevel):
                child.destroy()

        self.quit()
        self.destroy()
        os._exit(0)
            

def launch_app():
    LoginWindow().mainloop()
