import os
import shutil
import zipfile
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.ttk import Combobox, Notebook
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import pandas as pd
import logging
import random

def generate_seed_from_file(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
    return hashlib.sha256(content).hexdigest()

def derive_key(password: str, salt: bytes, length: int) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def aes_encrypt_file(file_path, password, output_folder):
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    
    salt = os.urandom(16)
    key = derive_key(password, salt, 32)
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    encrypted_filename = os.path.basename(file_path) + '.enc'
    output_path = os.path.join(output_folder, encrypted_filename)
    
    with open(output_path, 'wb') as file:
        file.write(salt + nonce + ciphertext)
    
    return output_path

def aes_decrypt_file(file_path, password, output_folder):
    with open(file_path, 'rb') as file:
        data = file.read()
    
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    
    key = derive_key(password, salt, 32)
    
    aesgcm = AESGCM(key)
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        return None
    
    decrypted_filename = os.path.basename(file_path)[:-4]  # Remove .enc extension
    output_path = os.path.join(output_folder, decrypted_filename)
    
    with open(output_path, 'wb') as file:
        file.write(plaintext)
    
    return output_path

def compress_folder(folder_path, output_path):
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, folder_path)
                zipf.write(file_path, arcname)
    return output_path

def decompress_folder(zip_path, output_folder):
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(output_folder)
    return output_folder

def encrypt_folder(folder_path, password, output_folder):
    zip_path = os.path.join(output_folder, "temp.zip")
    compress_folder(folder_path, zip_path)
    encrypted_path = aes_encrypt_file(zip_path, password, output_folder)
    os.remove(zip_path)
    return encrypted_path

def decrypt_folder(encrypted_folder_path, password, output_folder):
    decrypted_zip_path = aes_decrypt_file(encrypted_folder_path, password, output_folder)
    if decrypted_zip_path:
        folder_path = decompress_folder(decrypted_zip_path, output_folder)
        os.remove(decrypted_zip_path)
        return folder_path
    return None

def generate_key_from_file_and_password(file_path, password):
    file_seed = generate_seed_from_file(file_path)
    combined_seed = hashlib.sha256((str(file_seed) + password).encode()).hexdigest()
    return combined_seed

def file_based_encrypt(file_path, seed_file_path, password, output_folder):
    key = generate_key_from_file_and_password(seed_file_path, password)
    return aes_encrypt_file(file_path, key, output_folder)

def file_based_decrypt(encrypted_file_path, seed_file_path, password, output_folder):
    key = generate_key_from_file_and_password(seed_file_path, password)
    return aes_decrypt_file(encrypted_file_path, key, output_folder)

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def encrypt_with_public_key(message, public_key):
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_with_private_key(encrypted_message, private_key):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def create_tooltip(widget, text):
    def enter(event):
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
        label = tk.Label(tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1)
        label.pack()
        widget.tooltip = tooltip

    def leave(event):
        widget.tooltip.destroy()

    widget.bind("<Enter>", enter)
    widget.bind("<Leave>", leave)

def create_button_with_info(parent, text, command, info_text):
    frame = tk.Frame(parent)
    frame.pack(pady=10)
    
    button = tk.Button(frame, text=text, command=command)
    button.pack(side=tk.LEFT)
    
    info_icon = tk.Label(frame, text="ⓘ", fg="blue", cursor="hand2")
    info_icon.pack(side=tk.LEFT, padx=5)
    
    create_tooltip(info_icon, info_text)
    
    return button

class KeyManager:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.public_key_path = ""
        self.private_key_path = ""

    def load_public_key(self, file_path):
        try:
            with open(file_path, "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            self.public_key_path = file_path
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load public key: {str(e)}")
            return False

    def load_private_key(self, file_path):
        try:
            with open(file_path, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            self.private_key_path = file_path
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load private key: {str(e)}")
            return False

def main():
    root = tk.Tk()
    root.title("File Encryption/Decryption Tool")
    root.geometry("575x150")

    notebook = Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    key_manager = KeyManager()

    # Standard encryption tab
    standard_frame = tk.Frame(notebook)
    notebook.add(standard_frame, text="Standard Encryption")

    def encrypt_file():
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if file_path:
            password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
            if password:
                output_folder = filedialog.askdirectory(title="Select output folder")
                if output_folder:
                    try:
                        encrypted_file_path = aes_encrypt_file(file_path, password, output_folder)
                        messagebox.showinfo("Success", f"File encrypted and saved as:\n{encrypted_file_path}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_file():
        file_path = filedialog.askopenfilename(title="Select file to decrypt", filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
            if password:
                output_folder = filedialog.askdirectory(title="Select output folder")
                if output_folder:
                    try:
                        decrypted_file_path = aes_decrypt_file(file_path, password, output_folder)
                        if decrypted_file_path:
                            messagebox.showinfo("Success", f"File decrypted and saved as:\n{decrypted_file_path}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    create_button_with_info(standard_frame, "Encrypt File", encrypt_file, "Encrypt a file using a password")
    create_button_with_info(standard_frame, "Decrypt File", decrypt_file, "Decrypt a file using a password")

    # Folder encryption tab
    folder_frame = tk.Frame(notebook)
    notebook.add(folder_frame, text="Folder Encryption")

    def encrypt_folder_gui():
        folder_path = filedialog.askdirectory(title="Select folder to encrypt")
        if folder_path:
            password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
            if password:
                output_folder = filedialog.askdirectory(title="Select output folder")
                if output_folder:
                    try:
                        encrypted_file_path = encrypt_folder(folder_path, password, output_folder)
                        messagebox.showinfo("Success", f"Folder encrypted and saved as:\n{encrypted_file_path}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_folder_gui():
        file_path = filedialog.askopenfilename(title="Select encrypted folder file", filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
            if password:
                output_folder = filedialog.askdirectory(title="Select output folder")
                if output_folder:
                    try:
                        decrypted_folder_path = decrypt_folder(file_path, password, output_folder)
                        if decrypted_folder_path:
                            messagebox.showinfo("Success", f"Folder decrypted and saved in:\n{decrypted_folder_path}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    create_button_with_info(folder_frame, "Encrypt Folder", encrypt_folder_gui, "Encrypt an entire folder using a password")
    create_button_with_info(folder_frame, "Decrypt Folder", decrypt_folder_gui, "Decrypt an encrypted folder using a password")

    # File-based encryption tab
    file_based_frame = tk.Frame(notebook)
    notebook.add(file_based_frame, text="File-Based Encryption")

    def file_based_encrypt_gui():
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if file_path:
            seed_file_path = filedialog.askopenfilename(title="Select seed file")
            if seed_file_path:
                password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
                if password:
                    output_folder = filedialog.askdirectory(title="Select output folder")
                    if output_folder:
                        try:
                            encrypted_file_path = file_based_encrypt(file_path, seed_file_path, password, output_folder)
                            messagebox.showinfo("Success", f"File encrypted and saved as:\n{encrypted_file_path}")
                        except Exception as e:
                            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def file_based_decrypt_gui():
        file_path = filedialog.askopenfilename(title="Select file to decrypt", filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            seed_file_path = filedialog.askopenfilename(title="Select seed file")
            if seed_file_path:
                password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
                if password:
                    output_folder = filedialog.askdirectory(title="Select output folder")
                    if output_folder:
                        try:
                            decrypted_file_path = file_based_decrypt(file_path, seed_file_path, password, output_folder)
                            if decrypted_file_path:
                                messagebox.showinfo("Success", f"File decrypted and saved as:\n{decrypted_file_path}")
                        except Exception as e:
                            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    create_button_with_info(file_based_frame, "Encrypt File", file_based_encrypt_gui, "Encrypt a file using a password and a seed file")
    create_button_with_info(file_based_frame, "Decrypt File", file_based_decrypt_gui, "Decrypt a file using a password and a seed file")

    # Asymmetric Encryption tab
    asymmetric_frame = tk.Frame(notebook)
    notebook.add(asymmetric_frame, text="Asymmetric Encryption")

    def asymmetric_encrypt():
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if file_path:
            if key_manager.public_key:
                output_folder = filedialog.askdirectory(title="Select output folder")
                if output_folder:
                    try:
                        with open(file_path, "rb") as file:
                            data = file.read()
                        encrypted_data = encrypt_with_public_key(data, key_manager.public_key)
                        output_path = os.path.join(output_folder, os.path.basename(file_path) + ".enc")
                        with open(output_path, "wb") as output_file:
                            output_file.write(encrypted_data)
                        messagebox.showinfo("Success", f"File encrypted and saved as:\n{output_path}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            else:
                messagebox.showerror("Error", "Public key not loaded")

    def asymmetric_decrypt():
        file_path = filedialog.askopenfilename(title="Select file to decrypt", filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            if key_manager.private_key:
                output_folder = filedialog.askdirectory(title="Select output folder")
                if output_folder:
                    try:
                        with open(file_path, "rb") as file:
                            encrypted_data = file.read()
                        decrypted_data = decrypt_with_private_key(encrypted_data, key_manager.private_key)
                        output_path = os.path.join(output_folder, os.path.basename(file_path)[:-4])  # Remove .enc extension
                        with open(output_path, "wb") as output_file:
                            output_file.write(decrypted_data)
                        messagebox.showinfo("Success", f"File decrypted and saved as:\n{output_path}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            else:
                messagebox.showerror("Error", "Private key not loaded")

    create_button_with_info(asymmetric_frame, "Encrypt File", asymmetric_encrypt, "Encrypt a file using a public key")
    create_button_with_info(asymmetric_frame, "Decrypt File", asymmetric_decrypt, "Decrypt a file using a private key")

    # Key Management tab
    key_gen_frame = tk.Frame(notebook)
    notebook.add(key_gen_frame, text="Key Management")

    public_key_label = tk.Label(key_gen_frame, text="Public Key: Not loaded", wraplength=500)
    public_key_label.pack(pady=5)

    private_key_label = tk.Label(key_gen_frame, text="Private Key: Not loaded", wraplength=500)
    private_key_label.pack(pady=5)

    def update_key_labels():
        public_key_label.config(text=f"Public Key: {key_manager.public_key_path if key_manager.public_key else 'Not loaded'}")
        private_key_label.config(text=f"Private Key: {key_manager.private_key_path if key_manager.private_key else 'Not loaded'}")

    def generate_and_save_keys():
        output_folder = filedialog.askdirectory(title="Select output folder for keys")
        if output_folder:
            try:
                private_key, public_key = generate_rsa_key_pair()
                
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                private_key_path = os.path.join(output_folder, "private_key.pem")
                public_key_path = os.path.join(output_folder, "public_key.pem")
                
                save_key_to_file(private_pem, private_key_path)
                save_key_to_file(public_pem, public_key_path)
                
                key_manager.load_private_key(private_key_path)
                key_manager.load_public_key(public_key_path)

                update_key_labels()
                messagebox.showinfo("Success", f"Keys generated and saved in:\n{output_folder}")
            except Exception as e:
                messagebox.showerror("Error", f"Key generation failed: {str(e)}")

    def load_public_key():
        file_path = filedialog.askopenfilename(title="Select public key file", filetypes=[("PEM files", "*.pem")])
        if file_path:
            if key_manager.load_public_key(file_path):
                update_key_labels()
                messagebox.showinfo("Success", "Public key loaded successfully")

    def load_private_key():
        file_path = filedialog.askopenfilename(title="Select private key file", filetypes=[("PEM files", "*.pem")])
        if file_path:
            if key_manager.load_private_key(file_path):
                update_key_labels()
                messagebox.showinfo("Success", "Private key loaded successfully")

    create_button_with_info(key_gen_frame, "Generate RSA Key Pair", generate_and_save_keys, "Generate a new RSA key pair and save to files")
    create_button_with_info(key_gen_frame, "Load Public Key", load_public_key, "Load an existing public key from a file")
    create_button_with_info(key_gen_frame, "Load Private Key", load_private_key, "Load an existing private key from a file")

    root.mainloop()

if __name__ == "__main__":
    main()
