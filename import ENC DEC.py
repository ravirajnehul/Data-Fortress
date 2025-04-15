import os
import socket
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox

# Generate RSA keys
KEY_DIRECTORY = "keys"
os.makedirs(KEY_DIRECTORY, exist_ok=True)

# User database setup
def setup_user_database():
    conn = sqlite3.connect("user_data.db")
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
                        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_password TEXT NOT NULL,
                        user_mail_id TEXT UNIQUE NOT NULL
                    )""")
    conn.commit()
    conn.close()

def validate_user(user_id, user_password):
    conn = sqlite3.connect("user_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = ? AND user_password = ?", (user_id, user_password))
    user = cursor.fetchone()
    conn.close()
    return user

def add_user(user_password, user_mail_id):
    conn = sqlite3.connect("user_data.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (user_password, user_mail_id) VALUES (?, ?)", (user_password, user_mail_id))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None # Indicate registration failure due to existing email

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_key_path = os.path.join(KEY_DIRECTORY, "private_key.pem")
    public_key_path = os.path.join(KEY_DIRECTORY, "public_key.pem")

    with open(private_key_path, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(public_key_path, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return private_key_path, public_key_path

def load_keys():
    private_key_path = os.path.join(KEY_DIRECTORY, "private_key.pem")
    public_key_path = os.path.join(KEY_DIRECTORY, "public_key.pem")

    with open(private_key_path, "rb") as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None
        )

    with open(public_key_path, "rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())

    return private_key, public_key

# Encrypt/Decrypt Functions
def encrypt_message(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(private_key, encrypted):
    decrypted = private_key.decrypt(
        encrypted,
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Fetch System Info
def get_system_info():
    ip_address = socket.gethostbyname(socket.gethostname())
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    return ip_address, date

# GUI Implementation
def main_gui():
    setup_user_database()
    generate_keys()
    private_key, public_key = load_keys()

    def register_user():
        user_password = password_entry.get()
        user_mail_id = email_entry.get()
        if user_password and user_mail_id:
            user_id = add_user(user_password, user_mail_id)
            if user_id:
                messagebox.showinfo("Success", f"Registration successful! Your User ID is: {user_id}")
            else:
                messagebox.showerror("Error", "Email ID already registered.")
        else:
            messagebox.showerror("Error", "All fields are required.")

    def login_user():
        user_id = user_id_entry.get()
        user_password = password_entry.get()
        if validate_user(user_id, user_password):
            messagebox.showinfo("Success", "Login successful!")
            encryption_decryption_menu()
        else:
            messagebox.showerror("Error", "Invalid User ID or Password.")

    def encryption_decryption_menu():
        def encrypt_text():
            plaintext = plaintext_entry.get()
            if plaintext:
                ip, date = get_system_info()
                data = f"{plaintext}|{date}|{ip}"
                encrypted = encrypt_message(public_key, data)
                encrypted_message.set(encrypted.hex())
            else:
                messagebox.showerror("Error", "Text cannot be empty.")

        def decrypt_text():
            encrypted_text = encrypted_message.get()
            if encrypted_text:
                try:
                    encrypted_bytes = bytes.fromhex(encrypted_text)
                    decrypted = decrypt_message(private_key, encrypted_bytes)
                    decrypted_message.set(decrypted)
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            else:
                messagebox.showerror("Error", "Encrypted text cannot be empty.")

        encryption_window = tk.Toplevel(root)
        encryption_window.title("Encryption/Decryption Menu")
        encryption_window.geometry("500x400")
        encryption_window.configure(bg="#f0f8ff")

        tk.Label(encryption_window, text="Enter Plain Text:", bg="#f0f8ff", font=("Helvetica", 12)).pack(pady=5)
        plaintext_entry = ttk.Entry(encryption_window, width=50)
        plaintext_entry.pack(pady=5)

        encrypt_button = ttk.Button(encryption_window, text="Encrypt", command=encrypt_text)
        encrypt_button.pack(pady=10)

        tk.Label(encryption_window, text="Encrypted Message:", bg="#f0f8ff", font=("Helvetica", 12)).pack(pady=5)
        encrypted_message = tk.StringVar()
        encrypted_entry = ttk.Entry(encryption_window, textvariable=encrypted_message, width=50, state='readonly')
        encrypted_entry.pack(pady=5)

        decrypt_button = ttk.Button(encryption_window, text="Decrypt", command=decrypt_text)
        decrypt_button.pack(pady=10)

        tk.Label(encryption_window, text="Decrypted Message:", bg="#f0f8ff", font=("Helvetica", 12)).pack(pady=5)
        decrypted_message = tk.StringVar()
        decrypted_entry = ttk.Entry(encryption_window, textvariable=decrypted_message, width=50, state='readonly')
        decrypted_entry.pack(pady=5)

        # Displaying Public and Private Keys in the Encryption Menu
        tk.Label(encryption_window, text="Public Key (PEM):", bg="#f0f8ff", font=("Helvetica", 12)).pack(pady=5)
        public_key_display = tk.Text(encryption_window, height=5, width=50)
        public_key_display.insert(tk.END, public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        public_key_display.pack(pady=5)

        tk.Label(encryption_window, text="Private Key (PEM):", bg="#f0f8ff", font=("Helvetica", 12)).pack(pady=5)
        private_key_display = tk.Text(encryption_window, height=5, width=50)
        private_key_display.insert(tk.END, private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()).decode())
        private_key_display.pack(pady=5)

    root = tk.Tk()
    root.title("Secure Encryption/Decryption System")
    root.geometry("600x500")
    root.configure(bg="#e6f7ff")

    title_label = tk.Label(root, text="Welcome to Secure System", bg="#4682b4", fg="white", font=("Helvetica", 16, "bold"), pady=10)
    title_label.pack(fill=tk.X)

    frame = ttk.Frame(root, padding="20")
    frame.pack(pady=20)

    tk.Label(frame, text="User ID:", font=("Helvetica", 12)).grid(row=0, column=0, sticky=tk.W, pady=5)
    user_id_entry = ttk.Entry(frame, width=30)
    user_id_entry.grid(row=0, column=1, pady=5)

    tk.Label(frame, text="Password:", font=("Helvetica", 12)).grid(row=1, column=0, sticky=tk.W, pady=5)
    password_entry = ttk.Entry(frame, show="*", width=30)
    password_entry.grid(row=1, column=1, pady=5)

    tk.Label(frame, text="Email:", font=("Helvetica", 12)).grid(row=2, column=0, sticky=tk.W, pady=5)
    email_entry = ttk.Entry(frame, width=30)
    email_entry.grid(row=2, column=1, pady=5)

    register_button = ttk.Button(frame, text="Register", command=register_user)
    register_button.grid(row=3, column=0, pady=10, sticky=tk.W)

    login_button = ttk.Button(frame, text="Login", command=login_user)
    login_button.grid(row=3, column=1, pady=10, sticky=tk.E)

    exit_button = ttk.Button(root, text="Exit", command=root.quit)
    exit_button.pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    main_gui()