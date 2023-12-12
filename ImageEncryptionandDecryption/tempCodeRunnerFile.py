import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_key(password, salt=b'saltsalt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_text(text, password):
    key = generate_key(password)
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text) + encryptor.finalize()
    return encrypted_text

def decrypt_text(encrypted_text, password):
    key = generate_key(password)
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    return decrypted_text

class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption/Decryption")

        self.image_path = ""
        self.password_entry = tk.Entry(root, show="*")
        self.canvas = tk.Canvas(root, width=300, height=300)
        self.canvas.pack()

        encrypt_button = tk.Button(root, text="Encrypt Image", command=self.encrypt_image)
        decrypt_button = tk.Button(root, text="Decrypt Image", command=self.decrypt_image)
        choose_button = tk.Button(root, text="Choose Image", command=self.choose_image)

        self.password_entry.pack(pady=10)
        encrypt_button.pack(pady=5)
        decrypt_button.pack(pady=5)
        choose_button.pack(pady=5)

    def choose_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.gif")])
        if self.image_path:
            image = Image.open(self.image_path)
            image.thumbnail((300, 300))
            photo = ImageTk.PhotoImage(image)
            self.canvas.config(width=image.width, height=image.height)
            self.canvas.create_image(0, 0, anchor=tk.NW, image=photo)
            self.canvas.image = photo

    def encrypt_image(self):
        password = self.password_entry.get()

        if not self.image_path or not password:
            messagebox.showerror("Error", "Please choose an image and enter a password.")
            return

        with open(self.image_path, "rb") as image_file:
            image_data = image_file.read()

        encrypted_image_data = encrypt_text(image_data, password)

        encrypted_image_path = f"encrypted_{os.path.basename(self.image_path)}"
        with open(encrypted_image_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_image_data)

        messagebox.showinfo("Success", "Image encrypted successfully.")

    def decrypt_image(self):
        password = self.password_entry.get()

        if not self.image_path or not password:
            messagebox.showerror("Error", "Please choose an image and enter a password.")
            return

        with open(self.image_path, "rb") as encrypted_file:
            encrypted_image_data = encrypted_file.read()

        decrypted_image_data = decrypt_text(encrypted_image_data, password)

        decrypted_image_path = f"decrypted_{os.path.basename(self.image_path)}"
        with open(decrypted_image_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_image_data)

        messagebox.showinfo("Success", "Image decrypted successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()
