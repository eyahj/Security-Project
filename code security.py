import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import io
import base64
import qrcode
import bcrypt
from pymongo import MongoClient
import sqlite3 
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import numpy as np
import cv2
import os
import uuid
import tempfile
import shutil


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption System")
        self.root.geometry("900x700")
        
        # Initialize all necessary attributes
        self.current_user = None
        self.image_path = None
        self.encrypted_image_path = None
        self.key = None
        self.algo_var = None  # For algorithm selection
        self.key_entry = None  # For decryption key input
        self.image_preview = None  # For image display
        
        # Setup database connection
        self.setup_database()
        
        # Start with authentication
        self.setup_password_auth()

    def setup_database(self):
        """Initialize database connections"""
        try:
            # MongoDB connection
            connection_string = "mongodb+srv://Student:mySecure123@Cluster0.hx5ziss.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
            self.client = MongoClient(connection_string)
            self.db = self.client["radiocrypt"]
            self.collection = self.db["encryptedimages"]
            
            # SQLite connection
            self.conn = sqlite3.connect("hospitals.db")
            self.cursor = self.conn.cursor()
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to connect to databases: {str(e)}")
            self.root.destroy()

    def setup_password_auth(self):
        """Setup the password authentication screen"""
        self.clear_window()
        
        auth_frame = ttk.Frame(self.root, padding=20)
        auth_frame.pack(expand=True, fill='both')
        
        center_frame = ttk.Frame(auth_frame)
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        ttk.Label(center_frame, text="Image Encryption System", font=('Helvetica', 16)).grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(center_frame, text="Hospital ID:").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        self.id_entry = ttk.Entry(center_frame)
        self.id_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(center_frame, text="Password:").grid(row=2, column=0, sticky='e', padx=5, pady=5)
        self.password_entry = ttk.Entry(center_frame, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Button(center_frame, text="Login", command=self.authenticate).grid(row=3, column=0, columnspan=2, pady=10)

    def authenticate(self):
        """Handle user authentication"""
        hospital_id = self.id_entry.get()
        password = self.password_entry.get()

        if not hospital_id or not password:
            messagebox.showerror("Error", "Please enter both Hospital ID and Password")
            return

        try:
            self.cursor.execute("SELECT password, name FROM hospitals WHERE id = ?", (hospital_id,))
            result = self.cursor.fetchone()
            
            if result:
                stored_password, hospital_name = result
                if password == stored_password:
                    self.current_user = hospital_name
                    self.show_main_menu()
                else:
                    messagebox.showerror("Error", "Incorrect password")
            else:
                messagebox.showerror("Error", "Hospital ID not found")
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {str(e)}")

    def show_main_menu(self):
        """Show the main menu screen"""
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True, fill='both')
        
        center_frame = ttk.Frame(main_frame)
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        ttk.Label(center_frame, text=f"Welcome, {self.current_user}", font=('Helvetica', 14)).grid(row=0, column=0, pady=(0, 30))
        
        # Menu buttons
        ttk.Button(
            center_frame, 
            text="Encrypt Image", 
            command=self.show_encrypt_screen,
            width=25,
            style='Accent.TButton'
        ).grid(row=1, column=0, pady=10, sticky='ew')
        
        ttk.Button(
            center_frame, 
            text="Decrypt Image", 
            command=self.show_decrypt_screen,
            width=25,
            style='Accent.TButton'
        ).grid(row=2, column=0, pady=10, sticky='ew')
        
        ttk.Button(
            center_frame,
            text="Logout",
            command=self.setup_password_auth,
            width=25
        ).grid(row=3, column=0, pady=(30, 0), sticky='ew')
        
        # Configure style for buttons
        style = ttk.Style()
        style.configure('Accent.TButton', font=('Helvetica', 10, 'bold'), padding=10)

    def show_encrypt_screen(self):
        """Show the encryption screen"""
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True, fill='both')
        
        # Left panel - controls
        control_frame = ttk.Frame(main_frame, padding=10)
        control_frame.pack(side='left', fill='y', padx=10)
        
        ttk.Label(control_frame, text="Encrypt Image", font=('Helvetica', 14)).pack(pady=(0, 20))
        
        # Image selection
        ttk.Button(
            control_frame,
            text="Select Image",
            command=self.select_image,
            width=20
        ).pack(pady=10)
        
        # Algorithm selection
        ttk.Label(control_frame, text="Encryption Algorithm:").pack(pady=(10, 5))
        self.algo_var = tk.StringVar(value="AES")
        algo_menu = ttk.OptionMenu(
            control_frame,
            self.algo_var,
            "AES",
            "AES",
            "DES",
            "XOR",
            "RSA"
        )
        algo_menu.pack(pady=5)
        
        # Encrypt button
        ttk.Button(
            control_frame,
            text="Encrypt",
            command=self.perform_encryption,
            width=20
        ).pack(pady=20)
        
        # Back button
        ttk.Button(
            control_frame,
            text="Back to Menu",
            command=self.show_main_menu,
            width=20
        ).pack(pady=(20, 0))
        
        # Right panel - image preview
        self.preview_frame = ttk.Frame(main_frame, padding=10)
        self.preview_frame.pack(side='right', expand=True, fill='both')
        
        self.image_preview = ttk.Label(self.preview_frame)
        self.image_preview.pack(expand=True)

    def show_decrypt_screen(self):
        """Show the decryption screen"""
        self.clear_window()
    
    # Initialize variables for file paths
        self.encrypted_image_path = None
        self.encrypted_bin_path = None
    
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True, fill='both')
    
    # Left panel - controls
        control_frame = ttk.Frame(main_frame, padding=10)
        control_frame.pack(side='left', fill='y', padx=10)
    
        ttk.Label(control_frame, text="Decrypt Image", font=('Helvetica', 14)).pack(pady=(0, 20))
    
    # Image selection
        ttk.Button(
            control_frame,
            text="Select Encrypted Image",
            command=self.select_encrypted_image,
            width=20
        ).pack(pady=10)
    
    # Bin file selection (new)
        ttk.Button(
            control_frame,
            text="Select Encrypted Bin File",
            command=self.select_bin_file,
            width=20
        ).pack(pady=10)
    
    # File path display (new)
        self.bin_file_label = ttk.Label(control_frame, text="No bin file selected", font=('Helvetica', 8))
        self.bin_file_label.pack(pady=(0, 10))
    
    # Key entry
        ttk.Label(control_frame, text="Decryption Key:").pack(pady=(10, 5))
        self.key_entry = ttk.Entry(control_frame, width=25)
        self.key_entry.pack(pady=5)
    
    # Image dimensions frame (new)
        dimension_frame = ttk.LabelFrame(control_frame, text="Original Image Dimensions", padding=5)
        dimension_frame.pack(pady=10, fill='x')
    
    # Height input
        height_frame = ttk.Frame(dimension_frame)
        height_frame.pack(fill='x', pady=2)
        ttk.Label(height_frame, text="Height:").pack(side='left')
        self.height_entry = ttk.Entry(height_frame, width=6)
        self.height_entry.pack(side='right')
    
    # Width input
        width_frame = ttk.Frame(dimension_frame)
        width_frame.pack(fill='x', pady=2)
        ttk.Label(width_frame, text="Width:").pack(side='left')
        self.width_entry = ttk.Entry(width_frame, width=6)
        self.width_entry.pack(side='right')
    
    # Channels input
        channels_frame = ttk.Frame(dimension_frame)
        channels_frame.pack(fill='x', pady=2)
        ttk.Label(channels_frame, text="Channels:").pack(side='left')
        self.channels_entry = ttk.Entry(channels_frame, width=6)
        self.channels_entry.insert(0, "3")  # Default to 3 channels (RGB)
        self.channels_entry.pack(side='right')
    
    # Algorithm selection
        ttk.Label(control_frame, text="Decryption Algorithm:").pack(pady=(10, 5))
        self.algo_var = tk.StringVar(value="AES")
        algo_menu = ttk.OptionMenu(
            control_frame,
            self.algo_var,
        "AES",
        "AES",
        "DES",
        "XOR",
        
    )
        algo_menu.pack(pady=5)
    
    # Decrypt button
        ttk.Button(
            control_frame,
            text="Decrypt",
            command=self.perform_decryption,
            width=20
        ).pack(pady=20)
    
    # Back button
        ttk.Button(
            control_frame,
            text="Back to Menu",
            command=self.show_main_menu,
            width=20
        ).pack(pady=(20, 0))
    
    # Right panel - image preview
        self.preview_frame = ttk.Frame(main_frame, padding=10)
        self.preview_frame.pack(side='right', expand=True, fill='both')
    
        self.image_preview = ttk.Label(self.preview_frame)
        self.image_preview.pack(expand=True)
    
    def select_image(self):
            """Select an image file for encryption"""
            file_path = filedialog.askopenfilename(
                filetypes=[("Image Files", "*.jpg *.jpeg *.png"), ("All Files", "*.*")]
        )
            if file_path:
                self.image_path = file_path
                self.display_image(file_path)

    def select_encrypted_image(self):
        """Select an encrypted image file for decryption"""
        file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if file_path:
            self.image_path = file_path
            self.display_image(file_path)
    
    def display_image(self, file_path):
        """Display the selected image in the preview frame"""
        try:
            image = Image.open(file_path)
            image.thumbnail((500, 500))
            photo = ImageTk.PhotoImage(image)
            
            self.image_preview.config(image=photo)
            self.image_preview.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Failed to display image: {str(e)}")
    def perform_encryption(self):
   
        if not hasattr(self, 'image_path') or not self.image_path:
            messagebox.showerror("Error", "Please select an image first")
            return
    
        try:
            img = cv2.imread(self.image_path)
            if img is None:
                messagebox.showerror("Error", "Could not read the selected image")
                return
        
            algorithm = self.algo_var.get()
        
            if algorithm == "AES":
                enc_path, qr_path, key, bin_path, original_shape = self.aes_encrypt(img, self.image_path)
                self.show_encryption_result(enc_path, qr_path, key, bin_path, original_shape)
        
            elif algorithm == "DES":
            # DES encryption implementation
                enc_path, qr_path, key, bin_path, original_shape = self.des_encrypt(img, self.image_path)
                self.show_encryption_result(enc_path, qr_path, key, bin_path, original_shape)
        
            elif algorithm == "XOR":
            # XOR encryption implementation
                enc_path, qr_path, key, bin_path, original_shape = self.xor_encrypt(img, self.image_path)
                self.show_encryption_result(enc_path, qr_path, key, bin_path, original_shape)
        
            elif algorithm == "RSA":
            # RSA encryption implementation
                enc_path, qr_path, key, bin_path, original_shape = self.rsa_encrypt(img, self.image_path)
                self.show_encryption_result(enc_path, qr_path, key, bin_path, original_shape)
        
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt: {str(e)}")


    def perform_decryption(self):
   
      
            # 1. Get .bin file path from user
            if not hasattr(self, 'bin_path') or not self.bin_path:
                # If not already set, prompt user to select file
                self.bin_path = filedialog.askopenfilename(
                    title="Select Encrypted .bin File",
                    filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
                )
                if not self.bin_path:  # User cancelled
                    return

            # 2. Get decryption key from user
            key_input = self.key_entry.get().strip()
            if not key_input:
                messagebox.showerror("Error", "Please enter the decryption key")
                return

            # 3. Get original image dimensions from user
            try:
                h = int(self.height_entry.get())
                w = int(self.width_entry.get())
                c = int(self.channels_entry.get())
                
                # Validate dimensions
                if h <= 0 or w <= 0 or c not in (1, 3):  # 1=grayscale, 3=color
                    raise ValueError("Invalid channel count")
                    
                original_shape = {"height": h, "width": w, "channels": c}
                
            except ValueError as e:
                messagebox.showerror("Error", 
                    "Invalid image dimensions:\n"
                    f"- Height and width must be positive integers\n"
                    f"- Channels must be 1 (grayscale) or 3 (color)\n"
                    f"Error: {str(e)}")
                return
            algorithm = self.algo_var.get()
            # 4. Perform decryption
        
            if algorithm == "AES":
                result = self.aes_decrypt(
                    bin_path=self.bin_path,
                    key_iv_str=key_input,
                    original_shape=original_shape
                )
            elif algorithm == "DES":
                result = self.des_decrypt(
                    bin_path=self.bin_path,
                    key_iv_str=key_input,
                    original_shape=original_shape
                )
            elif algorithm == "XOR":
                result = self.xor_decrypt(
                bin_path=self.bin_path,
                key_str=key_input,
                original_shape=original_shape
                )
           
            else:
                messagebox.showerror("Unknown Algorithm", f"Unsupported algorithm: {algorithm}")
                return

        

        # 5. Show results
            self.show_decryption_result(result["decrypted_path"])
            messagebox.showinfo("Success", 
                f"Image successfully decrypted to:\n{result['decrypted_path']}")

            
    def show_decryption_result(self, decrypted_image_path):
    
        if not os.path.exists(decrypted_image_path):
            messagebox.showerror("Error", "Decrypted image file not found.")
            return

        try:
            # Open the image using PIL
            image = Image.open(decrypted_image_path)

             # resize image
            
            image = image.resize((300, 300), Image.Resampling.LANCZOS)

            # Convert the image to a format tkinter can display
            self.tk_image = ImageTk.PhotoImage(image)

            # Display the image on a label (create one if not already existing)
            if hasattr(self, 'image_label'):
                self.image_label.config(image=self.tk_image)
            else:
                self.image_label = tk.Label(self.root, image=self.tk_image)
                self.image_label.pack(pady=10)

        except Exception as e:
            messagebox.showerror("Display Error", f"Failed to display image:\n{str(e)}")

    def select_bin_file(self):
        """Select an encrypted binary file (.bin) for decryption"""
        file_path = filedialog.askopenfilename(
            title="Select Encrypted Binary File",
            filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")]
        )
        
        if file_path:
            self.encrypted_bin_path = file_path
            # Display the filename in the UI
            filename = os.path.basename(file_path)
            self.bin_file_label.config(text=f"Selected: {filename}")

    def show_encryption_result(self, encrypted_path, qr_path, key, bin_path, original_shape):
        """Display encryption results in GUI"""
        self.clear_window()

        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True, fill='both')

        # Title
        ttk.Label(main_frame, text="Encryption Successful", font=('Helvetica', 14)).pack(pady=(0, 20))

        # Image display frame
        img_frame = ttk.Frame(main_frame)
        img_frame.pack(fill='both', expand=True)

        # Encrypted image
        encrypted_img = Image.open(encrypted_path)
        encrypted_img.thumbnail((400, 400))
        encrypted_photo = ImageTk.PhotoImage(encrypted_img)
        ttk.Label(img_frame, image=encrypted_photo).pack(side='left', padx=20)

        # QR code
        qr_img = Image.open(qr_path)
        qr_img.thumbnail((300, 300))
        qr_photo = ImageTk.PhotoImage(qr_img)
        ttk.Label(img_frame, image=qr_photo).pack(side='left', padx=20)

        # Key information
        key_frame = ttk.Frame(main_frame)
        key_frame.pack(pady=20)
        ttk.Label(key_frame, text="Encryption Key (keep this safe!):", font=('Helvetica', 11)).pack()
        ttk.Label(key_frame, text=key, wraplength=400).pack()

        # Dimensions info
        dim_frame = ttk.LabelFrame(main_frame, text="Original Image Dimensions", padding=10)
        dim_frame.pack(pady=10)
        dim_text = f"Height: {original_shape['height']}   Width: {original_shape['width']}   Channels: {original_shape['channels']}"
        ttk.Label(dim_frame, text=dim_text, font=('Helvetica', 11)).pack(pady=5)

        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)
        
        buttons = [
            ("Download Encrypted Image", lambda: self.download_file(encrypted_path)),
            ("Download .bin File", lambda: self.download_file(bin_path)),
            ("Download QR Code", lambda: self.download_file(qr_path)),
            ("Back to Menu", self.show_main_menu)
        ]
        
        for text, command in buttons:
            ttk.Button(button_frame, text=text, command=command).pack(side='left', padx=10)

    def download_file(self, file_path):
    
        dest_path = filedialog.asksaveasfilename(
            initialfile=os.path.basename(file_path),
            title="Save File As"
        )
        if dest_path:
            shutil.copy(file_path, dest_path)
            messagebox.showinfo("Download", f"File saved at:\n{dest_path}")
        
    def clear_window(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def copy_to_clipboard(self, text):
        """Copy text to clipboard and show confirmation"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()  # Required for clipboard to work
        messagebox.showinfo("Copied", "Image dimensions copied to clipboard!")

    # Encryption algorithms
    def aes_encrypt(self, img, image_path):
        h, w, c = img.shape
        block_size = AES.block_size
        encrypted_channels = []
        raw_encrypted_bytes = b''
    
    # Generate AES key and IV
        key = get_random_bytes(32)  # AES-256
        iv = get_random_bytes(16)   # AES CBC mode IV
    
        for channel in cv2.split(img):  # Separate R, G, B channels
            channel_bytes = channel.tobytes()
            padded_bytes = pad(channel_bytes, block_size)
        
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_bytes = cipher.encrypt(padded_bytes)
            raw_encrypted_bytes += encrypted_bytes
    
        # Convert encrypted bytes to a 2D array
            padded_height = len(encrypted_bytes) // w + (1 if len(encrypted_bytes) % w else 0)
            encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
            encrypted_2d = np.zeros((padded_height, w), dtype=np.uint8)
            encrypted_2d.flat[:len(encrypted_array)] = encrypted_array
            encrypted_channels.append(encrypted_2d)
    
    # Merge encrypted channels into one image
        min_height = min([ch.shape[0] for ch in encrypted_channels])
        encrypted_img = cv2.merge([ch[:min_height, :] for ch in encrypted_channels])
    
    # Save encrypted image
        enc_path = os.path.join(tempfile.gettempdir(), f"encrypted_{os.path.splitext(os.path.basename(image_path))[0]}.png")
        cv2.imwrite(enc_path, encrypted_img)
    
    # Save raw encrypted bytes to .bin
        bin_path = enc_path.replace(".png", ".bin")
        with open(bin_path, "wb") as bin_file:
            bin_file.write(raw_encrypted_bytes)
    
    # Generate QR code for (key + iv)
        key_iv_combined = base64.b64encode(key + iv).decode('utf-8')
        qr_path = os.path.join(tempfile.gettempdir(), os.path.splitext(os.path.basename(image_path))[0] + "_aes_qr.png")
        qrcode.make(key_iv_combined).save(qr_path)
    
    # Store original image dimensions
        original_shape = {"height": h, "width": w, "channels": c}
        return enc_path, qr_path, key_iv_combined, bin_path, original_shape
    
    
    def des_encrypt(self, img, image_path):
        """DES encryption (aligned with AES structure)"""
        h, w, c = img.shape
        block_size = DES.block_size
        encrypted_channels = []
        raw_encrypted_bytes = b''

        # Generate DES key and IV
        key = get_random_bytes(8)
        iv = get_random_bytes(8)

        for channel in cv2.split(img):  # Separate R, G, B channels
            channel_bytes = channel.tobytes()
            padded_bytes = pad(channel_bytes, block_size)

            cipher = DES.new(key, DES.MODE_CBC, iv)
            encrypted_bytes = cipher.encrypt(padded_bytes)
            raw_encrypted_bytes += encrypted_bytes

            # Convert encrypted bytes to a 2D array
            padded_height = len(encrypted_bytes) // w + (1 if len(encrypted_bytes) % w else 0)
            encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
            encrypted_2d = np.zeros((padded_height, w), dtype=np.uint8)
            encrypted_2d.flat[:len(encrypted_array)] = encrypted_array
            encrypted_channels.append(encrypted_2d)

        # Merge encrypted channels into one image
        min_height = min([ch.shape[0] for ch in encrypted_channels])
        encrypted_img = cv2.merge([ch[:min_height, :] for ch in encrypted_channels])

        # Save encrypted image
        enc_path = os.path.join(tempfile.gettempdir(), f"encrypted_{os.path.splitext(os.path.basename(image_path))[0]}.png")
        cv2.imwrite(enc_path, encrypted_img)

        # Save raw encrypted bytes to .bin
        bin_path = enc_path.replace(".png", ".bin")
        with open(bin_path, "wb") as bin_file:
            bin_file.write(raw_encrypted_bytes)

        # Generate QR code for (key + iv)
        key_iv_combined = base64.b64encode(key + iv).decode('utf-8')
        qr_path = os.path.join(tempfile.gettempdir(), os.path.splitext(os.path.basename(image_path))[0] + "_des_qr.png")
        qrcode.make(key_iv_combined).save(qr_path)

        # Store original image dimensions
        original_shape = {"height": h, "width": w, "channels": c}
        return enc_path, qr_path, key_iv_combined, bin_path, original_shape

    
    def xor_encrypt(self, img, image_path):
        h, w, c = img.shape
        encrypted_channels = []
        raw_encrypted_bytes = b''

        # Generate XOR key (32 bytes)
        key = get_random_bytes(32)

        for channel in cv2.split(img):  # Separate channels
            channel_bytes = channel.tobytes()
            
            # Repeat key bytes to match channel bytes length
            key_bytes = (key * ((len(channel_bytes) // len(key)) + 1))[:len(channel_bytes)]

            # XOR encryption per byte
            encrypted_bytes = bytes([b ^ k for b, k in zip(channel_bytes, key_bytes)])
            raw_encrypted_bytes += encrypted_bytes

            # Convert encrypted bytes to 2D array to save as image channel
            padded_height = len(encrypted_bytes) // w + (1 if len(encrypted_bytes) % w else 0)
            encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
            encrypted_2d = np.zeros((padded_height, w), dtype=np.uint8)
            encrypted_2d.flat[:len(encrypted_array)] = encrypted_array
            encrypted_channels.append(encrypted_2d)

        # Merge encrypted channels into one image with min height
        min_height = min([ch.shape[0] for ch in encrypted_channels])
        encrypted_img = cv2.merge([ch[:min_height, :] for ch in encrypted_channels])

        # Save encrypted image
        enc_path = os.path.join(tempfile.gettempdir(), f"encrypted_{os.path.splitext(os.path.basename(image_path))[0]}.png")
        cv2.imwrite(enc_path, encrypted_img)

        # Save raw encrypted bytes to .bin
        bin_path = enc_path.replace(".png", ".bin")
        with open(bin_path, "wb") as bin_file:
            bin_file.write(raw_encrypted_bytes)

        # Generate QR code for key only (no IV in XOR)
        key_str = base64.b64encode(key).decode('utf-8')
        qr_path = os.path.join(tempfile.gettempdir(), os.path.splitext(os.path.basename(image_path))[0] + "_xor_qr.png")
        qrcode.make(key_str).save(qr_path)

        # Store original image dimensions
        original_shape = {"height": h, "width": w, "channels": c}
        return enc_path, qr_path, key_str, bin_path, original_shape

    
    def rsa_encrypt(self, img, image_path, output_folder='.'):
        """Hybrid RSA-AES encryption of an image"""
        try:
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Image not found.")

            h, w, c = img.shape
            block_size = AES.block_size
            encrypted_channels = []
            raw_encrypted_bytes = b''

            # Generate AES key and IV
            aes_key = get_random_bytes(32)
            iv = get_random_bytes(16)

            # Encrypt each channel
            for channel in cv2.split(img):
                channel_bytes = channel.tobytes()
                padded_bytes = pad(channel_bytes, block_size)
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                encrypted_bytes = cipher.encrypt(padded_bytes)
                raw_encrypted_bytes += encrypted_bytes

                # Prepare encrypted image visualization
                padded_height = len(encrypted_bytes) // w + (1 if len(encrypted_bytes) % w else 0)
                encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
                encrypted_2d = np.zeros((padded_height, w), dtype=np.uint8)
                encrypted_2d.flat[:len(encrypted_array)] = encrypted_array
                encrypted_channels.append(encrypted_2d)

            # Create output directory if needed
            os.makedirs(output_folder, exist_ok=True)
            filename = os.path.splitext(os.path.basename(image_path))[0]

            # Save encrypted files
            enc_path = os.path.join(output_folder, f"encrypted_{filename}.png")
            bin_path = os.path.join(output_folder, f"encrypted_{filename}.bin")
            qr_path = os.path.join(output_folder, f"{filename}_rsa_qr.png")

            # Save visual encrypted image
            min_height = min([ch.shape[0] for ch in encrypted_channels])
            encrypted_img = cv2.merge([ch[:min_height, :] for ch in encrypted_channels])
            cv2.imwrite(enc_path, encrypted_img)

            # Save raw encrypted data
            with open(bin_path, "wb") as bin_file:
                bin_file.write(raw_encrypted_bytes)

            # Generate RSA keys and encrypt AES key
            rsa_key = RSA.generate(2048)
            cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
            encrypted_key_iv = cipher_rsa.encrypt(aes_key + iv)
            encrypted_key_iv_b64 = base64.b64encode(encrypted_key_iv).decode()

            # Create QR code
            qrcode.make(encrypted_key_iv_b64).save(qr_path)

            original_shape = {"height": h, "width": w, "channels": c}
            return enc_path, qr_path, encrypted_key_iv_b64, bin_path, original_shape

        except Exception as e:
            raise ValueError(f"RSA encryption failed: {str(e)}")

    
    
    # Decryption algorithms
    def aes_decrypt(self, bin_path, key_iv_str, original_shape):
    
        try:
            # Decode key and IV from base64
            key_iv = base64.b64decode(key_iv_str)
            key = key_iv[:32]  # AES-256 key (32 bytes)
            iv = key_iv[32:48]  # 16-byte IV

            # Read the encrypted binary file
            with open(bin_path, "rb") as f:
                encrypted = f.read()

            # Create cipher and decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_bytes = cipher.decrypt(encrypted)

            # Convert to numpy array
            img_array = np.frombuffer(decrypted_bytes, dtype=np.uint8)

            # Extract shape from the dictionary
            try:
                h = original_shape["height"]
                w = original_shape["width"]
                c = original_shape["channels"]
                shape = (h, w, c)
            except KeyError:
                raise ValueError("Invalid original_shape format - must contain height, width, channels")

            # Reshape to original dimensions
            try:
                # Take only the needed bytes (height * width * channels)
                img = np.reshape(img_array[:shape[0]*shape[1]*shape[2]], shape)
            except ValueError as e:
                raise ValueError(f"Could not reshape decrypted image: {str(e)}")

            # Save decrypted image
            output_path = bin_path.replace(".bin", "_decrypted.jpg")
            cv2.imwrite(output_path, img)

            return {
                "decrypted_path": output_path,
                "image": img
            }

        except Exception as e:
            raise ValueError(f"AES decryption failed: {str(e)}")
        
    def des_decrypt(self, bin_path, key_iv_str, original_shape):
        """Decrypt DES-encrypted .bin file using the same logic as AES decryption"""
        try:
            # Decode key and IV from base64
            key_iv = base64.b64decode(key_iv_str)
            if len(key_iv) < 16:
                raise ValueError("Key/IV string too short - must be at least 16 bytes")
            key = key_iv[:8]  # DES key (8 bytes)
            iv = key_iv[8:16]  # 8-byte IV

            # Read the encrypted binary file
            with open(bin_path, "rb") as f:
                encrypted = f.read()

            # Create cipher and decrypt
            cipher = DES.new(key, DES.MODE_CBC, iv)
            decrypted_bytes = cipher.decrypt(encrypted)

            # Convert to numpy array
            img_array = np.frombuffer(decrypted_bytes, dtype=np.uint8)

            # Extract shape from the dictionary
            try:
                h = original_shape["height"]
                w = original_shape["width"]
                c = original_shape["channels"]
                shape = (h, w, c)
            except KeyError:
                raise ValueError("Invalid original_shape format - must contain height, width, channels")

            # Reshape to original dimensions
            try:
                # Take only the needed bytes (height * width * channels)
                img = np.reshape(img_array[:shape[0]*shape[1]*shape[2]], shape)
            except ValueError as e:
                raise ValueError(f"Could not reshape decrypted image: {str(e)}")

            # Save decrypted image
            output_path = bin_path.replace(".bin", "_decrypted.jpg")
            cv2.imwrite(output_path, img)

            return {
                "decrypted_path": output_path,
                "image": img
            }

        except Exception as e:
            raise ValueError(f"DES decryption failed: {str(e)}")



    def xor_decrypt(self, bin_path, key_str, original_shape):
        try:
            # Decode the XOR key from base64 string
            key = base64.b64decode(key_str)

            # Read the encrypted binary file
            with open(bin_path, "rb") as f:
                encrypted_bytes = f.read()

            # Repeat key bytes to match the length of encrypted bytes
            key_bytes = (key * ((len(encrypted_bytes) // len(key)) + 1))[:len(encrypted_bytes)]

            # XOR decryption (same operation as encryption)
            decrypted_bytes = bytes([b ^ k for b, k in zip(encrypted_bytes, key_bytes)])

            # Convert decrypted bytes to numpy array
            img_array = np.frombuffer(decrypted_bytes, dtype=np.uint8)

            # Extract original shape info
            try:
                h = original_shape["height"]
                w = original_shape["width"]
                c = original_shape["channels"]
                shape = (h, w, c)
            except KeyError:
                raise ValueError("Invalid original_shape format - must contain height, width, channels")

            # Reshape decrypted array to original image shape
            try:
                img = np.reshape(img_array[:h * w * c], shape)
            except ValueError as e:
                raise ValueError(f"Could not reshape decrypted image: {str(e)}")

            # Save decrypted image
            output_path = bin_path.replace(".bin", "_decrypted.jpg")
            cv2.imwrite(output_path, img)

            return {
                "decrypted_path": output_path,
                "image": img
            }

        except Exception as e:
            raise ValueError(f"XOR decryption failed: {str(e)}")

    

def create_database():
    conn = sqlite3.connect('hospitals.db')
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS hospitals")
    cursor.execute('''
        CREATE TABLE hospitals (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    hospitals_data = [
        (1, "Hôpital Charles Nicolle", "Tunis", "pass123"),
        (2, "Hôpital La Rabta", "Tunis", "rabta456"),
        (3, "Hôpital Habib Thameur", "Tunis", "thameur789"),
        (4, "Hôpital Fattouma Bourguiba", "Monastir", "monastir321"),
        (5, "Hôpital Sahloul", "Sousse", "sahloul654"),
        (6, "Hôpital Tahar Sfar", "Mahdia", "mahdia987"),
        (7, "Hôpital Hédi Chaker", "Sfax", "sfax111"),
        (8, "Hôpital Farhat Hached", "Sousse", "farhat222"),
        (9, "Hôpital Régional de Gafsa", "Gafsa", "gafsa333"),
        (10, "Hôpital Régional de Kairouan", "Kairouan", "kairouan444"),
    ]

    cursor.executemany('''
        INSERT INTO hospitals (id, name, location, password)
        VALUES (?, ?, ?, ?)
    ''', hospitals_data)

    conn.commit()
    conn.close()
    print("✅ Database created and populated successfully.")

if __name__ == "__main__":
    create_database()
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()