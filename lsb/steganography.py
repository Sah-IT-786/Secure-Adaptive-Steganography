from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from Crypto.Cipher import Blowfish, AES
from Crypto.Util.Padding import pad, unpad
import numpy as np
import zlib
import os
from io import BytesIO

# Encryption Functions
def blowfish_encrypt(message, key):
    """Encrypt data using Blowfish encryption."""
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return cipher.encrypt(pad(message, Blowfish.block_size))

def aes_encrypt(data, key):
    """Encrypt data using AES encryption."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def hybrid_encrypt(data, blowfish_key, aes_key):
    """
    Encrypt data using a hybrid approach:
    1. Blowfish encryption first.
    2. AES encryption on top of the Blowfish result.
    """
    blowfish_encrypted = blowfish_encrypt(data, blowfish_key)
    aes_encrypted = aes_encrypt(blowfish_encrypted, aes_key)
    return aes_encrypted

# Decryption Functions
def aes_decrypt(data, key):
    """Decrypt data using AES decryption."""
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)

def blowfish_decrypt(data, key):
    """Decrypt data using Blowfish decryption."""
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return unpad(cipher.decrypt(data), Blowfish.block_size)

def hybrid_decrypt(data, blowfish_key, aes_key):
    """
    Decrypt data using a hybrid approach:
    1. AES decryption first.
    2. Blowfish decryption on the result.
    """
    aes_decrypted = aes_decrypt(data, aes_key)
    original_data = blowfish_decrypt(aes_decrypted, blowfish_key)
    return original_data

# LSB Steganography Functions
def lsb_embed(image, data_bits):
    # Convert image to numpy array and flatten the pixels
    pixels = np.array(image, dtype=np.uint8)
    flat_pixels = pixels.flatten()

    for i, bit in enumerate(data_bits):
        # Use & 254 (0xFE) to clear the LSB, ensuring proper uint8 handling
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)

    # Reshape the flattened array back to the original image shape
    stego_pixels = flat_pixels.reshape(pixels.shape)
    return Image.fromarray(stego_pixels.astype(np.uint8))

def extract_bits(image, length):
    """
    Extract the embedded data bits from the image.
    """
    pixels = np.array(image).flatten()
    return ''.join(str(p & 1) for p in pixels[:length])

# Helper Functions for Bit Conversion
def to_bit_stream(data):
    """Convert byte data into a stream of bits."""
    return ''.join(format(byte, '08b') for byte in data)

def to_bytes(bit_stream):
    """Convert a bit stream back to bytes."""
    return bytes(int(bit_stream[i:i+8], 2) for i in range(0, len(bit_stream), 8))

# GUI Application Class
class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography with Hybrid Encryption")
        self.root.geometry("600x600")

        # Variables
        self.cover_image_path = None
        self.hidden_data_path = None
        self.output_image_path = "stego_image.png"
        self.blowfish_key = b'BlowfishKey1234'  # 16-byte key for Blowfish
        self.aes_key = b'AESKey16Bytes!! '  # Ensure 16 bytes for AES key

        # UI Layout
        Label(root, text="Image Steganography", font=("Helvetica", 16)).pack(pady=10)

        # Preview Frame for displaying images
        self.preview_frame = Frame(root)
        self.preview_frame.pack(pady=10)

        Button(root, text="Load Cover Image", command=self.load_cover_image).pack(pady=5)
        Button(root, text="Select Data Type", command=self.select_data_type).pack(pady=5)
        Button(root, text="Extract Data", command=self.extract_data).pack(pady=5)

    def load_cover_image(self):
        """Load the cover image."""
        self.cover_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg")])
        if self.cover_image_path:
            # Open and display the image
            image = Image.open(self.cover_image_path)
            image.thumbnail((250, 250))  # Resize the image to fit the window
            self.cover_image = ImageTk.PhotoImage(image)

            # Clear previous image preview (if any)
            for widget in self.preview_frame.winfo_children():
                widget.destroy()

            # Display the loaded cover image in the preview frame
            Label(self.preview_frame, image=self.cover_image).pack()

            messagebox.showinfo("Success", "Cover image loaded successfully!")

    def select_data_type(self):
        """Allow user to select the type of data to hide."""
        data_type = simpledialog.askstring("Data Type", "Enter the data type to hide: text, img, or audio")
        if data_type == "text":
            self.hide_text_data()
        elif data_type == "img":
            self.hide_image_data()
        elif data_type == "audio":
            self.hide_audio_data()
        else:
            messagebox.showerror("Error", "Invalid data type entered. Please choose from text, img, or audio.")

    def hide_text_data(self):
        """Hide text data into the image."""
        secret_message = simpledialog.askstring("Input", "Enter secret message:")
        if not secret_message:
            messagebox.showerror("Error", "No message entered!")
            return
        compressed_data = zlib.compress(secret_message.encode())  # Compress text data

        # Encrypt the data
        encrypted_data = hybrid_encrypt(compressed_data, self.blowfish_key, self.aes_key)

        self.embed_data(encrypted_data)

    def hide_image_data(self):
        """Hide image data into the cover image."""
        self.hidden_data_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg")])
        with open(self.hidden_data_path, "rb") as f:
            file_data = f.read()
        compressed_data = zlib.compress(file_data)  # Compress file data

        # Encrypt the data
        encrypted_data = hybrid_encrypt(compressed_data, self.blowfish_key, self.aes_key)

        self.embed_data(encrypted_data)

    def hide_audio_data(self):
        """Hide audio data into the image."""
        self.hidden_data_path = filedialog.askopenfilename(filetypes=[("Audio Files", "*.mp3;*.wav")])
        with open(self.hidden_data_path, "rb") as f:
            file_data = f.read()
        compressed_data = zlib.compress(file_data)  # Compress file data

        # Encrypt the data
        encrypted_data = hybrid_encrypt(compressed_data, self.blowfish_key, self.aes_key)

        self.embed_data(encrypted_data)

    def embed_data(self, encrypted_data):
        """Embed the encrypted data into the image."""
        if not self.cover_image_path:
            messagebox.showerror("Error", "Please load a cover image first!")
            return

        # Load the cover image
        image = Image.open(self.cover_image_path)
        total_pixels = np.array(image).size  # Total number of pixels in the image

        # Convert to bit stream and validate size
        data_bits = to_bit_stream(encrypted_data)
        print(f"Embedded data size in bits: {len(data_bits)} bits")
        print(f"Embedded data size in bytes: {len(encrypted_data)} bytes")
        
        if len(data_bits) > total_pixels:
            messagebox.showerror("Error", "The cover image is too small to hide the data!")
            return

        # Embed the encrypted data
        stego_image = lsb_embed(image, data_bits)
        stego_image.save(self.output_image_path)

        # Preview the stego image
        stego_image.thumbnail((250, 250))
        self.stego_image = ImageTk.PhotoImage(stego_image)
        for widget in self.preview_frame.winfo_children():
            widget.destroy()

        Label(self.preview_frame, image=self.stego_image).pack()

        # Display embedded data size on GUI
        Label(self.root, text=f"Embedded Data Size: {len(data_bits)} bits").pack(pady=10)
        messagebox.showinfo("Success", f"Data embedded successfully!\nSaved as {self.output_image_path}")

    def extract_data(self):
        """Extract hidden data from a stego image."""
        stego_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png")])
        if not stego_image_path:
            messagebox.showerror("Error", "Please load the stego image!")
            return

        # Extract the data length
        length = int(simpledialog.askstring("Input", "Enter length of embedded data in bits:"))

        # Extract bits and convert back to bytes
        stego_image = Image.open(stego_image_path)
        extracted_bits = extract_bits(stego_image, length)
        extracted_data = to_bytes(extracted_bits)

        # Decrypt the data
        decrypted_data = hybrid_decrypt(extracted_data, self.blowfish_key, self.aes_key)
        original_data = zlib.decompress(decrypted_data)  # Decompress data

        # Check if the extracted data is an image or some other type of data
        is_image = False
        try:
            # Attempt to load the data as an image to determine if it's a valid image
            Image.open(BytesIO(original_data))
            is_image = True
        except:
            is_image = False

        # Save the extracted data
        if is_image:
            # If the data is an image, save it as a .png (or you can change this to .jpg if needed)
            output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
            if output_path:
                with open(output_path, "wb") as f:
                    f.write(original_data)
                messagebox.showinfo("Success", f"Image extracted and saved at {output_path}")
        else:
            # Otherwise, save as a text file
            output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
            if output_path:
                with open(output_path, "wb") as f:
                    f.write(original_data)
                messagebox.showinfo("Success", f"Data extracted and saved at {output_path}")


if __name__ == "__main__":
    root = Tk()
    app = SteganographyApp(root)
    root.mainloop()
