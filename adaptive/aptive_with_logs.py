from tkinter import *
from tkinter import filedialog, messagebox, simpledialog, Label
from PIL import Image, ImageTk
import numpy as np
import zlib
from io import BytesIO
from Crypto.Cipher import Blowfish, AES
from Crypto.Util.Padding import pad, unpad
import math
import os

# Encryption Functions
def blowfish_encrypt(message, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return cipher.encrypt(pad(message, Blowfish.block_size))

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def hybrid_encrypt(data, blowfish_key, aes_key):
    blowfish_encrypted = blowfish_encrypt(data, blowfish_key)
    aes_encrypted = aes_encrypt(blowfish_encrypted, aes_key)
    return aes_encrypted

# Decryption Functions
def aes_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)

def blowfish_decrypt(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return unpad(cipher.decrypt(data), Blowfish.block_size)

def hybrid_decrypt(data, blowfish_key, aes_key):
    aes_decrypted = aes_decrypt(data, aes_key)
    original_data = blowfish_decrypt(aes_decrypted, blowfish_key)
    return original_data

# Adaptive Steganography Functions
def adaptive_embed(image, data_bits):
    pixels = np.array(image, dtype=np.uint8)
    height, width, _ = pixels.shape
    data_index = 0

    for i in range(height):
        for j in range(width):
            pixel = pixels[i, j]
            for k in range(3):  # Red, Green, Blue channels
                if data_index < len(data_bits):
                    # Embed the bit into the least significant bit of each channel
                    pixel[k] = (pixel[k] & 0xFE) | int(data_bits[data_index])
                    data_index += 1
            pixels[i, j] = pixel
            if data_index >= len(data_bits):
                break
        if data_index >= len(data_bits):
            break

    return Image.fromarray(pixels)

def extract_bits(image, length):
    pixels = np.array(image)
    height, width, _ = pixels.shape
    extracted_bits = []

    for i in range(height):
        for j in range(width):
            pixel = pixels[i, j]
            for k in range(3):  # Red, Green, Blue channels
                extracted_bits.append(str(pixel[k] & 1))
                if len(extracted_bits) >= length:
                    return ''.join(extracted_bits)

    return ''.join(extracted_bits)

# Helper Functions for Bit Conversion
def to_bit_stream(data):
    return ''.join(format(byte, '08b') for byte in data)

def to_bytes(bit_stream):
    return bytes(int(bit_stream[i:i+8], 2) for i in range(0, len(bit_stream), 8))

# Calculate PSNR (Peak Signal-to-Noise Ratio)
def psnr(original, stego):
    mse_value = np.mean((np.array(original).astype(float) - np.array(stego).astype(float))**2)
    if mse_value == 0:
        return 100  # No noise, perfect quality
    max_pixel_value = 255.0
    psnr_value = 20 * math.log10(max_pixel_value / math.sqrt(mse_value))
    return psnr_value

# Calculate MSE (Mean Squared Error)
def mse(original, stego):
    return np.mean((np.array(original).astype(float) - np.array(stego).astype(float))**2)

# Log PSNR and MSE to a log file
def log_psnr_mse(cover_image_path, stego_image_path, psnr_value, mse_value):
    log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.txt")
    with open(log_file_path, "a") as log_file:
        log_file.write(f"Cover Image: {cover_image_path}\n")
        log_file.write(f"Stego Image: {stego_image_path}\n")
        log_file.write(f"PSNR: {psnr_value:.2f} dB\n")
        log_file.write(f"MSE: {mse_value:.2f}\n")
        log_file.write("-" * 40 + "\n")

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

        self.preview_frame = Frame(root)
        self.preview_frame.pack(pady=10)

        Button(root, text="Load Cover Image", command=self.load_cover_image).pack(pady=5)
        Button(root, text="Select Data Type", command=self.select_data_type).pack(pady=5)
        Button(root, text="Extract Data", command=self.extract_data).pack(pady=5)

        # PSNR, MSE, and Embedded Bits Length Labels
        self.psnr_label = Label(root, text="PSNR: ")
        self.psnr_label.pack(pady=5)
        self.mse_label = Label(root, text="MSE: ")
        self.mse_label.pack(pady=5)
        self.embedded_length_label = Label(root, text="Embedded Bits Length: ")
        self.embedded_length_label.pack(pady=5)

    # Method to load cover image
    def load_cover_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.cover_image_path = file_path
            cover_image = Image.open(self.cover_image_path)
            cover_image.thumbnail((150, 150))  # Resize for preview
            cover_image_preview = ImageTk.PhotoImage(cover_image)
            Label(self.preview_frame, image=cover_image_preview).pack(pady=5)
            self.preview_frame.image = cover_image_preview  # Keep a reference

    # Method to select data type
    def select_data_type(self):
        data_type = filedialog.askopenfilename(title="Select Data File", 
                                               filetypes=[("Text Files", "*.txt"), 
                                                         ("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.tiff")])
        if data_type:
            if data_type.endswith(".txt"):
                self.hide_text_data(data_type)
            elif data_type.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff')):
                self.hide_image_data(data_type)
            else:
                messagebox.showerror("Error", "Invalid data type selected!")

    # Method to hide text data in image
    def hide_text_data(self, text_file):
        with open(text_file, "rb") as file:
            hidden_data = file.read()
        encrypted_data = hybrid_encrypt(zlib.compress(hidden_data), self.blowfish_key, self.aes_key)

        data_bits = to_bit_stream(encrypted_data)
        cover_image = Image.open(self.cover_image_path)
        stego_image = adaptive_embed(cover_image, data_bits)

        # Save the stego image
        stego_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if stego_image_path:
            stego_image.save(stego_image_path)
            messagebox.showinfo("Success", "Data hidden successfully in the image!")

            # Calculate PSNR and MSE
            psnr_value = psnr(cover_image, stego_image)
            mse_value = mse(cover_image, stego_image)

            # Update the PSNR and MSE labels
            self.psnr_label.config(text=f"PSNR: {psnr_value:.2f} dB")
            self.mse_label.config(text=f"MSE: {mse_value:.2f}")

            # Show the length of embedded bits
            embedded_length = len(data_bits)
            self.embedded_length_label.config(text=f"Embedded Bits Length: {embedded_length}")
            print(f"Embedded Bits Length: {embedded_length} bits")

            # Log the PSNR and MSE to a log file
            log_psnr_mse(self.cover_image_path, stego_image_path, psnr_value, mse_value)

    # Method to hide image data in cover image
    def hide_image_data(self, image_file):
        with open(image_file, "rb") as file:
            hidden_data = file.read()
        encrypted_data = hybrid_encrypt(zlib.compress(hidden_data), self.blowfish_key, self.aes_key)

        data_bits = to_bit_stream(encrypted_data)
        cover_image = Image.open(self.cover_image_path)
        stego_image = adaptive_embed(cover_image, data_bits)

        # Save the stego image
        stego_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if stego_image_path:
            stego_image.save(stego_image_path)
            messagebox.showinfo("Success", "Image data hidden successfully!")

            # Calculate PSNR and MSE
            psnr_value = psnr(cover_image, stego_image)
            mse_value = mse(cover_image, stego_image)

            # Update the PSNR and MSE labels
            self.psnr_label.config(text=f"PSNR: {psnr_value:.2f} dB")
            self.mse_label.config(text=f"MSE: {mse_value:.2f}")

            # Show the length of embedded bits
            embedded_length = len(data_bits)
            self.embedded_length_label.config(text=f"Embedded Bits Length: {embedded_length}")
            print(f"Embedded Bits Length: {embedded_length} bits")

            # Log the PSNR and MSE to a log file
            log_psnr_mse(self.cover_image_path, stego_image_path, psnr_value, mse_value)

    def extract_data(self):
        stego_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png")])
        if not stego_image_path:
            messagebox.showerror("Error", "Please load the stego image!")
            return

        # Request length of embedded data
        length = int(simpledialog.askstring("Input", "Enter length of embedded data in bits:"))
        stego_image = Image.open(stego_image_path)

        # Extract the bits from the stego image
        extracted_bits = extract_bits(stego_image, length)
        extracted_data = to_bytes(extracted_bits)

        # Decrypt the data
        decrypted_data = hybrid_decrypt(extracted_data, self.blowfish_key, self.aes_key)
        original_data = zlib.decompress(decrypted_data)

        # Check if the extracted data could be an image
        is_image = False
        try:
            # Try to open the extracted data as an image
            img = Image.open(BytesIO(original_data))
            img.verify()  # Verify if it's a valid image
            is_image = True
        except (IOError, SyntaxError) as e:
            is_image = False  # Not an image if an error occurs

        if is_image:
            # If the data is an image, save it
            output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
            if output_path:
                with open(output_path, "wb") as f:
                    f.write(original_data)
            messagebox.showinfo("Success", "Extracted image saved!")
        else:
            # If it's not an image, treat it as text and try to decode
            try:
                extracted_text = original_data.decode('utf-8')
                messagebox.showinfo("Extracted Text", extracted_text)
            except UnicodeDecodeError:
                # If the data isn't valid UTF-8 text, show an error
                messagebox.showerror("Error", "The extracted data is not valid text.")

# Main Program
if __name__ == "__main__":
    root = Tk()
    app = SteganographyApp(root)
    root.mainloop()
