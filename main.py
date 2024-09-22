import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
from cryptography.fernet import Fernet
import os


def generate_key():
    return Fernet.generate_key()


def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())


def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()


def text_to_binary(text):
    if isinstance(text, str):
        return ''.join(format(ord(char), '08b') for char in text)
    elif isinstance(text, bytes):
        return ''.join(format(byte, '08b') for byte in text)
    else:
        raise ValueError(f"Unsupported type for text_to_binary: {type(text)}")


def encode_image(image_path, message, key, output_path):
    print(f"Encoding message: {message}")
    print(f"Key type: {type(key)}")

    img = Image.open(image_path)
    width, height = img.size

    encrypted_message = encrypt_message(message, key)
    print(f"Encrypted message type: {type(encrypted_message)}")
    print(f"Encrypted message: {encrypted_message}")

    binary_message = text_to_binary(encrypted_message) + '1111111111111110'  # EOF marker
    print(f"Binary message: {binary_message[:50]}...")  # Print first 50 characters

    if len(binary_message) > width * height * 3:
        raise ValueError("Message too large for the image")

    data_index = 0
    for x in range(width):
        for y in range(height):
            pixel = list(img.getpixel((x, y)))
            for color_channel in range(3):  # R, G, B
                if data_index < len(binary_message):
                    pixel[color_channel] = pixel[color_channel] & ~1 | int(binary_message[data_index])
                    data_index += 1
            img.putpixel((x, y), tuple(pixel))
        if data_index >= len(binary_message):
            break

    img.save(output_path)
    print(f"Image saved to: {output_path}")
    return output_path


# Update the encrypt_message function to ensure it returns bytes
def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())

def binary_to_bytes(binary):
    return bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
def decode_image_from_file(image_path, key):
    img = Image.open(image_path)
    width, height = img.size
    binary_message = ""

    for x in range(width):
        for y in range(height):
            pixel = img.getpixel((x, y))
            for color_channel in range(3):  # R, G, B
                binary_message += str(pixel[color_channel] & 1)
            if binary_message[-16:] == '1111111111111110':
                encrypted_message = binary_to_bytes(binary_message[:-16])
                return decrypt_message(encrypted_message, key)

    raise ValueError("No hidden message found")

# Update the SteganographyGUI class's encode_and_save method
class SteganographyGUI:
    def __init__(self, master):
        self.master = master
        master.title("Steganography Tool")

        self.key_file = "encryption_key.key"
        if not os.path.exists(self.key_file):
            key = generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
        with open(self.key_file, "rb") as key_file:
            self.key = key_file.read()

        # Encode Section
        self.encode_frame = tk.LabelFrame(master, text="Encode", padx=5, pady=5)
        self.encode_frame.pack(padx=10, pady=10, fill="both", expand="yes")

        self.input_image_frame = tk.Frame(self.encode_frame)
        self.input_image_frame.pack(fill="x")

        self.input_image_button = tk.Button(self.input_image_frame, text="Select Input Image", command=self.select_input_image)
        self.input_image_button.pack(side="left")

        self.input_image_label = tk.Label(self.input_image_frame, text="")
        self.input_image_label.pack(side="left", padx=5)

        self.input_image_cancel = tk.Button(self.input_image_frame, text="x", command=self.cancel_input_image)
        self.input_image_cancel.pack(side="left")
        self.input_image_cancel.pack_forget()

        self.message_label = tk.Label(self.encode_frame, text="Enter message:")
        self.message_label.pack()
        self.message_entry = tk.Entry(self.encode_frame, width=50)
        self.message_entry.pack()

        self.encode_button = tk.Button(self.encode_frame, text="Encode and Save", command=self.encode_and_save)
        self.encode_button.pack()

        # Decode Section
        self.decode_frame = tk.LabelFrame(master, text="Decode", padx=5, pady=5)
        self.decode_frame.pack(padx=10, pady=10, fill="both", expand="yes")

        self.encoded_image_frame = tk.Frame(self.decode_frame)
        self.encoded_image_frame.pack(fill="x")

        self.encoded_image_button = tk.Button(self.encoded_image_frame, text="Select Encoded Image", command=self.select_encoded_image)
        self.encoded_image_button.pack(side="left")

        self.encoded_image_label = tk.Label(self.encoded_image_frame, text="")
        self.encoded_image_label.pack(side="left", padx=5)

        self.encoded_image_cancel = tk.Button(self.encoded_image_frame, text="x", command=self.cancel_encoded_image)
        self.encoded_image_cancel.pack(side="left")
        self.encoded_image_cancel.pack_forget()

        self.decode_button = tk.Button(self.decode_frame, text="Decode", command=self.decode_image_button_click)
        self.decode_button.pack()

        self.decoded_message_label = tk.Label(self.decode_frame, text="Decoded message:")
        self.decoded_message_label.pack()
        self.decoded_message_text = tk.Text(self.decode_frame, height=3, width=50)
        self.decoded_message_text.pack()

    def select_input_image(self):
        self.input_image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
        if self.input_image_path:
            self.input_image_button.config(state="disabled")
            self.input_image_label.config(text=os.path.basename(self.input_image_path))
            self.input_image_cancel.pack(side="left")

    def cancel_input_image(self):
        self.input_image_path = None
        self.input_image_button.config(state="normal")
        self.input_image_label.config(text="")
        self.input_image_cancel.pack_forget()

    def select_encoded_image(self):
        self.encoded_image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
        if self.encoded_image_path:
            self.encoded_image_button.config(state="disabled")
            self.encoded_image_label.config(text=os.path.basename(self.encoded_image_path))
            self.encoded_image_cancel.pack(side="left")

    def cancel_encoded_image(self):
        self.encoded_image_path = None
        self.encoded_image_button.config(state="normal")
        self.encoded_image_label.config(text="")
        self.encoded_image_cancel.pack_forget()

    def encode_and_save(self):
        if not hasattr(self, 'input_image_path') or not self.input_image_path:
            messagebox.showerror("Error", "Please select an input image first.")
            return

        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Error", "Please enter a message to encode.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if not output_path:
            return  # User cancelled save operation

        try:
            encoded_image_path = encode_image(self.input_image_path, message, self.key, output_path)
            messagebox.showinfo("Success", f"Message encoded successfully. Saved as {encoded_image_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode_image_button_click(self):
        if not hasattr(self, 'encoded_image_path') or not self.encoded_image_path:
            messagebox.showerror("Error", "Please select an encoded image first.")
            return

        try:
            decoded_message = decode_image_from_file(self.encoded_image_path, self.key)
            self.decoded_message_text.delete(1.0, tk.END)  # Clear previous message
            self.decoded_message_text.insert(tk.END, decoded_message)
        except Fernet.InvalidToken:
            messagebox.showerror("Error", "Invalid encryption key or the image doesn't contain an encrypted message.")
        except AttributeError:
            messagebox.showerror("Error", "Invalid encryption key or the image doesn't contain an encrypted message.")
        except ValueError as ve:
            messagebox.showerror("Error", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
            print(f"Detailed error: {e}")
            import traceback
            traceback.print_exc()


root = tk.Tk()
gui = SteganographyGUI(root)
root.mainloop()