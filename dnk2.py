import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from typing import Union, Tuple
import time

NONCE_SIZE = 16
MARKER_START = "AAAA"
MARKER_END = "TTTT"
BITS_TO_NUCLEOTIDE = {
    '00': 'A',
    '01': 'C',
    '10': 'G',
    '11': 'T'
}
NUCLEOTIDE_TO_BITS = {v: k for k, v in BITS_TO_NUCLEOTIDE.items()}

class DNK2Cipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes only (256 bits)")
        
        self.key = key
        self.backend = default_backend()
    
    @classmethod
    def generate_key(cls) -> bytes:
        return secrets.token_bytes(32)
    
    @classmethod
    def from_password(cls, password: str, salt: bytes = None) -> Tuple['DNK2Cipher', bytes]:
        if salt is None:
            salt = secrets.token_bytes(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return cls(key), salt
    
    def _generate_chacha20_stream(self, nonce: bytes, length: int) -> bytes:
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")
        
        algorithm = algorithms.ChaCha20(self.key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=self.backend)
        encryptor = cipher.encryptor()
        
        zeros = b'\x00' * length
        return encryptor.update(zeros)
    
    def _bytes_to_dna(self, data: bytes) -> str:
        dna = []
        for byte in data:
            bits = format(byte, '08b')
            for i in range(0, 8, 2):
                pair = bits[i:i+2]
                dna.append(BITS_TO_NUCLEOTIDE[pair])
        return ''.join(dna)
    
    def _dna_to_bytes(self, dna: str) -> bytes:
        if len(dna) % 4 != 0:
            raise ValueError("DNA length must be multiple of 4")
        
        bytes_data = []
        for i in range(0, len(dna), 4):
            byte_bits = ''
            for j in range(4):
                nucleotide = dna[i + j]
                if nucleotide not in NUCLEOTIDE_TO_BITS:
                    raise ValueError(f"Incorrect nucleotide: {nucleotide}")
                byte_bits += NUCLEOTIDE_TO_BITS[nucleotide]
            bytes_data.append(int(byte_bits, 2))
        return bytes(bytes_data)
    
    def encrypt(self, message: Union[str, bytes]) -> Tuple[str, bytes]:
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        nonce = secrets.token_bytes(NONCE_SIZE)
        key_stream = self._generate_chacha20_stream(nonce, len(message))
        encrypted_data = bytes(a ^ b for a, b in zip(message, key_stream))
        
        dna_data = self._bytes_to_dna(encrypted_data)
        dna_nonce = self._bytes_to_dna(nonce)
        
        result = dna_nonce + MARKER_START + dna_data + MARKER_END
        return result, nonce
    
    def decrypt(self, dna_packet: str) -> bytes:
        if not dna_packet.endswith(MARKER_END):
            raise ValueError("End marker 'TTTT' is missing")
        
        marker_pos = dna_packet.find(MARKER_START)
        if marker_pos == -1:
            raise ValueError("Start marker 'AAAA' is missing")
        
        dna_nonce = dna_packet[:marker_pos]
        if len(dna_nonce) != NONCE_SIZE * 4:
            raise ValueError(f"Incorrect Nonce length")
        
        nonce = self._dna_to_bytes(dna_nonce)
        
        start_data = marker_pos + len(MARKER_START)
        end_data = len(dna_packet) - len(MARKER_END)
        dna_encrypted = dna_packet[start_data:end_data]
        
        encrypted = self._dna_to_bytes(dna_encrypted)
        key_stream = self._generate_chacha20_stream(nonce, len(encrypted))
        
        return bytes(a ^ b for a,b in zip(encrypted, key_stream))
    
    def encrypt_with_auth(self, message: Union[str, bytes]) -> Tuple[str, bytes]:
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=self.backend)
        h.update(message)
        signature = h.finalize()
        
        message_with_sig = message + signature
        return self.encrypt(message_with_sig)
    
    def decrypt_with_auth(self, dna_packet: str) -> bytes:
        decrypted = self.decrypt(dna_packet)
        
        if len(decrypted) < 32:
            raise ValueError("The data is too short to verify the signature.")
        
        message = decrypted[:-32]
        expected_sig = decrypted[-32:]
        
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=self.backend)
        h.update(message)
        
        try:
            h.verify(expected_sig)
            return message
        except:
            raise ValueError("Authentication error: data has been changed!")

class DNK2App:
    def __init__(self, root):
        self.root = root
        self.root.title("DNK2 Encrypt/Decrypt")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        
        style = ttk.Style()
        style.theme_use('clam')
        
        self.create_main_menu()
        
    def create_main_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        title_label = ttk.Label(
            self.root,
            text="DNK-2 Cryptosystem",
            font=("Arial", 20, "bold")
        )
        title_label.pack(pady=20)
        
        desc_label = ttk.Label(
            self.root,
            text="Algorithm for encrypting data in DNA sequences\nVersion 1.2",
            font=("Arial, 10"),
            justify="center"
        )
        desc_label.pack(pady=10)
        
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=40)
        
        encrypt_btn = ttk.Button(btn_frame, text="Encrypt", command=self.show_encrypt_window, width=25)
        encrypt_btn.pack(pady=10)
        decrypt_btn = ttk.Button(btn_frame, text="Decrypt", command=self.show_decrypt_window, width=25)
        decrypt_btn.pack(pady=10)
        exit_btn = ttk.Button(btn_frame, text="Exit", command=self.root.quit, width=25)
        exit_btn.pack(pady=10)
        
    def show_encrypt_window(self):
        encrypt_win = tk.Toplevel(self.root)
        encrypt_win.title("Encrypt")
        encrypt_win.geometry("600x500")
        encrypt_win.resizable(False, False)
    
        ttk.Label(
            encrypt_win,
            text="Encrypt data",
            font=("Arial", 16, "bold")
        ).pack(pady=20)
    
        input_frame = ttk.LabelFrame(encrypt_win, text="Data source")
        input_frame.pack(pady=10, padx=20, fill="x")
    
        self.input_type = tk.StringVar(value="text")
    
        ttk.Radiobutton(
            input_frame,
            text="Text message",
            variable=self.input_type,
            value="text",
            command=self.toggle_input_mode
        ).pack(pady=5, anchor="w", padx=10)
    
        ttk.Radiobutton(
            input_frame,
            text="File",
            variable=self.input_type,
            value="file",
            command=self.toggle_input_mode
        ).pack(pady=5, anchor="w", padx=10)
    
        self.text_input = scrolledtext.ScrolledText(
            encrypt_win,
            height=8,
            width=60,
            font=("Arial", 10)
        )
        self.text_input.pack(pady=10, padx=20)

        self.file_frame = ttk.Frame(encrypt_win)
        self.file_path = tk.StringVar()
    
        ttk.Label(self.file_frame, text="Choose file:").pack(side="left", padx=5)
        ttk.Entry(self.file_frame, textvariable=self.file_path, width=40).pack(side="left", padx=5)
        ttk.Button(
            self.file_frame,
            text="Browse...",
            command=self.browse_file
        ).pack(side="left", padx=5)
    
        self.file_frame.pack_forget()

        pass_frame = ttk.LabelFrame(encrypt_win, text="Password")
        pass_frame.pack(pady=10, padx=20, fill="x")
    
        self.password = tk.StringVar()
        ttk.Entry(
            pass_frame,
            textvariable=self.password,
            show="*",
            width=50
        ).pack(pady=10, padx=10)

        ttk.Button(
            encrypt_win,
            text="Encrypt",
            command=lambda: self.start_encryption(encrypt_win),
            width=20
        ).pack(pady=20)
        
    def show_decrypt_window(self):
        decrypt_win = tk.Toplevel(self.root)
        
        decrypt_win.title("Decrypt")
        decrypt_win.geometry("500x400")
        decrypt_win.resizable(False, False)
        
        ttk.Label(
            decrypt_win,
            text="Decrypt data",
            font=("Arial", 16, "bold")
        ).pack(pady=20)
        
        file_frame = ttk.LabelFrame(decrypt_win, text="Choose .DNK file")
        file_frame.pack(pady=20, padx=20, fill="x")
        
        self.decrypt_file_path = tk.StringVar()
        
        ttk.Entry(file_frame, textvariable=self.decrypt_file_path, width=50).pack(pady=10, padx=10)
        ttk.Button(file_frame, text="Browse...", command=self.browse_dnk_file).pack(pady=10)
        
        pass_frame = ttk.LabelFrame(decrypt_win, text="Password (key)")
        pass_frame.pack(pady=10, padx=20, fill="x")
        
        self.decrypt_password = tk.StringVar()
        ttk.Entry(pass_frame, textvariable=self.decrypt_password, show="*", width=50).pack(pady=10, padx=10)
        ttk.Button(decrypt_win, text="Decrypt", command=lambda:self.start_decryption(decrypt_win), width=20).pack(pady=20)
        
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
            
    def browse_dnk_file(self):
        filename=filedialog.askopenfilename(filetypes=[("DNK files", "*.DNK"), ("All files", "*.*")])
        if filename:
            self.decrypt_file_path.set(filename)
    
    def start_encryption(self, window):
        progress_win = tk.Toplevel(window)
        progress_win.title("Process")
        
        progress_win.geometry("300x150")
        progress_win.resizable(False, False)
        
        ttk.Label(
            progress_win,
            text="Encrypting...",
            font=("Arial", 14, "bold")
        ).pack(pady=20)
        
        progress = ttk.Progressbar(
            progress_win,
            mode='indeterminate',
            length=200
        )
        progress.pack(pady=10)
        progress.start()
        
        thread = threading.Thread(
            target=self.do_encryption,
            args=(window, progress_win)
        )
        thread.daemon = True
        thread.start()

    def start_decryption(self, parent_window):
        if not self.decrypt_file_path.get():
            messagebox.showerror("Error", "Please select a .DNK file")
            return
        if not self.decrypt_password.get():
            messagebox.showerror("Error", "Please enter password")
            return

        progress_win = tk.Toplevel(parent_window)
        progress_win.title("Processing")
        progress_win.geometry("300x150")
        progress_win.resizable(False, False)
        progress_win.transient(parent_window)
        progress_win.grab_set()
    
        ttk.Label(
            progress_win,
            text="Decrypting...",
            font=("Arial", 14, "bold")
        ).pack(pady=20)
    
        progress = ttk.Progressbar(
            progress_win,
            mode='indeterminate',
            length=200
        )
        progress.pack(pady=10)
        progress.start()
    
        thread = threading.Thread(
            target=self.do_decryption,
            args=(parent_window, progress_win)
        )
        thread.daemon = True
        thread.start()
        
    def do_encryption(self, parent_win, progress_win):
        try:
            password = self.password.get().encode('utf-8')
            cipher, salt = DNK2Cipher.from_password(password.decode())
            
            if self.input_type.get() == "text":
                data = self.text_input.get("1.0", tk.END).strip()
                if not data:
                    raise ValueError("Enter text to encrypt")
                data_bytes = data.encode('utf-8')
            else:
                file_path = self.file_path.get()
                if not file_path:
                    raise ValueError("Choose file")
                with open(file_path, 'rb') as f:
                    data_bytes = f.read()
            
            dna_packet, nonce = cipher.encrypt_with_auth(data_bytes)
            
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            output_file = os.path.join(desktop, "dnk-2-crypted.DNK")
            
            with open(output_file, 'wb') as f:
                f.write(salt)
                f.write(dna_packet.encode('utf-8'))
            
            progress_win.destroy()
            
            self.show_key_window(nonce.hex(), output_file)
        
        except Exception as e:
            progress_win.destroy()
            messagebox.showerror("Error", str(e))
    
    def do_decryption(self, parent_win, progress_win):
        try:
            # Получаем данные
            password = self.decrypt_password.get().encode('utf-8')
            file_path = self.decrypt_file_path.get()
            
            if not file_path:
                raise ValueError("Choose .DNK file")
            
            # Читаем файл
            with open(file_path, 'rb') as f:
                salt = f.read(16)  # Первые 16 байт - соль
                dna_packet = f.read().decode('utf-8')
            
            # Создаем ключ из пароля с солью
            cipher, _ = DNK2Cipher.from_password(password.decode(), salt)
            
            # Расшифровываем
            decrypted_data = cipher.decrypt_with_auth(dna_packet)
            
            # Сохраняем результат
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            output_file = os.path.join(desktop, "decrypted_output")
            
            # Пытаемся декодировать как текст
            try:
                text_result = decrypted_data.decode('utf-8')
                # Сохраняем как текст
                with open(output_file + ".txt", 'w', encoding='utf-8') as f:
                    f.write(text_result)
                result_msg = f"File saved: {output_file}.txt"
            except:
                # Сохраняем как бинарный файл
                with open(output_file + ".bin", 'wb') as f:
                    f.write(decrypted_data)
                result_msg = f"File saved: {output_file}.bin"
            
            progress_win.destroy()
            messagebox.showinfo("Succes", f"Decryption has done!\n{result_msg}")
            
        except Exception as e:
            progress_win.destroy()
            messagebox.showerror("Error", str(e))
    
    def show_key_window(self, key_hex, file_path):
        key_win = tk.Toplevel(self.root)
        key_win.title("Encryption key")
        key_win.geometry("500x300")
        key_win.resizable(False, False)
        
        ttk.Label(
            key_win,
            text="Encryption has done!",
            font=("Arial", 14, "bold"),
            foreground="green"
        ).pack(pady=20)
        
        ttk.Label(
            key_win,
            text="Nonce (NO KEY!!):",
            font=("Arial", 10)
        ).pack(pady=5)
        
        key_frame = ttk.Frame(key_win)
        key_frame.pack(pady=10, padx=20, fill="x")
        
        key_entry = ttk.Entry(key_frame, width=50)
        key_entry.insert(0, key_hex)
        key_entry.pack(side="left", padx=5)
        key_entry.config(state="readonly")
        
        ttk.Button(key_frame, text="Copy", command=lambda:self.copy_to_clipboard(key_hex, key_win)).pack(side="left")
        ttk.Label(key_win, text=f"File saved:\n{file_path}", font=("Arial", 9), justify="center").pack(pady=20)
        ttk.Button(key_win, text="OK", command=key_win.destroy, width=20).pack(pady=10)
    
    def copy_to_clipboard(self, text, window):
        window.clipboard_clear()
        window.clipboard_append(text)
        
        messagebox.showinfo("Copied", "Key copied to clipboard")

    def toggle_input_mode(self):
        if self.input_type.get() == "text":
            self.text_input.pack(pady=10, padx=20)
            self.file_frame.pack_forget()
        else:
            self.text_input.pack_forget()
            self.file_frame.pack(pady=10, padx=20, fill="x")

if __name__ == "__main__":
    root = tk.Tk()
    app = DNK2App(root)
    root.mainloop()

