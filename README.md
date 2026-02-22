# DNK-2 🔐🧬

**A modern encryption algorithm with DNA steganography.**

DNK-2 is a cryptographic system that encrypts data using ChaCha20 and then encodes the ciphertext into a DNA-like sequence (A, C, G, T). The result looks like a real DNA strand — perfect for steganography, biological data storage, or just for fun.

> *"I didn't know it was impossible, so I did it."*

---

## ✨ Features

- ✅ **ChaCha20 stream cipher** (256-bit key)
- ✅ **PBKDF2 key derivation** (600,000 iterations)
- ✅ **HMAC-SHA256 authentication** (integrity check)
- ✅ **DNA encoding** — 00→A, 01→C, 10→G, 11→T
- ✅ **Marker structure** — `[DNA-nonce][AAAA][DNA-data][TTTT]`
- ✅ **Text and file encryption**
- ✅ **GUI** (Tkinter) — user-friendly interface
- ✅ **UTF-8 support** (Russian, emoji, etc.)
- ✅ **Steganography-ready** — output indistinguishable from real DNA

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/DNK-2.git
cd DNK-2
pip install -r requirements.txt
python dnk2.py
```

Dependencies:

- Python 3.8+
- cryptography library

## 🚀 How to use
Encrypt:
    - Run the program
    - Choose Text or File
    - Enter your message or select a file
    - Set a password
    - Click Encrypt
    - Save the .DNK file
Decrypt:
    - Open the program
    - Go to Decrypt
    - Select your .DNK file
    - Enter the same password
    - Click Decrypt
    - Get your original data back
    
    # ⚠️ Note: The "key" shown after encryption is just the nonce — it's already inside the file. You only need the password to decrypt.

## 🧬 File format

[16 bytes salt]
[DNA-nonce (64 chars)]
[AAAA]
[DNA-encrypted data]
[TTTT]

    - .DNK files are plain text (A/C/G/T) + binary salt at the beginning
    - The nonce is encoded in DNA and stored at the start of the sequence
    - Markers AAAA and TTTT ensure correct parsing

## 🔐 Security
- Feature	Value
- Key size	256 bits
- Nonce size	128 bits (16 bytes)
- KDF	PBKDF2-HMAC-SHA256, 600k iterations
- Cipher	ChaCha20
- Authentication	HMAC-SHA256
- Brute-force resistance	2²⁵⁶ operations (physically impossible)

## 📁 Project structuretext

- DNK-2/
- ├── dnk2.py               # Encrypter/Decryptor
- ├── SPECIFICATION.md      # Full algorithm specification (ENG)
- ├── RUS_SPECIFICATION.txt # Full algorithm specification (RUS)
- ├── README.md             # This file
- └── requirements.txt      # Dependencies

## 🧪 Example

Input: "Hi"
Password: "test"
Output:
text

```DNK-2
TЎЃ4аJЦlЌЈ~dgўCTGCGAGCGATAATTCCTTATCCGATGTGTAGCTTCGCGAAGCCAATGTAGAGCAGTGTGGTGCAAAAAGGGTAACCGAGAGTTACATTTT...
```

## 👨‍💻 Author
- Alexey Kazakevich
Country: Russia

📜 License

GNU GPL v3 — use it, learn from it, improve it.
⭐ Support

If you like this project, give it a star on GitHub!
Pull requests, issues, and ideas are always welcome.
