# n1nja - Cybersecurity & CTF Helper

```
          _
       /' \            __
  ___ /\_, \    ___   /\_\     __
/' _ `\/_/\ \ /' _ `\ \/\ \  /'__`\
/\ \/\ \ \ \ \/\ \/\ \ \ \ \/\ \L\.\_
\ \_\ \_\ \ \_\ \_\ \_\_\ \ \ \__/.\_\
 \/_/\/_/  \/_/\/_/\/_/\ \_\ \/__/\/_/
                      \ \____/
                       \/___/
    n1nja - Cybersecurity & CTF Helper
```

**n1nja** is a **lightweight, standalone** command-line tool designed for **Capture The Flag (CTF)** competitions, focusing on **Cryptography**. 

It works **without any external dependencies** (Zero Dependency) and runs on any OS with Python 3.

---

## 🚀 Features

### 🔐 Encodings & Conversions
*   **Encoders/Decoders**: Base64, Hex, Base32, URL, ROT13, Atbash.
*   **Number Converter**: Instant Binary/Decimal/Hex to ASCII conversion.

### 📜 Classic Ciphers
*   **Caesar Cipher**: Brute-force shift or specific key.
*   **Vigenère Cipher**: Polyalphabetic substitution.
*   **Rail Fence Cipher**: Zig-zag transposition.
*   **Baconian Cipher**: Steganography text hiding.
*   **Morse Code**: Encoder/Decoder.
*   **Affine Cipher**: Linear substitution `(ax + b)`.

### 🧮 Modern Crypto & Math
*   **RSA Calculator**: Calculate Private Key `d` from `p, q, e`.
*   **Running Key XOR**: XOR encryption with long keys (strings/hex).
*   **XOR Brute-force**: Crack single-byte XOR.
*   **Math Tools**: GCD (Greatest Common Divisor), Modular Inverse.

### 🔍 Analysis
*   **Auto-Solver**: Recursively attempts to decode strings and find flags.
*   **Hash Identifier**: Identifies hash types (MD5, SHA1, etc.).
*   **Frequency Analysis**: Analyze character distribution for substitution ciphers.
*   **File Info**: Check MD5/SHA hashes of files.
*   **Hexdump**: View data in clean hex format.

---

## 📦 Installation

**No installation required!** Just download the script.

### Option 1: Run Directly
```bash
python3 n1nja_cli.py help
```

### Option 2: Create Alias (Recommended)
Add this to your shell config (`.bashrc` or `.zshrc`) to run it from anywhere:

```bash
alias n1nja="python3 /path/to/n1nja_cli.py"
```
Reload shell: `source ~/.bashrc`
Now you can simply type:
```bash
n1nja help
```

---

## 📖 Usage Examples

### 1. RSA Challenge
You are given `p=61`, `q=53`, `e=17`. Find the private key `d`.
```bash
n1nja rsa 61 53 17
# Output: d = 2753 (Private Key)
```

### 2. Repeating Key XOR
Decrypt a hex string using the key "SECRET".
```bash
n1nja xorkey SECRET 1A0B2C...
```

### 3. Analyze Unknown Text
Check if a text uses a substitution cipher.
```bash
n1nja freq "HFKJHZK..."
```

### 4. Decode Hidden Messages
```bash
n1nja morse dec "... --- ..."
n1nja railfence dec 3 "HRE..."
n1nja bacon dec "ABBAA BAABA..."
```

### 5. Magic Auto-Solver
Lazy to check manual decoding? Let n1nja try everything.
```bash
n1nja solve "VGhlIGZsYWcgaXM6IENURntnZXRfbHVja3l9"
```

---

## 🛡️ License
MIT License