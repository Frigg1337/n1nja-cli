#!/usr/bin/env python3
"""
n1nja CLI - Cybersecurity & CTF Helper Command Line Interface
"""

import os
import re
import io
import sys
import time
import json
import base64
import binascii
import hashlib
import codecs
import sqlite3
import argparse
import tempfile
import math
from typing import Optional, List, Tuple
from collections import defaultdict
# Removed external dependencies for standalone usage
# from dotenv import load_dotenv
# from PIL import Image, ExifTags

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger("n1nja")

# ---------------- Styling ----------------
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"

class Console:
    @staticmethod
    def print_banner(text):
        print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.RESET}")

    @staticmethod
    def success(msg):
        print(f"{Colors.GREEN}[+] {Colors.RESET}{msg}")

    @staticmethod
    def error(msg):
        print(f"{Colors.RED}[-] {Colors.RESET}{msg}")

    @staticmethod
    def info(msg):
        print(f"{Colors.BLUE}[*] {Colors.RESET}{msg}")

    @staticmethod
    def warning(msg):
        print(f"{Colors.YELLOW}[!] {Colors.RESET}{msg}")

    @staticmethod
    def panel(title, content, color=Colors.CYAN):
        """Draws a box/panel around content"""
        lines = content.strip().split('\n')
        width = max([len(line) for line in lines] + [len(title) + 4]) + 2
        
        # Top border
        print(f"{color}╭{'─' * (width)}╮{Colors.RESET}")
        print(f"{color}│{Colors.RESET} {Colors.BOLD}{title.center(width-2)}{Colors.RESET} {color}│{Colors.RESET}")
        print(f"{color}├{'─' * (width)}┤{Colors.RESET}")
        
        # Content
        for line in lines:
            print(f"{color}│{Colors.RESET} {line.ljust(width-2)} {color}│{Colors.RESET}")
            
        # Bottom border
        print(f"{color}╰{'─' * (width)}╯{Colors.RESET}")

    @staticmethod
    def table(headers, rows):
        """Draws a simple ASCII table"""
        if not rows:
            return
            
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Top border
        border = f"{Colors.DIM}+{Colors.RESET}"
        header_row = f"{Colors.DIM}|{Colors.RESET}"
        for w in col_widths:
            border += f"{Colors.DIM}{'-' * (w + 2)}+{Colors.RESET}"
        
        print(border)
        for i, h in enumerate(headers):
            header_row += f" {Colors.BOLD}{h.center(col_widths[i])}{Colors.RESET} {Colors.DIM}|{Colors.RESET}"
        print(header_row)
        print(border)
        
        for row in rows:
            line = f"{Colors.DIM}|{Colors.RESET}"
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    line += f" {str(cell).ljust(col_widths[i])} {Colors.DIM}|{Colors.RESET}"
            print(line)
        print(border)


# ---------------- Load konfigurasi ----------------
# load_dotenv() # Removed
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")
USE_DCODE = os.getenv("USE_DCODE", "true").lower() == "true"
PASTE_PROVIDER = os.getenv("PASTE_PROVIDER", "spaste")
PASTE_EXPIRY = os.getenv("PASTE_EXPIRY", "1d")
MAX_HISTORY_STORE = int(os.getenv("MAX_HISTORY_STORE", "1000") or 1000)
DB_FILE = os.getenv("DB_FILE", os.path.join(tempfile.gettempdir(), "n1nja.db"))
DCODE_API = os.getenv("DCODE_API", "https://www.dcode.fr/api/")

# ---------------- DB (SQLite safe) ----------------
def get_sqlite_connection():
    db_file = DB_FILE
    conn_local = None
    try:
        d = os.path.dirname(db_file)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(db_file, "a"):
            pass
        conn_local = sqlite3.connect(db_file, check_same_thread=False)
        print("DB running at %s" % db_file)
    except Exception as e:
        print("SQLite file failed (%s), fallback to in-memory" % str(e))
        conn_local = sqlite3.connect(":memory:", check_same_thread=False)
        print("DB in-memory active")
    return conn_local

conn = get_sqlite_connection()
cur = conn.cursor()

def db_init():
    try:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            command TEXT,
            input TEXT,
            output TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT)
        """)
        conn.commit()
    except Exception as e:
        print("DB init error: %s" % str(e))

db_init()

# ---------------- Constants/regex ----------------
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
BASE64_RE = re.compile(r'^[A-Za-z0-9+/=\n\r]+$')
BASE32_RE = re.compile(r'^[A-Z2-7=\n\r]+$', re.IGNORECASE)
B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}
FLAG_PATTERNS = [r'CTF\{[^}]{3,}\}', r'flag\{[^}]{3,}\}', r'[A-Za-z0-9_{}-]{8,}']
COMMON_WORDS = [b'the', b'flag', b'ctf', b'and', b'http', b'admin']
HASH_GUESSES = {
    32: ['MD5', 'NTLM', 'LM'],
    40: ['SHA-1', 'RIPEMD-160'],
    56: ['SHA-224'],
    64: ['SHA-256', 'SHA3-256'],
    96: ['SHA-384', 'SHA3-384'],
    128: ['SHA-512', 'SHA3-512']
}
_provider_cache = {}
_last_cmd_ts = defaultdict(lambda: 0.0)

# ---------------- Utilities ----------------
def save_history(user_id, command, inp, out):
    try:
        cur.execute("INSERT INTO history(user_id,command,input,output) VALUES(?,?,?,?)",
                    (str(user_id), command, (inp or "")[:4000], (out or "")[:4000]))
        cur.execute("SELECT COUNT(*) FROM history")
        total = cur.fetchone()[0]
        if total > MAX_HISTORY_STORE:
            cur.execute("DELETE FROM history WHERE id IN (SELECT id FROM history ORDER BY id ASC LIMIT ?)",
                        (total - MAX_HISTORY_STORE,))
        conn.commit()
    except Exception:
        pass

def find_flags(text: str) -> List[str]:
    found = []
    for p in FLAG_PATTERNS:
        for m in re.findall(p, text, flags=re.IGNORECASE):
            if m not in found:
                found.append(m)
    return found

# ---------------- Binary helpers ----------------
# String extraction removed (Forensics context)

def hexdump(data: bytes, length=16) -> str:
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_bytes = " ".join(["%02x" % b for b in chunk])
        ascii_bytes = "".join([chr(b) if 32 <= b < 127 else "." for b in chunk])
        lines.append("%08x  %s  %s" % (i, hex_bytes.ljust(length * 3), ascii_bytes))
    return "\n".join(lines[:400])

# ---------------- Encoding / decoding ----------------
def is_hex(s: str) -> bool:
    s2 = s.strip().replace(" ", "")
    return bool(HEX_RE.match(s2)) and len(s2) % 2 == 0

def is_base64(s: str) -> bool:
    s2 = s.strip()
    if len(s2) % 4 != 0:
        return False
    return bool(BASE64_RE.match(s2))

def try_base64(s: str) -> Optional[bytes]:
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        try:
            return base64.b64decode(s + "==")
        except Exception:
            return None

def try_hex(s: str) -> Optional[bytes]:
    try:
        s2 = re.sub(r"[^0-9a-fA-F]", "", s)
        return bytes.fromhex(s2)
    except Exception:
        return None

def try_base32(s: str) -> Optional[bytes]:
    try:
        return base64.b32decode(s)
    except Exception:
        return None

def b58_decode(s: str) -> bytes:
    num = 0
    for ch in s:
        if ch not in B58_MAP:
            raise ValueError("Invalid base58 char")
        num = num * 58 + B58_MAP[ch]
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") or b"\x00"
    n_pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_pad + full

# ---------------- Crypto helpers ----------------
def score_plaintext(b: bytes) -> int:
    s = 0
    low = b.lower()
    for w in COMMON_WORDS:
        if w.lower() in low:
            s += 10
    printable = sum(1 for c in b if 32 <= c < 127)
    s += int((printable / max(1, len(b))) * 20)
    return s

def single_xor_bruteforce(data: bytes, top=6):
    res = []
    for k in range(256):
        out = bytes([c ^ k for c in data])
        sc = score_plaintext(out)
        res.append((sc, k, out))
    res.sort(reverse=True, key=lambda x: x[0])
    return res[:top]

def caesar_shift(text: str, shift: int) -> str:
    out = ""
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out += chr((ord(ch) - base + shift) % 26 + base)
        else:
            out += ch
    return out

def atbash(text: str) -> str:
    out = ""
    for ch in text:
        if ch.isupper():
            out += chr(90 - (ord(ch) - 65))
        elif ch.islower():
            out += chr(122 - (ord(ch) - 97))
        else:
            out += ch
    return out

def vigenere(text: str, key: str, decrypt=False) -> str:
    out = ""
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            kch = key[ki % len(key)]
            shift = ord(kch.upper()) - ord("A")
            if decrypt:
                shift = -shift
            out += chr((ord(ch) - base + shift) % 26 + base)
            ki += 1
        else:
            out += ch
    return out

# ---------------- Advanced Crypto ----------------
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', '0': '-----', ',': '--..--', '.': '.-.-.-', '?': '..--..',
    '/': '-..-.', '-': '-....-', '(': '-.--.', ')': '-.--.-', ' ': '/'
}

def morse_encode(text: str) -> str:
    return ' '.join(MORSE_CODE_DICT.get(char.upper(), char) for char in text)

def morse_decode(text: str) -> str:
    # Reverse dictionary
    REVERSE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}
    return ''.join(REVERSE_DICT.get(code, code) for code in text.split(' '))

def frequency_analysis(text: str) -> str:
    # Filter only letters
    letters = [c.upper() for c in text if c.isalpha()]
    total = len(letters)
    if total == 0:
        return "No letters found."
    
    counts = defaultdict(int)
    for c in letters:
        counts[c] += 1
    
    # English frequency reference
    # E T A O I N S H R D L C U M W F G Y P B V K J X Q Z
    
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    
    lines = [f"Total letters: {total}"]
    for char, count in sorted_counts:
        percent = (count / total) * 100
        lines.append(f"{char}: {count} ({percent:.2f}%)")
        
    return "\n".join(lines)

def rail_fence_cipher(text: str, key: int, mode='enc') -> str:
    if key <= 1: return text
    
    # Create the matrix to probe for positions
    rail = [['\n' for i in range(len(text))] for j in range(key)]
    dir_down = False
    row, col = 0, 0
    
    for i in range(len(text)):
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
        
        if mode == 'enc':
            rail[row][col] = text[i]
        else:
            rail[row][col] = '*'
            
        col += 1
        if dir_down: row += 1
        else: row -= 1
        
    if mode == 'dec':
        index = 0
        for i in range(key):
            for j in range(len(text)):
                if ((rail[i][j] == '*') and (index < len(text))):
                    rail[i][j] = text[index]
                    index += 1
                    
    result = []
    row, col = 0, 0
    dir_down = False
    for i in range(len(text)):
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
            
        if mode == 'enc':
            if rail[row][col] != '\n':
                result.append(rail[row][col])
        else:
            if rail[row][col] != '\n':
                result.append(rail[row][col])
                
        col += 1
        if dir_down: row += 1
        else: row -= 1
        
    return("".join(result))

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def rsa_calc(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return n, phi, d

def affine_cipher(text, a, b, mode='enc'):
    if math.gcd(a, 26) != 1:
        return "Error: 'a' must be coprime to 26."
    
    result = ""
    m = 26
    
    if mode == 'dec':
        a_inv = modinv(a, m)
        
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            x = ord(char) - base
            
            if mode == 'enc':
                new_x = (a * x + b) % m
            else:
                new_x = (a_inv * (x - b)) % m
                
            result += chr(new_x + base)
        else:
            result += char
    return result

def xor_repeating_key(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        k = key[i % len(key)]
        out.append(b ^ k)
    return bytes(out)

BACON_DICT = {
    'A': 'aaaaa', 'B': 'aaaab', 'C': 'aaaba', 'D': 'aaabb', 'E': 'aabaa',
    'F': 'aabab', 'G': 'aabba', 'H': 'aabbb', 'I': 'abaaa', 'J': 'abaab',
    'K': 'ababa', 'L': 'ababb', 'M': 'abbaa', 'N': 'abbab', 'O': 'abbba',
    'P': 'abbbb', 'Q': 'baaaa', 'R': 'baaad', 'S': 'baaba', 'T': 'baabb',
    'U': 'babaa', 'V': 'babab', 'W': 'babba', 'X': 'babbb', 'Y': 'bbaaa',
    'Z': 'bbaab'
}
BACON_REV = {v: k for k, v in BACON_DICT.items()}

def bacon_cipher(text, mode='enc'):
    if mode == 'enc':
        out = []
        for c in text:
            if c.upper() in BACON_DICT:
                out.append(BACON_DICT[c.upper()])
            else:
                out.append(c)
        return " ".join(out)
    else:
        # Simple parsing: remove non-ab characters or try to split
        # This is a basic implementation assuming standard format
        clean = text.lower().replace(" ", "")
        out = ""
        for i in range(0, len(clean), 5):
            chunk = clean[i:i+5]
            out += BACON_REV.get(chunk, "?")
        return out

def nums_to_ascii(text, base=10):
    parts = text.replace(',', ' ').split()
    out = ""
    for p in parts:
        try:
            val = int(p, base)
            out += chr(val)
        except:
            out += "?"
    return out

# ---------------- LSB stego ----------------
# LSB stego (Disabled in standalone mode)
# def lsb_extract(img, bits=1, max_bytes=8192) -> bytes:
#     pass

# ---------------- Auto decode recursive ----------------
def auto_decode_recursive(data: bytes, max_depth=3) -> List[Tuple[str, bytes]]:
    results = []
    seen = set()
    def rec(d: bytes, depth: int, label: str):
        if depth > max_depth:
            return
        key = (label, d)
        if key in seen:
            return
        seen.add(key)
        results.append((label, d))
        try:
            b64 = base64.b64decode(d, validate=True)
            rec(b64, depth + 1, label + "->base64")
        except Exception:
            pass
        try:
            hx = binascii.unhexlify(d)
            rec(hx, depth + 1, label + "->hex")
        except Exception:
            pass
        try:
            b32 = base64.b32decode(d)
            rec(b32, depth + 1, label + "->base32")
        except Exception:
            pass
        try:
            s = d.decode(errors="ignore")
            b58 = b58_decode(s)
            rec(b58, depth + 1, label + "->base58")
        except Exception:
            pass
    rec(data, 0, "raw")
    return results

# ---------------- Hash Identifier helpers ----------------
def lookup_hash_local(hashtext: str) -> Optional[str]:
    """Use local hash identification as the only option."""
    # Removed hashid library dependency for standalone usage
    pass

    # Heuristic fallback
    s = re.sub(r'[^0-9a-fA-F]', '', hashtext)
    L = len(s)
    heur = []
    if ":" in hashtext:
        heur.append("Hash contains ':' - likely fingerprint/salted format (check manually).")
    if L == 32:
        heur.append("Length 32 hex -> likely MD5/NTLM.")
    elif L == 40:
        heur.append("Length 40 hex -> likely SHA1/RipeMD-160.")
    elif L == 64:
        heur.append("Length 64 hex -> likely SHA256.")
    elif L == 128:
        heur.append("Length 128 hex -> likely SHA512.")
    elif L > 0:
        heur.append(f"Length (hex-only) = {L}; uncommon or not pure hex.")

    if heur:
        return "Local guess (heuristics):\n" + "\n".join(heur)
    return None

def lookup_hash_online(hashtext: str, use_cache: bool = True, cache_ttl: int = 3600) -> str:
    """Local hash identification only (no online services)."""
    ht = hashtext.strip()
    if not ht:
        return "Hash empty."

    # cache check
    if use_cache and ht in _provider_cache:
        ts, val = _provider_cache[ht]
        if time.time() - ts < cache_ttl:
            return val

    # Only local lookup
    local_result = lookup_hash_local(ht)
    if local_result:
        out = local_result
    else:
        out = "Unable to identify hash. No local identifier available."

    _provider_cache[ht] = (time.time(), out)
    return out

# ---------------- CLI Functions ----------------
def cmd_decode(args):
    """Function to decode various encoding formats"""
    d = args.type.lower()
    teks = args.text

    if d == "base64":
        b = try_base64(teks)
        if b:
            try:
                out = b.decode("utf-8", errors="ignore")
            except Exception:
                out = b.hex()
        else:
            out = "Failed to decode base64."
    elif d == "hex":
        b = try_hex(teks)
        if b:
            try:
                out = b.decode("utf-8", errors="ignore")
            except Exception:
                out = b.hex()
        else:
            out = "Failed to decode hex."
    elif d == "base32":
        b = try_base32(teks)
        if b:
            try:
                out = b.decode("utf-8", errors="ignore")
            except Exception:
                out = b.hex()
        else:
            out = "Failed to decode base32."
    elif d == "rot13":
        out = codecs.decode(teks, "rot_13")
    elif d == "atbash":
        out = atbash(teks)
    else:
        out = "Unknown decode type."

    if str(out).startswith("Failed") or str(out).startswith("Unknown"):
        Console.error(out)
    else:
        Console.success(out)
    save_history("cli_user", f"decode {d}", teks, out[:4000])

def cmd_encode(args):
    """Function to encode to various formats"""
    d = args.type.lower()
    teks = args.text

    if d == "base64":
        out = base64.b64encode(teks.encode()).decode()
    elif d == "hex":
        out = teks.encode().hex()
    elif d == "url":
        from urllib.parse import quote
        out = quote(teks)
    else:
        out = "Unknown encode type."

    if str(out).startswith("Unknown"):
        Console.error(out)
    else:
        Console.success(out)
    save_history("cli_user", f"encode {d}", teks, out)

def cmd_hashid(args):
    """Function for hash identification"""
    try:
        out = lookup_hash_online(args.hashtext)
    except Exception as e:
        out = "Error lookup hash: %s" % str(e)

    if str(out).startswith("Error"):
        Console.error(out)
    else:
        Console.panel("Hash Identification", out)
    save_history("cli_user", "hashid", args.hashtext, out[:4000])

def cmd_solve(args):
    """Function for recursive auto-decode"""
    try:
        b = args.text.encode()
        decs = auto_decode_recursive(b, max_depth=3)
        lines = []
        for label, data in decs:
            try:
                preview = data.decode("utf-8", errors="ignore")
            except Exception:
                preview = data.hex()
            flags = find_flags(preview)
            lines.append("[" + label + "]\n" + preview[:800])
            if flags:
                lines.append("  >> flag detected: " + ", ".join(flags))
        if not lines:
            Console.warning("No decodes found or depth limit reached.")
        else:
            for line in lines[:30]:
                # line format is: [label]\ncontent...
                parts = line.split('\n', 1)
                if len(parts) == 2:
                    header = parts[0]
                    body = parts[1]
                    Console.panel(header.strip('[]'), body)
                else:
                    print(line)
                    
        out = "\n\n".join(lines[:30])
        # print(out) # Suppressed effectively by loop above, but we keep 'out' for history
        save_history("cli_user", "solve", args.text, out[:4000])
    except Exception as e:
        Console.error("Error during solve: " + str(e))

def cmd_xorbrute(args):
    """Function for brute-force single-byte XOR"""
    try:
        parsed = None
        if is_hex(args.data):
            parsed = try_hex(args.data)
        else:
            parsed = try_base64(args.data) or args.data.encode()
        res = single_xor_bruteforce(parsed, top=12)
        lines = []
        rows = []
        for sc, k, outb in res:
            try:
                pr = outb.decode("utf-8", errors="ignore")
            except Exception:
                pr = outb.hex()
            # Clean up preview for table
            clean_pr = (pr[:60] + '..') if len(pr) > 60 else pr
            clean_pr = clean_pr.replace('\n', ' ').replace('\r', '')
            rows.append([f"0x{k:02x}", str(sc), clean_pr])
            
            lines.append("k=0x%02x score=%d\n%s" % (k, sc, pr[:800])) # Keep original for history/raw
            
        Console.table(["Key", "Score", "Preview"], rows)
        outt = "\n\n".join(lines)
        save_history("cli_user", "xorbrute", args.data, outt[:4000])
    except Exception as e:
        Console.error("XOR error: " + str(e))

def cmd_caesar(args):
    """Function for Caesar cipher"""
    try:
        out = caesar_shift(args.text, args.shift)
        Console.success(out)
        save_history("cli_user", "caesar", str(args.shift) + "|" + args.text, out)
    except Exception as e:
        Console.error("Caesar error: " + str(e))

def cmd_vigenere(args):
    """Function for Vigenere cipher"""
    try:
        if args.mode.lower() in ("enc", "encrypt"):
            out = vigenere(args.text, args.key, decrypt=False)
        else:
            out = vigenere(args.text, args.key, decrypt=True)
        Console.success(out)
        save_history("cli_user", "vigenere", args.mode + "|" + args.key + "|" + args.text, out[:4000])
    except Exception as e:
        Console.error("Vigenere error: " + str(e))

def cmd_atbash(args):
    """Function for Atbash cipher"""
    try:
        out = atbash(args.text)
        Console.success(out)
        save_history("cli_user", "atbash", args.text, out)
    except Exception as e:
        Console.error("Atbash error: " + str(e))

def cmd_rot13(args):
    """Function for ROT13"""
    try:
        out = codecs.decode(args.text, "rot_13")
        Console.success(out)
        save_history("cli_user", "rot13", args.text, out)
    except Exception as e:
        Console.error("ROT13 error: " + str(e))

# cmd_strings and cmd_stego removed to focus on Cryptography

def cmd_fileinfo(args):
    """Function for file information"""
    if not os.path.exists(args.file):
        print("File not found.")
        return

    try:
        with open(args.file, 'rb') as f:
            data = f.read()

        file_size = len(data)
        md5_hash = hashlib.md5(data).hexdigest()
        sha1_hash = hashlib.sha1(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        info = f"File name: {args.file}\nSize: {file_size} bytes\nMD5: {md5_hash}\nSHA1: {sha1_hash}\nSHA256: {sha256_hash}"
        Console.panel("File Information", info)
        save_history("cli_user", "fileinfo", args.file, info)
    except Exception as e:
        Console.error(f"Fileinfo error: {str(e)}")

def cmd_hexdump(args):
    """Function for hexdump"""
    try:
        # Try to parse as hex if input is hex string
        if is_hex(args.data):
            data = try_hex(args.data)
        else:
            # Try to parse as base64
            b64_data = try_base64(args.data)
            if b64_data:
                data = b64_data
            else:
                # If not hex or base64, treat as regular string
                data = args.data.encode()

        hd = hexdump(data)
        print(hd)
        save_history("cli_user", "hexdump", args.data, hd[:4000])
    except Exception as e:
        print(f"Hexdump error: {str(e)}")

def cmd_morse(args):
    """Function for Morse code"""
    try:
        if args.mode == 'enc':
            out = morse_encode(args.text)
        else:
            out = morse_decode(args.text)
        Console.success(out)
        save_history("cli_user", "morse", args.mode + "|" + args.text, out)
    except Exception as e:
        Console.error(f"Morse error: {str(e)}")

def cmd_freq(args):
    """Function for Frequency Analysis"""
    try:
        out = frequency_analysis(args.text)
        # Parse the output string back into rows for table display
        lines = out.split('\n')
        total_line = lines[0]
        rows = []
        for line in lines[1:]:
            parts = line.split(': ')
            if len(parts) == 2:
                char = parts[0]
                rest = parts[1]
                # rest is like "2 (20.00%)"
                count_str = rest.split(' ')[0]
                percent_str = rest.split('(')[1].rstrip(')')
                rows.append([char, count_str, percent_str])
        
        print(f"{Colors.BOLD}{Colors.CYAN}{total_line}{Colors.RESET}")
        Console.table(["Char", "Count", "Percent"], rows)
        save_history("cli_user", "freq", args.text, out[:4000])
    except Exception as e:
        Console.error(f"Freq error: {str(e)}")

def cmd_railfence(args):
    """Function for Rail Fence Cipher"""
    try:
        mode = 'enc' if args.mode in ('enc', 'encrypt') else 'dec'
        out = rail_fence_cipher(args.text, args.rails, mode)
        Console.success(out)
        save_history("cli_user", "railfence", f"{mode}|{args.rails}|{args.text}", out)
    except Exception as e:
        Console.error(f"Railfence error: {str(e)}")

def cmd_rsa(args):
    """Function for RSA calc"""
    try:
        n, phi, d = rsa_calc(args.p, args.q, args.e)
        content = (
            f"p   = {args.p}\n"
            f"q   = {args.q}\n"
            f"e   = {args.e}\n"
            f"n   = {n}\n"
            f"phi = {phi}\n"
            f"d   = {d} (Private Key)"
        )
        Console.panel("RSA Calculation Result", content)
        save_history("cli_user", "rsa", f"{args.p}|{args.q}|{args.e}", f"d={d}")
    except Exception as e:
        Console.error(f"RSA error: {str(e)}")

def cmd_math(args):
    """Function for math helpers"""
    try:
        if args.op == 'gcd':
            res = math.gcd(args.a, args.b)
            Console.success(f"GCD({args.a}, {args.b}) = {res}")
        elif args.op == 'modinv':
            res = modinv(args.a, args.b)
            Console.success(f"ModInv({args.a}, {args.b}) = {res}")
    except Exception as e:
        Console.error(f"Math error: {str(e)}")

def cmd_affine(args):
    """Function for Affine cipher"""
    try:
        mode = 'enc' if args.mode in ('enc', 'encrypt') else 'dec'
        out = affine_cipher(args.text, args.a, args.b, mode)
        Console.success(out)
        save_history("cli_user", "affine", f"{mode}|{args.a}|{args.b}|{args.text}", out)
    except Exception as e:
        Console.error(f"Affine error: {str(e)}")

def cmd_xorkey(args):
    """Function for Repeating Key XOR"""
    try:
        # Input data handling (hex/base64 auto detection)
        if is_hex(args.data):
            data_bytes = try_hex(args.data)
        elif is_base64(args.data):
             data_bytes = try_base64(args.data)
        else:
            data_bytes = args.data.encode()
            
        key_bytes = args.key.encode()
        res = xor_repeating_key(data_bytes, key_bytes)
        
        # Display results in hex and string
        Console.info("Hex Output:")
        print(res.hex())
        Console.info("String Preview:")
        print(res.decode('utf-8', errors='ignore'))
        
        save_history("cli_user", "xorkey", args.key, res.hex())
    except Exception as e:
        Console.error(f"XORKey error: {str(e)}")

def cmd_bacon(args):
    """Function for Bacon cipher"""
    try:
        mode = 'enc' if args.mode in ('enc', 'encrypt') else 'dec'
        out = bacon_cipher(args.text, mode)
        Console.success(out)
        save_history("cli_user", "bacon", f"{mode}|{args.text}", out)
    except Exception as e:
        Console.error(f"Bacon error: {str(e)}")

def cmd_num(args):
    """Function for Number conversion"""
    try:
        if args.type == 'bin':
            out = nums_to_ascii(args.text, 2)
        elif args.type == 'dec':
            out = nums_to_ascii(args.text, 10)
        elif args.type == 'hex':
            out = nums_to_ascii(args.text, 16)
        Console.success(out)
        save_history("cli_user", "num", f"{args.type}|{args.text}", out)
    except Exception as e:
        Console.error(f"Num error: {str(e)}")

def show_help():
    """Display CLI help"""
    # Custom colored help
    print(f"{Colors.BOLD}{Colors.MAGENTA}Available Commands:{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*19}{Colors.RESET}\n")

    sections = [
        (
            f"{Colors.YELLOW}[!] Encodings & Conversions{Colors.RESET}",
            [
                ("decode", "Decode (base64, hex, base32, rot13, atbash)"),
                ("encode", "Encode (base64, hex, url)"),
                ("num   ", "Convert numbers to ASCII (bin, dec, hex)")
            ]
        ),
        (
            f"{Colors.YELLOW}[!] Classic Ciphers{Colors.RESET}",
            [
                ("caesar   ", "Caesar Cipher (shift)"),
                ("rot13    ", "ROT13 Cipher (caesar 13)"),
                ("atbash   ", "Atbash Cipher (mirror)"),
                ("affine   ", "Affine Cipher (ax + b)"),
                ("vigenere ", "Vigenere Cipher (polyalphabetic)"),
                ("railfence", "Rail Fence Cipher (zigzag)"),
                ("bacon    ", "Bacon Cipher (stego text)"),
                ("morse    ", "Morse Code")
            ]
        ),
        (
            f"{Colors.YELLOW}[!] Modern Crypto & Math{Colors.RESET}",
            [
                ("rsa      ", "RSA Calculator (p, q, e -> d)"),
                ("xorkey   ", "Repeating Key XOR"),
                ("xorbrute ", "Single Byte XOR Bruteforce"),
                ("math     ", "Math Helpers (gcd, modinv)")
            ]
        ),
        (
            f"{Colors.YELLOW}[!] Analysis & Identifiers{Colors.RESET}",
            [
                ("solve    ", "Auto-Solver (Recursive decode & flag detection)"),
                ("hashid   ", "Identify hash type"),
                ("freq     ", "Frequency Analysis"),
                ("fileinfo ", "File Hash & Size Info"),
                ("hexdump  ", "Hexdump View")
            ]
        )
    ]

    for title, cmds in sections:
        print(title)
        for cmd, desc in cmds:
            print(f"  {Colors.GREEN}{cmd:<10}{Colors.RESET} : {desc}")
        print("")

    print(f"{Colors.BOLD}Usage Examples:{Colors.RESET}")
    examples = [
        'n1nja solve "SGVsbG8..."',
        'n1nja rsa 61 53 17',
        'n1nja xorkey SECRET 120412...',
        'n1nja caesar 13 "URYYB"',
        'n1nja num dec "104 101 108 108 111"'
    ]
    for ex in examples:
        print(f"  {Colors.CYAN}{ex}{Colors.RESET}")
    print("")

def main():
    # Print ASCII art when the program starts
    Console.print_banner(r"""
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
    """)

    # Check for help flags manually before argparse
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        show_help()
        sys.exit(0)

    # Disable default help to avoid conflict
    parser = argparse.ArgumentParser(description='n1nja - Cybersecurity & CTF Helper CLI', add_help=False)
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Decode from various formats')
    decode_parser.add_argument('type', help='Encoding type (base64, hex, base32, rot13, atbash)')
    decode_parser.add_argument('text', help='Text to decode')

    # Encode command
    encode_parser = subparsers.add_parser('encode', help='Encode to various formats')
    encode_parser.add_argument('type', help='Encoding type (base64, hex, url)')
    encode_parser.add_argument('text', help='Text to encode')

    # Hashid command
    hashid_parser = subparsers.add_parser('hashid', help='Hash identification')
    hashid_parser.add_argument('hashtext', help='Hash text to identify')

    # Solve command
    solve_parser = subparsers.add_parser('solve', help='Recursive auto-decode and flag detection')
    solve_parser.add_argument('text', help='Text to analyze')

    # XOR Bruteforce command
    xorbrute_parser = subparsers.add_parser('xorbrute', help='Bruteforce single-byte XOR')
    xorbrute_parser.add_argument('data', help='Data in hex or base64 format')

    # Caesar command
    caesar_parser = subparsers.add_parser('caesar', help='Caesar cipher')
    caesar_parser.add_argument('shift', type=int, help='Shift amount')
    caesar_parser.add_argument('text', help='Text to process')

    # Vigenère command
    vigenere_parser = subparsers.add_parser('vigenere', help='Vigenere cipher')
    vigenere_parser.add_argument('mode', help='enc for encrypt, dec for decrypt')
    vigenere_parser.add_argument('key', help='Key for cipher')
    vigenere_parser.add_argument('text', help='Text to process')

    # Atbash command
    atbash_parser = subparsers.add_parser('atbash', help='Atbash cipher')
    atbash_parser.add_argument('text', help='Text to process')

    # ROT13 command
    rot13_parser = subparsers.add_parser('rot13', help='ROT13')
    rot13_parser.add_argument('text', help='Text to process')

    # Fileinfo command
    fileinfo_parser = subparsers.add_parser('fileinfo', help='File information (hash, size)')
    fileinfo_parser.add_argument('file', help='File name to analyze')

    # Hexdump command
    hexdump_parser = subparsers.add_parser('hexdump', help='Display hexdump')
    hexdump_parser.add_argument('data', help='Data in hex, base64, or string format')

    # Morse command
    morse_parser = subparsers.add_parser('morse', help='Morse code')
    morse_parser.add_argument('mode', choices=['enc', 'dec'], help='Encode or Decode')
    morse_parser.add_argument('text', help='Text to process')

    # Freq command
    freq_parser = subparsers.add_parser('freq', help='Frequency analysis')
    freq_parser.add_argument('text', help='Text to analyze')

    # Railfence command
    rail_parser = subparsers.add_parser('railfence', help='Rail fence cipher')
    rail_parser.add_argument('mode', choices=['enc', 'dec'], help='Encode or Decode')
    rail_parser.add_argument('rails', type=int, help='Number of rails')
    rail_parser.add_argument('text', help='Text to process')

    # RSA command
    rsa_parser = subparsers.add_parser('rsa', help='RSA Calculator')
    rsa_parser.add_argument('p', type=int, help='Prime p')
    rsa_parser.add_argument('q', type=int, help='Prime q')
    rsa_parser.add_argument('e', type=int, help='Public exponent e')

    # Math command
    math_parser = subparsers.add_parser('math', help='Math helpers')
    math_parser.add_argument('op', choices=['gcd', 'modinv'], help='Operation')
    math_parser.add_argument('a', type=int, help='Value A')
    math_parser.add_argument('b', type=int, help='Value B (or modulus)')

    # Affine command
    affine_parser = subparsers.add_parser('affine', help='Affine cipher')
    affine_parser.add_argument('mode', choices=['enc', 'dec'], help='Encode or Decode')
    affine_parser.add_argument('a', type=int, help='Slope a')
    affine_parser.add_argument('b', type=int, help='Intercept b')
    affine_parser.add_argument('text', help='Text to process')

    # XOR Key command
    xorky_parser = subparsers.add_parser('xorkey', help='Repeating Key XOR')
    xorky_parser.add_argument('key', help='Key string')
    xorky_parser.add_argument('data', help='Data (hex/base64/string)')

    # Bacon command
    bacon_parser = subparsers.add_parser('bacon', help='Bacon cipher')
    bacon_parser.add_argument('mode', choices=['enc', 'dec'], help='Encode or Decode')
    bacon_parser.add_argument('text', help='Text to process')

    # Num command
    num_parser = subparsers.add_parser('num', help='Number converter')
    num_parser.add_argument('type', choices=['bin', 'dec', 'hex'], help='Input type')
    num_parser.add_argument('text', help='Space separated numbers')

    # Help command
    subparsers.add_parser('help', help='Display help')

    args = parser.parse_args()

    if args.command == 'decode':
        cmd_decode(args)
    elif args.command == 'encode':
        cmd_encode(args)
    elif args.command == 'hashid':
        cmd_hashid(args)
    elif args.command == 'solve':
        cmd_solve(args)
    elif args.command == 'xorbrute':
        cmd_xorbrute(args)
    elif args.command == 'caesar':
        cmd_caesar(args)
    elif args.command == 'vigenere':
        cmd_vigenere(args)
    elif args.command == 'atbash':
        cmd_atbash(args)
    elif args.command == 'rot13':
        cmd_rot13(args)
    elif args.command == 'fileinfo':
        cmd_fileinfo(args)
    elif args.command == 'hexdump':
        cmd_hexdump(args)
    elif args.command == 'morse':
        cmd_morse(args)
    elif args.command == 'freq':
        cmd_freq(args)
    elif args.command == 'railfence':
        cmd_railfence(args)
    elif args.command == 'rsa':
        cmd_rsa(args)
    elif args.command == 'math':
        cmd_math(args)
    elif args.command == 'affine':
        cmd_affine(args)
    elif args.command == 'xorkey':
        cmd_xorkey(args)
    elif args.command == 'bacon':
        cmd_bacon(args)
    elif args.command == 'num':
        cmd_num(args)
    elif args.command == 'help' or not args.command:
        show_help()
    else:
        show_help()

if __name__ == "__main__":
    main()