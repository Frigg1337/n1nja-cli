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
from typing import Optional, List, Tuple
from collections import defaultdict

from dotenv import load_dotenv
from PIL import Image, ExifTags
import json
import time

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger("n1nja")

# ---------------- Load konfigurasi ----------------
load_dotenv()
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")
USE_DCODE = os.getenv("USE_DCODE", "true").lower() == "true"
PASTE_PROVIDER = os.getenv("PASTE_PROVIDER", "spaste")
PASTE_EXPIRY = os.getenv("PASTE_EXPIRY", "1d")
MAX_HISTORY_STORE = int(os.getenv("MAX_HISTORY_STORE", "1000") or 1000)
DB_FILE = os.getenv("DB_FILE", "/tmp/n1nja.db")
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
def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    res = []
    current = bytearray()
    for b in data:
        if 32 <= b < 127:
            current.append(b)
        else:
            if len(current) >= min_len:
                res.append(current.decode("utf-8", errors="ignore"))
            current = bytearray()
    if len(current) >= min_len:
        res.append(current.decode("utf-8", errors="ignore"))
    return res

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

# ---------------- LSB stego ----------------
def lsb_extract(img: Image.Image, bits=1, max_bytes=8192) -> bytes:
    img = img.convert("RGB")
    pixels = list(img.getdata())
    bits_stream = []
    for px in pixels:
        for c in px:
            bits_stream.append(c & ((1 << bits) - 1))
    bits_flat = []
    for val in bits_stream:
        for b in range(bits - 1, -1, -1):
            bits_flat.append((val >> b) & 1)
    out = bytearray()
    for i in range(0, min(len(bits_flat), max_bytes * 8), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits_flat[i + j]
        out.append(byte)
    return bytes(out).rstrip(b"\x00")

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
    try:
        from hashid import HashID
        hid = HashID()
        guesses = list(hid.identifyHash(hashtext))
        if not guesses:
            return None
        lines = ["Local hash identifier:"]
        for i, g in enumerate(guesses[:12]):
            name = getattr(g, "name", None) or getattr(g, "title", None) or str(g)
            lines.append(f"{i+1}. {name}")
        return "\n".join(lines)
    except Exception as e:
        # Silently fail if hashid library is not available
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

    print(out)
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

    print(out)
    save_history("cli_user", f"encode {d}", teks, out)

def cmd_hashid(args):
    """Function for hash identification"""
    try:
        out = lookup_hash_online(args.hashtext)
    except Exception as e:
        out = "Error lookup hash: %s" % str(e)

    print(out)
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
        out = "\n\n".join(lines[:30])
        print(out)
        save_history("cli_user", "solve", args.text, out[:4000])
    except Exception as e:
        print("Error during solve: " + str(e))

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
        for sc, k, outb in res:
            try:
                pr = outb.decode("utf-8", errors="ignore")
            except Exception:
                pr = outb.hex()
            lines.append("k=0x%02x score=%d\n%s" % (k, sc, pr[:800]))
        outt = "\n\n".join(lines)
        print(outt)
        save_history("cli_user", "xorbrute", args.data, outt[:4000])
    except Exception as e:
        print("XOR error: " + str(e))

def cmd_caesar(args):
    """Function for Caesar cipher"""
    try:
        out = caesar_shift(args.text, args.shift)
        print(out)
        save_history("cli_user", "caesar", str(args.shift) + "|" + args.text, out)
    except Exception as e:
        print("Caesar error: " + str(e))

def cmd_vigenere(args):
    """Function for Vigenere cipher"""
    try:
        if args.mode.lower() in ("enc", "encrypt"):
            out = vigenere(args.text, args.key, decrypt=False)
        else:
            out = vigenere(args.text, args.key, decrypt=True)
        print(out)
        save_history("cli_user", "vigenere", args.mode + "|" + args.key + "|" + args.text, out[:4000])
    except Exception as e:
        print("Vigenere error: " + str(e))

def cmd_atbash(args):
    """Function for Atbash cipher"""
    try:
        out = atbash(args.text)
        print(out)
        save_history("cli_user", "atbash", args.text, out)
    except Exception as e:
        print("Atbash error: " + str(e))

def cmd_rot13(args):
    """Function for ROT13"""
    try:
        out = codecs.decode(args.text, "rot_13")
        print(out)
        save_history("cli_user", "rot13", args.text, out)
    except Exception as e:
        print("ROT13 error: " + str(e))

def cmd_strings(args):
    """Function to extract strings from file"""
    if not os.path.exists(args.file):
        print("File not found.")
        return

    with open(args.file, 'rb') as f:
        data = f.read()

    hasil = extract_strings(data)
    if not hasil:
        print("No readable strings found.")
        return

    teks = "\n".join(hasil[:200])
    print(teks)
    save_history("cli_user", "strings", args.file, teks[:4000])

def cmd_stego(args):
    """Function for steganography analysis"""
    if not os.path.exists(args.file):
        print("File not found.")
        return

    with open(args.file, 'rb') as f:
        data = f.read()

    reply = []
    try:
        img = Image.open(io.BytesIO(data))
        exif = None
        try:
            exif = img._getexif()
        except Exception:
            exif = None
        if exif:
            reply.append("EXIF detected:")
            for k, v in exif.items():
                name = ExifTags.TAGS.get(k, k)
                reply.append("%s: %s" % (str(name), str(v)[:200]))
        else:
            reply.append("No EXIF.")

        # LSB extraction
        try:
            lsb_data = lsb_extract(img)
            if lsb_data:
                lsb_text = lsb_data.decode("utf-8", errors="ignore")
                if lsb_text:
                    reply.append("\nLSB extracted text (first 800 chars):")
                    reply.append(lsb_text[:800])
            else:
                reply.append("\nNo LSB data.")
        except Exception as e:
            reply.append("\nLSB extraction error: %s" % str(e))

        # Strings from image
        img_strings = extract_strings(data)
        if img_strings:
            reply.append("\nStrings (first 20):")
            reply.extend(img_strings[:20])
        else:
            reply.append("\nNo strings found.")

        # Hexdump
        hd = hexdump(data)
        reply.append("\nHexdump (first 50 lines):")
        reply.append(hd)

        out = "\n".join(reply)
        print(out)
        save_history("cli_user", "stego", args.file, out[:4000])

    except Exception as e:
        print("Stego error: %s" % str(e))

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
        print(info)
        save_history("cli_user", "fileinfo", args.file, info)
    except Exception as e:
        print(f"Fileinfo error: {str(e)}")

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

def show_help():
    """Display CLI help"""
    help_text = (
        "n1nja - Cybersecurity & CTF Helper CLI\n\n"
        "Available commands:\n"
        "  decode <type> <text>    : Decode from various formats (base64, hex, base32, rot13, atbash)\n"
        "  encode <type> <text>    : Encode to various formats (base64, hex, url)\n"
        "  hashid <hashtext>       : Hash identification\n"
        "  solve <text>            : Recursive auto-decode and flag detection\n"
        "  xorbrute <data>         : Bruteforce single-byte XOR\n"
        "  caesar <shift> <text>   : Caesar cipher\n"
        "  vigenere <enc|dec> <key> <text> : Vigenere cipher\n"
        "  atbash <text>           : Atbash cipher\n"
        "  rot13 <text>            : ROT13\n"
        "  strings <file>          : Extract strings from file\n"
        "  stego <file>            : Steganography analysis (EXIF, LSB, strings, hexdump)\n"
        "  fileinfo <file>         : File information (hash, size)\n"
        "  hexdump <data>          : Display hexdump from hex/base64/string data\n\n"
        "Usage examples:\n"
        "  python n1nja_cli.py decode base64 SGVsbG8=\n"
        "  python n1nja_cli.py hashid 5d41402abc4b2a76b9719d911017c592\n"
        "  python n1nja_cli.py solve SGVsbG8gV29ybGQ=\n"
    )
    print(help_text)

def main():
    # Print ASCII art when the program starts
    print(r"""
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

    parser = argparse.ArgumentParser(description='n1nja - Cybersecurity & CTF Helper CLI')
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

    # Strings command
    strings_parser = subparsers.add_parser('strings', help='Extract strings from file')
    strings_parser.add_argument('file', help='File name to extract strings from')

    # Stego command
    stego_parser = subparsers.add_parser('stego', help='Steganography analysis')
    stego_parser.add_argument('file', help='Image file name to analyze')

    # Fileinfo command
    fileinfo_parser = subparsers.add_parser('fileinfo', help='File information (hash, size)')
    fileinfo_parser.add_argument('file', help='File name to analyze')

    # Hexdump command
    hexdump_parser = subparsers.add_parser('hexdump', help='Display hexdump')
    hexdump_parser.add_argument('data', help='Data in hex, base64, or string format')

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
    elif args.command == 'strings':
        cmd_strings(args)
    elif args.command == 'stego':
        cmd_stego(args)
    elif args.command == 'fileinfo':
        cmd_fileinfo(args)
    elif args.command == 'hexdump':
        cmd_hexdump(args)
    elif args.command == 'help' or not args.command:
        show_help()
    else:
        show_help()

if __name__ == "__main__":
    main()