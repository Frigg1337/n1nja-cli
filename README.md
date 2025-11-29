# n1nja CLI - Cybersecurity & CTF Helper

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

n1nja CLI is a command-line tool designed to assist in cybersecurity and CTF (Capture The Flag) fields. This tool provides various functions for decoding, encoding, hash analysis, and steganography. This is a standalone command-line tool only, without web or Discord bot functionality.

## Installation

1. Make sure you have Python 3.7+ installed on your system
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Add the `D:\n1nja CLI\` folder to your system PATH so that the `n1nja` command can be used globally
4. **Security Warning**: Create your own `.env` file from the example `.env.example` - do not commit your actual `.env` file as it contains sensitive information like API keys

## Security Notice

⚠️ **IMPORTANT**: This tool handles sensitive information. Please ensure:
- Do not commit your `.env` file containing actual API keys
- Keep your API keys secure and private
- Review the code before running it in your environment
- Only provide necessary permissions to API keys

## Usage

After installation is complete and the folder is added to the system PATH, you can use the command:

```
n1nja [command] [options]
```

## Available Commands

### decode
Decode from various encoding formats:
```bash
n1nja decode base64 SGVsbG8=
n1nja decode hex 48656c6c6f
n1nja decode base32 JBSWY3DPFQQFO33SNRSCC
n1nja decode rot13 "Hello World"
n1nja decode atbash "Hello World"
```

### encode
Encode to various formats:
```bash
n1nja encode base64 Hello
n1nja encode hex "Hello World"
n1nja encode url "Hello World"
```

### hashid
Identify hash type:
```bash
n1nja hashid 5d41402abc4b2a76b9719d911017c592
```

### solve
Perform recursive auto-decode and flag detection:
```bash
n1nja solve "QmFzZTY0IGVuY29kZWQgdGV4dA=="
```

### xorbrute
Brute-force single-byte XOR:
```bash
n1nja xorbrute "48656c6c6f"
```

### caesar
Use Caesar cipher:
```bash
n1nja caesar 13 "Hello World"
```

### vigenere
Use Vigenère cipher:
```bash
n1nja vigenere enc mykey "Hello World"
```

### atbash & rot13
Use Atbash and ROT13 cipher:
```bash
n1nja atbash "Hello World"
n1nja rot13 "Hello World"
```

### strings
Extract readable strings from file:
```bash
n1nja strings myimage.jpg
```

### stego
Steganography analysis on image:
```bash
n1nja stego myimage.jpg
```

### fileinfo
File information (hash, size):
```bash
n1nja fileinfo myfile.txt
```

### hexdump
Display hexdump from data:
```bash
n1nja hexdump "Hello World"
```

## Main Features

1. **Multi-format decoding**: Base64, hex, base32, etc.
2. **Encoding**: Base64, hex, URL encoding
3. **Hash identification**: Supports MD5, SHA1, SHA256, etc.
4. **Auto-solve**: Try various decoding recursively
5. **Cipher tools**: Caesar, Vigenère, Atbash, XOR brute-force
6. **Steganography**: File analysis, strings, hexdump
7. **File analysis**: File information, hash, size

## Troubleshooting

- If using PowerShell and the `n1nja` command is not recognized, try `.\n1nja [command]` from the `D:\n1nja CLI\` folder
- Make sure all dependencies are installed: `pip install -r requirements.txt`
- Ensure the `D:\n1nja CLI\` folder has been added to the system PATH

## License

MIT License