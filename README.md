🔐 Secure File Encryption & Decryption Tool
  A modern, GUI-based AES-256-GCM file encryption & decryption application built using Python. Features password-based encryption, key-file support, SHA-256 integrity          validation, streaming for large files, and a premium gold-black themed Tkinter interface.

✨ Features
  AES-256-GCM Encryption & Decryption (authenticated & secure)
  PBKDF2 (200k rounds) for password-based key derivation
  Random 256-bit Key File support (.key)
  SHA-256 integrity verification (detects tampering & corruption)
  Streaming encryption for large files (no memory limit)
  Modern Royal UI (Gold/Black theme)
  Progress bar + Activity Log
  Rounded card UI, glowing background, blur effects
  Fully Offline Application

🛡️ How It Works

Encryption:
  User selects a file.
  Provides a password or loads a .key file.
  Tool generates:
  Random Salt (16 bytes)
  Random Nonce (12 bytes)
  SHA-256 of plaintext
  AES-256-GCM encrypts the file in 64KB streams.
  Header + ciphertext + authentication tag are saved into .enc.

Decryption:
  Reads header & validates signature (ENCRv2).
  Derives key using password or raw key.
  Decrypts in streams.
  Verifies AES-GCM tag + SHA-256 hash.
  Restores original file if everything matches.

📁 File Structure
  Component	Description
  MAGIC	Signature to validate encrypted files
  PBKDF2	Converts password → AES key
  SHA-256	Ensures file integrity
  AES-256-GCM	Encryption and authentication

🖥️ GUI Preview
  Gold + Black Royal Design
  Custom generated background
  Minimal rounded card with glow
  Clear log messages
  Clean button hover effects

🚀 Usage
  1. Install dependencies
  pip install pycryptodome pillow
  
  2. Run
  python app.py
  
  3. Encrypt
  Select file
  Enter password or load .key
  Click Encrypt
  
  4. Decrypt
  Select .enc file
  Provide same password or key
  Click Decrypt

🔑 Key Files
  You can generate a random 256-bit key using the Generate Key button.
  The key is saved as a .key file and can be reused for encryption/decryption.

⚠️ Security Notes
  Don’t lose your password or key—decryption is impossible without them.
  AES-GCM ensures protection from modification/tampering.
  Hash mismatch or tag failure means corrupted or wrong key.

📜 License
  MIT License – free for personal and commercial use.
