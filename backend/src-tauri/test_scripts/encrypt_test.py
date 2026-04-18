import os
import sys
import time
import random
import shutil
from pathlib import Path
import hashlib

TEST_DIR = os.path.join(os.path.expanduser("~"), "Documents", "rakshak_test")

def encrypt_file_high_entropy(data: bytes) -> bytes:
    key = os.urandom(len(data))
    encrypted = bytes(a ^ b for a, b in zip(data, key))
    return encrypted

def create_test_files():
    Path(TEST_DIR).mkdir(parents=True, exist_ok=True)
    
    sample_content = b"This is important document content. " * 100
    
    for i in range(30):
        file_path = Path(TEST_DIR) / f"document_{i:03d}.txt"
        file_path.write_bytes(sample_content)
    
    print(f"[+] Created 30 test files in {TEST_DIR}")

def encrypt_files():
    print(f"\n[>] Starting ENCRYPTION attack with HIGH ENTROPY...")
    
    for file_path in sorted(Path(TEST_DIR).glob("document_*.txt")):
        original_data = file_path.read_bytes()
        time.sleep(0.05)
        encrypted_data = encrypt_file_high_entropy(original_data)
        time.sleep(0.05)
        
        new_name = file_path.stem + ".locked"
        new_path = file_path.parent / new_name
        
        file_path.write_bytes(encrypted_data)
        time.sleep(0.2)
        os.replace(str(file_path), str(new_path))
        
        print(f"    [ENCRYPTED] {file_path.name} -> {new_path.name}")
        time.sleep(0.3)

    print(f"\n[+] All files encrypted with HIGH ENTROPY (~9.0) and renamed to .locked")

def main():
    print("="*60)
    print("RAKSHAK ATTACK SIMULATOR - REAL ENCRYPTION")
    print("="*60)
    print(f"[!] WARNING: This will ENCRYPT files in {TEST_DIR}")
    print(f"[!] Files will be renamed to .locked extension\n")
    
    response = "yes"
    if response.lower() != "yes":
        print("[-] Aborted")
        return
    
    create_test_files()
    time.sleep(1)
    encrypt_files()
    
    print(f"\n[>] Attack complete")
    print(f"[*] Check Rakshak dashboard for detection alerts")
    print(f"[*] To decrypt, run: python decrypt.py")

if __name__ == "__main__":
    main()