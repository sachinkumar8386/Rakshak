import os
from pathlib import Path

TEST_DIR = os.path.join(os.path.expanduser("~"), "Documents", "rakshak_test")
KEY = b"RAKSHAK_TEST_KEY_2024"

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    return bytes(result)

def decrypt_files():
    print(f"[>] Decrypting files...")
    
    for file_path in Path(TEST_DIR).glob("*.locked"):
        encrypted_data = file_path.read_bytes()
        decrypted_data = xor_decrypt(encrypted_data, KEY)
        
        new_name = file_path.stem.replace(".locked", "") + ".txt"
        new_path = file_path.parent / new_name
        
        file_path.write_bytes(decrypted_data)
        os.replace(str(file_path), str(new_path))
        
        print(f"    [DECRYPTED] {file_path.name} -> {new_path.name}")
    
    print(f"\n[+] All files restored")

if __name__ == "__main__":
    decrypt_files()