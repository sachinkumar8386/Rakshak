import os
import sys
import time
import random
from pathlib import Path
import threading

TEST_DIR = os.path.join(os.path.expanduser("~"), "Documents", "rakshak_test")

def generate_random_data(size: int) -> bytes:
    return os.urandom(size)

def encrypt_file(data: bytes) -> bytes:
    key = os.urandom(len(data))
    return bytes(a ^ b for a, b in zip(data, key))

def create_and_encrypt_files():
    Path(TEST_DIR).mkdir(parents=True, exist_ok=True)
    
    print("[+] Creating test files with random data...")
    
    files_to_create = []
    for i in range(50):
        file_path = Path(TEST_DIR) / f"document_{i:03d}.txt"
        random_data = generate_random_data(8192)  # 8KB random data = ~8 entropy
        files_to_create.append((file_path, random_data))
    
    print(f"[+] Starting RAPID encryption attack on {len(files_to_create)} files...")
    print("[!] This will trigger: HIGH ENTROPY (>6.5) + HIGH VELOCITY (>10 files) + EXTENSION CHANGE")
    
    start_time = time.time()
    
    for idx, (file_path, random_data) in enumerate(files_to_create):
        file_path.write_bytes(random_data)
        
        encrypted = encrypt_file(random_data)
        new_name = file_path.stem + ".locked"
        new_path = file_path.parent / new_name
        
        file_path.write_bytes(encrypted)
        
        if idx % 5 == 0:
            print(f"    [PROGRESS] {idx+1}/{len(files_to_create)} files encrypted...")
        
        if idx < len(files_to_create) - 1:
            time.sleep(0.05)
    
    elapsed = time.time() - start_time
    files_per_sec = len(files_to_create) / elapsed
    
    print(f"\n[+] ATTACK COMPLETE!")
    print(f"    Files encrypted: {len(files_to_create)}")
    print(f"    Time elapsed: {elapsed:.2f}s")
    print(f"    Velocity: {files_per_sec:.1f} files/second")
    print(f"    Extension changed to: .locked")
    print(f"    Average entropy: ~8.0 (random data)")
    print(f"\n[*] Expected detection: CRITICAL - KILL & ISOLATE")
    print(f"    - Entropy > 6.5 = KILL")
    print(f"    - Velocity {files_per_sec:.1f} > 10 = KILL")  
    print(f"    - Extension .locked = ALERT")

def main():
    print("="*70)
    print("RAKSHAK DETECTION TEST - AGGRESSIVE RANSOMWARE SIMULATION")
    print("="*70)
    print(f"[!] Target directory: {TEST_DIR}")
    print(f"[!] This will create and encrypt 50 files with HIGH ENTROPY")
    print(f"[!] EXTREMELY FAST - designed to trigger velocity detection\n")
    
    response = input("[?] Continue? (yes/no): ")
    if response.lower() != "yes":
        print("[-] Aborted")
        return
    
    create_and_encrypt_files()
    
    print(f"\n[>] Attack simulation complete")
    print(f"[*] Check Rakshak dashboard for CRITICAL alert")
    print(f"[*] Python process should be killed immediately")

if __name__ == "__main__":
    main()