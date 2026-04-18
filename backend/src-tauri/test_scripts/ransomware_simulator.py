"""
Rakshak Ransomware Attack Simulator
=================================
This script simulates various ransomware attack patterns to test
the Rakshak detection system WITHOUT causing real damage.

Safe Features:
- Creates TEST files only in designated test directories
- Automatically cleans up after testing
- Can run in DRY-RUN mode (no actual encryption)
- Logs all actions for analysis
"""

import os
import sys
import time
import random
import string
import hashlib
import tempfile
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import List, Optional

class AttackType(Enum):
    ENCRYPTION = "encryption"
    ENTROPY_SPIKE = "entropy_spike"
    VELOCITY = "velocity"
    EXTENSION_CHANGE = "extension_change"
    COMBINED = "combined"

@dataclass
class AttackConfig:
    attack_type: AttackType
    file_count: int = 20
    entropy_threshold: float = 7.5
    velocity_threshold: int = 10
    delay_ms: int = 50
    dry_run: bool = True
    test_directory: Optional[str] = None

class RakshakRansomwareSimulator:
    def __init__(self, config: AttackConfig):
        self.config = config
        self.test_dir = Path(config.test_directory or tempfile.mkdtemp(prefix="rakshak_test_"))
        self.created_files: List[Path] = []
        self.original_content: dict = {}
        
    def setup(self):
        """Create test files before attack"""
        print(f"[*] Setting up test environment...")
        print(f"[*] Test directory: {self.test_dir}")
        self.test_dir.mkdir(parents=True, exist_ok=True)
        
        sample_content = "This is important document content. " * 50
        
        for i in range(self.config.file_count):
            test_file = self.test_dir / f"document_{i:03d}.txt"
            test_file.write_text(sample_content)
            self.created_files.append(test_file)
            self.original_content[str(test_file)] = sample_content
            
        print(f"[+] Created {len(self.created_files)} test files")
        
    def generate_encrypted_content(self, original: bytes) -> bytes:
        """Simulate encryption by replacing with high-entropy random data"""
        return os.urandom(len(original))
    
    def encrypt_file(self, file_path: Path) -> bool:
        """Encrypt a single file (simulated or real)"""
        if self.config.dry_run:
            entropy = self.calculate_entropy(b"X" * 1000 + os.urandom(1000))
            print(f"    [SIMULATED] Would encrypt: {file_path.name} (entropy: {entropy:.2f})")
            return True
        else:
            original = file_path.read_bytes()
            encrypted = self.generate_encrypted_content(original)
            file_path.write_bytes(encrypted)
            print(f"    [ENCRYPTED] {file_path.name}")
            return True
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count == 0:
                continue
            p = count / length
            entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def simulate_entropy_spike(self):
        """Simulate high-entropy file writes (encryption signature)"""
        print(f"\n[>] ATTACK TYPE: Entropy Spike Detection")
        print(f"[*] Creating files with high entropy (simulated encrypted data)...")
        
        for i, test_file in enumerate(self.created_files[:self.config.file_count // 2]):
            high_entropy_data = os.urandom(4096)
            entropy = self.calculate_entropy(high_entropy_data)
            
            print(f"    [HIGH ENTROPY] {test_file.name}: {entropy:.2f} bits")
            
            if entropy > self.config.entropy_threshold:
                print(f"    [!] ABOVE THRESHOLD: {entropy:.2f} > {self.config.entropy_threshold}")
            
            if not self.config.dry_run:
                test_file.write_bytes(high_entropy_data)
            
            time.sleep(self.config.delay_ms / 1000)
    
    def simulate_velocity_attack(self):
        """Simulate rapid file modifications (mass encryption signature)"""
        print(f"\n[>] ATTACK TYPE: Velocity-Based Detection")
        print(f"[*] Rapidly modifying {self.config.file_count} files...")
        
        start_time = time.time()
        for i, test_file in enumerate(self.created_files):
            print(f"    [MODIFY {i+1}/{self.config.file_count}] {test_file.name}")
            
            if not self.config.dry_run:
                test_file.write_bytes(os.urandom(1024))
            
            time.sleep(self.config.delay_ms / 1000)
            
        elapsed = time.time() - start_time
        velocity = len(self.created_files) / elapsed if elapsed > 0 else 0
        
        print(f"[*] Velocity: {velocity:.1f} files/sec")
        if velocity > self.config.velocity_threshold:
            print(f"[!] VELOCITY ABOVE THRESHOLD: {velocity:.1f} > {self.config.velocity_threshold}")
    
    def simulate_extension_change(self):
        """Simulate ransomware extension change behavior"""
        print(f"\n[>] ATTACK TYPE: Extension Change Detection")
        
        ransomware_extensions = [
            ".encrypted", ".locked", ".crypt", ".enc", 
            ".encrypted", ".locky", ".crypto"
        ]
        
        for i, test_file in enumerate(self.created_files):
            new_ext = random.choice(ransomware_extensions)
            new_name = test_file.stem + new_ext
            new_path = test_file.parent / new_name
            
            print(f"    [RENAME] {test_file.name} -> {new_path.name}")
            
            if not self.config.dry_run:
                test_file.rename(new_path)
            
            time.sleep(self.config.delay_ms / 1000)
    
    def simulate_combined_attack(self):
        """Simulate a sophisticated combined attack"""
        print(f"\n[>] ATTACK TYPE: Combined Multi-Vector Attack")
        print(f"[*] Launching coordinated attack...")
        
        print(f"\n[1/4] Phase 1: Establishing presence...")
        for i, test_file in enumerate(self.created_files[:5]):
            print(f"    [SCAN] {test_file.name}")
            time.sleep(30 / 1000)
        
        print(f"\n[2/4] Phase 2: Pre-encryption entropy probes...")
        for test_file in self.created_files[5:10]:
            data = os.urandom(512)
            entropy = self.calculate_entropy(data)
            print(f"    [PROBE] {test_file.name}: entropy={entropy:.2f}")
            time.sleep(20 / 1000)
        
        print(f"\n[3/4] Phase 3: Rapid mass encryption...")
        start_time = time.time()
        for i, test_file in enumerate(self.created_files[10:]):
            print(f"    [ENCRYPT {i+1}/{len(self.created_files)-10}] {test_file.name}")
            
            if not self.config.dry_run:
                test_file.write_bytes(os.urandom(4096))
            
            time.sleep(self.config.delay_ms / 1000)
        
        elapsed = time.time() - start_time
        velocity = (len(self.created_files) - 10) / elapsed if elapsed > 0 else 0
        print(f"\n[*] Encryption velocity: {velocity:.1f} files/sec")
        
        print(f"\n[4/4] Phase 4: Extension modification...")
        self.simulate_extension_change()
    
    def run_attack(self):
        """Execute the configured attack simulation"""
        print(f"\n{'='*60}")
        print(f"RAKSHAK RANSOMWARE ATTACK SIMULATOR")
        print(f"{'='*60}")
        print(f"[+] Mode: {'DRY-RUN (no real encryption)' if self.config.dry_run else 'LIVE (actual encryption)'}")
        print(f"[+] Attack Type: {self.config.attack_type.value}")
        print(f"[+] Files to target: {self.config.file_count}")
        print(f"[+] Entropy threshold: {self.config.entropy_threshold}")
        print(f"[+] Velocity threshold: {self.config.velocity_threshold} files/sec")
        print(f"{'='*60}\n")
        
        if self.config.dry_run:
            print("[!] WARNING: Running in DRY-RUN mode - no files will be encrypted")
            print("[!] To perform real attack simulation, set dry_run=False\n")
        
        self.setup()
        
        try:
            if self.config.attack_type == AttackType.ENTROPY_SPIKE:
                self.simulate_entropy_spike()
            elif self.config.attack_type == AttackType.VELOCITY:
                self.simulate_velocity_attack()
            elif self.config.attack_type == AttackType.EXTENSION_CHANGE:
                self.simulate_extension_change()
            elif self.config.attack_type == AttackType.COMBINED:
                self.simulate_combined_attack()
            else:
                self.simulate_combined_attack()
                
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user")
        
        print(f"\n[>] Attack simulation complete")
        print(f"[*] Check Rakshak dashboard for detection alerts")
    
    def cleanup(self):
        """Remove test files"""
        if self.config.dry_run:
            print(f"\n[*] DRY-RUN mode: Skipping cleanup")
            return
            
        print(f"\n[*] Cleaning up test files...")
        for file_path in self.created_files:
            try:
                if file_path.exists():
                    file_path.unlink()
            except Exception as e:
                print(f"[!] Failed to delete {file_path}: {e}")
        
        try:
            if self.test_dir.exists() and not any(self.test_dir.iterdir()):
                self.test_dir.rmdir()
        except Exception:
            pass
        
        print(f"[+] Cleanup complete")

def print_help():
    print("""
RAKSHAK ATTACK SIMULATOR - Usage Guide
=======================================

USAGE:
    python ransomware_simulator.py [OPTIONS]

OPTIONS:
    --type TYPE          Attack type: entropy, velocity, extension, combined
    --count N            Number of test files (default: 20)
    --dry-run            Run without actual encryption (default: ON)
    --live               Run actual encryption (DANGEROUS)
    --dir PATH           Custom test directory
    --help               Show this help message

EXAMPLES:
    # Test entropy spike detection (safe)
    python ransomware_simulator.py --type entropy

    # Test velocity-based detection (safe)
    python ransomware_simulator.py --type velocity

    # Test extension change detection (safe)
    python ransomware_simulator.py --type extension

    # Test all detection mechanisms (safe)
    python ransomware_simulator.py --type combined

    # Run with actual encryption (CAUTION!)
    python ransomware_simulator.py --type combined --live

    # Custom test with more files
    python ransomware_simulator.py --type combined --count 50
""")

def main():
    config = AttackConfig(
        attack_type=AttackType.COMBINED,
        file_count=20,
        dry_run=True,
        delay_ms=50
    )
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i].lower()
        if arg == "--type" and i + 1 < len(args):
            type_str = args[i + 1].lower()
            if type_str == "entropy":
                config.attack_type = AttackType.ENTROPY_SPIKE
            elif type_str == "velocity":
                config.attack_type = AttackType.VELOCITY
            elif type_str == "extension":
                config.attack_type = AttackType.EXTENSION_CHANGE
            elif type_str == "combined":
                config.attack_type = AttackType.COMBINED
            i += 2
        elif arg == "--count" and i + 1 < len(args):
            config.file_count = int(args[i + 1])
            i += 2
        elif arg == "--dry-run":
            config.dry_run = True
            i += 1
        elif arg == "--live":
            config.dry_run = False
            i += 1
        elif arg == "--dir" and i + 1 < len(args):
            config.test_directory = args[i + 1]
            i += 2
        elif arg == "--help":
            print_help()
            return
        else:
            i += 1
    
    simulator = RakshakRansomwareSimulator(config)
    
    try:
        simulator.run_attack()
    finally:
        if input("\n[?] Clean up test files? (y/n): ").lower() == 'y':
            simulator.cleanup()

if __name__ == "__main__":
    main()
