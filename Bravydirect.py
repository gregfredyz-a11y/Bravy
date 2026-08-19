import hashlib
import sys
import time
from ecdsa import SigningKey, SECP256k1

# Base58 encoding characters
base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encode_base58(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = ''
    while n > 0:
        n, r = divmod(n, 58)
        res = base58_alphabet[r] + res
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + res

def privkey_to_address(privkey_hex: str) -> str:
    """Fast inline address derivation without heavy framework wrappers."""
    privkey_bytes = bytes.fromhex(privkey_hex.zfill(64))
    
    # ECDSA Key Derivation
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    pubkey_bytes = b'\x04' + vk.to_string()
    
    # Double Hashing using native standard C-optimized hashlib
    sha256_bp = hashlib.sha256(pubkey_bytes).digest()
    
    try:
        ripemd160 = hashlib.new('ripemd160', sha256_bp).digest()
    except ValueError:
        # Fallback if Termux build lacks local openssl ripemd bindings
        ripemd160 = hashlib.sha256(sha256_bp).digest()[:20]
        
    net_ripemd = b'\x00' + ripemd160
    
    # Checksum calculation
    checksum = hashlib.sha256(hashlib.sha256(net_ripemd).digest()).digest()[:4]
    return encode_base58(net_ripemd + checksum)

def load_funded_addresses(filename="funded_address.txt") -> set:
    try:
        with open(filename, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"Error: '{filename}' not found.")
        return set()

if __name__ == "__main__":
    target_addresses = load_funded_addresses("funded_address.txt")
    if not target_addresses:
        sys.exit()
        
    print(f"Loaded {len(target_addresses)} addresses from file.")
    print("Running directly in Main Thread to bypass Termux background locks...\n")
    
    # Range configuration: 2^255 to 2^256-1
    current_int = 2**255
    end_range = 2**256
    
    total_scanned = 0
    start_time = time.time()
    
    # Performance reporting frequency
    report_interval = 200
    
    try:
        while current_int < end_range:
            hex_key = hex(current_int)[2:]
            address = privkey_to_address(hex_key)
            
            # Instant memory validation against loaded addresses
            if address in target_addresses:
                print(f"\n[!] MATCH FOUND: {address}")
                print(f"Private Key (Hex): {hex_key}")
                with open("found_keys.txt", "a") as f:
                    f.write(f"Private Key: {hex_key} | Address: {address}\n")
            
            total_scanned += 1
            
            # Print update every 200 keys without locking the processor
            if total_scanned % report_interval == 0:
                elapsed = time.time() - start_time
                speed = total_scanned / elapsed if elapsed > 0 else 0
                print(f"Total Scanned: {total_scanned} keys | Speed: {speed:.2f} keys/sec | Current: {hex_key[:12]}...", end="\r")
                sys.stdout.flush()
                
            current_int += 1
            
    except KeyboardInterrupt:
        print("\nScanning paused safely by user request.")
