import hashlib
import sys
import time
from cryptography.hazmat.primitives.asymmetric import ec

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

def privkey_to_address_fast(privkey_hex: str) -> str:
    """Derives a legacy Bitcoin address using native OpenSSL C-bindings via cryptography library."""
    # Convert hex key directly into numerical private key bytes
    privkey_bytes = bytes.fromhex(privkey_hex.zfill(64))
    
    # Fast Native C-Derivation of Public Key
    private_key_obj = ec.derive_private_key(int.from_bytes(privkey_bytes, 'big'), ec.SECP256K1())
    public_key_obj = private_key_obj.public_key()
    
    # Get uncompressed public key bytes (starts with 0x04)
    pub_numbers = public_key_obj.public_numbers()
    x_bytes = pub_numbers.x.to_bytes(32, 'big')
    y_bytes = pub_numbers.y.to_bytes(32, 'big')
    pubkey_bytes = b'\x04' + x_bytes + y_bytes
    
    # Native SHA256 & RIPEMD160 hash execution
    sha256_bp = hashlib.sha256(pubkey_bytes).digest()
    try:
        ripemd160 = hashlib.new('ripemd160', sha256_bp).digest()
    except ValueError:
        ripemd160 = hashlib.sha256(sha256_bp).digest()[:20]
        
    net_ripemd = b'\x00' + ripemd160
    
    # Double SHA256 Checksum
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
    print("Running with C-accelerated elliptic curve bindings...\n")
    
    # Starting at exactly 2^255
    current_int = 2**255
    end_range = 2**256
    
    total_scanned = 0
    start_time = time.time()
    
    # Reduced to 1 to give you an INSTANT visual response on your screen
    report_interval = 1 
    
    try:
        while current_int < end_range:
            hex_key = hex(current_int)[2:]
            address = privkey_to_address_fast(hex_key)
            
            if address in target_addresses:
                print(f"\n[!] MATCH FOUND: {address}")
                print(f"Private Key (Hex): {hex_key}")
                with open("found_keys.txt", "a") as f:
                    f.write(f"Private Key: {hex_key} | Address: {address}\n")
            
            total_scanned += 1
            
            if total_scanned % report_interval == 0:
                elapsed = time.time() - start_time
                speed = total_scanned / elapsed if elapsed > 0 else 0
                print(f"Total Scanned: {total_scanned} keys | Speed: {speed:.2f} keys/sec | Current: {hex_key[:12]}...", end="\r")
                sys.stdout.flush()
                
                # After verifying the first 10 keys work, dynamically scale reporting 
                # interval up to prevent printing operations from slowing down the CPU
                if total_scanned == 10:
                    report_interval = 50
                    
            current_int += 1
            
    except KeyboardInterrupt:
        print("\nScanning paused safely.")
