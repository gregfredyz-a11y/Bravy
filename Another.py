import hashlib
import sys
import time
from cryptography.hazmat.primitives.asymmetric import ec

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

def pubkey_to_address(pubkey_bytes: bytes) -> str:
    """Helper to convert raw public keys to a standard Base58 check address."""
    sha256_bp = hashlib.sha256(pubkey_bytes).digest()
    try:
        ripemd160 = hashlib.new('ripemd160', sha256_bp).digest()
    except ValueError:
        ripemd160 = hashlib.sha256(sha256_bp).digest()[:20]
        
    net_ripemd = b'\x00' + ripemd160
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
        
    print(f"Loaded {len(target_addresses)} targets. Scanning...")
    
    current_int = 2**255
    end_range = 2**256
    total_scanned = 0
    start_time = time.time()
    report_interval = 250 # Reduced updates slightly to save Termux UI processing lag

    try:
        while current_int < end_range:
            hex_key = hex(current_int)[2:].zfill(64)
            privkey_bytes = bytes.fromhex(hex_key)
            
            # Fast Native C-Derivation of Public Key Points
            private_key_obj = ec.derive_private_key(int.from_bytes(privkey_bytes, 'big'), ec.SECP256K1())
            pub_numbers = private_key_obj.public_key().public_numbers()
            x_bytes = pub_numbers.x.to_bytes(32, 'big')
            y_bytes = pub_numbers.y.to_bytes(32, 'big')
            
            # Format 1: Uncompressed Legacy (0x04 prefix)
            pub_uncompressed = b'\x04' + x_bytes + y_bytes
            addr_uncompressed = pubkey_to_address(pub_uncompressed)
            
            # Format 2: Compressed Legacy (0x02 or 0x03 prefix depending on Y coordinate parity)
            prefix = b'\x02' if pub_numbers.y % 2 == 0 else b'\x03'
            pub_compressed = prefix + x_bytes
            addr_compressed = pubkey_to_address(pub_compressed)
            
            # Match Verification against both formats
            if addr_uncompressed in target_addresses:
                print(f"\n[!] MATCH FOUND (Uncompressed): {addr_uncompressed} | Key: {hex_key}")
                with open("found_keys.txt", "a") as f:
                    f.write(f"Private Key: {hex_key} | Uncompressed Address: {addr_uncompressed}\n")
                    
            if addr_compressed in target_addresses:
                print(f"\n[!] MATCH FOUND (Compressed): {addr_compressed} | Key: {hex_key}")
                with open("found_keys.txt", "a") as f:
                    f.write(f"Private Key: {hex_key} | Compressed Address: {addr_compressed}\n")
            
            total_scanned += 1
            
            # Clean, shortened status bar to prevent terminal line wrapping
            if total_scanned % report_interval == 0:
                elapsed = time.time() - start_time
                speed = total_scanned / elapsed if elapsed > 0 else 0
                print(f"Count: {total_scanned} | Speed: {speed:.1f} k/s | Hex: {hex_key[:8]}...", end="\r")
                sys.stdout.flush()
                
            current_int += 1
            
    except KeyboardInterrupt:
        print("\nScanning paused safely.")
