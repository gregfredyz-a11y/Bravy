import hashlib
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
    """Derives an uncompressed Bitcoin Legacy address (P2PKH) from a hex private key."""
    privkey_bytes = bytes.fromhex(privkey_hex.zfill(64))
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    pubkey_bytes = b'\x04' + vk.to_string()
    
    sha256_bp = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_bp).digest()
    net_ripemd = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(net_ripemd).digest()).digest()[:4]
    return encode_base58(net_ripemd + checksum)

def load_funded_addresses(filename="funded_address.txt") -> set:
    """Loads target addresses into a set for O(1) ultra-fast lookup."""
    try:
        with open(filename, "r") as f:
            # Strip whitespace and ignore empty lines
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"Error: '{filename}' not found. Please create it first.")
        return set()

# Load the file
target_addresses = load_funded_addresses("funded_address.txt")

if target_addresses:
    print(f"Successfully loaded {len(target_addresses)} addresses from file.")
    
    # Range configuration: 2^255 to 2^256-1
    start_key = 2**255
    end_key = 2**256
    current_int = start_key
    
    print("Starting key scan...")
    
    # Counters for progress tracking
    scanned_count = 0
    
    while current_int < end_key:
        hex_key = hex(current_int)[2:]
        address = privkey_to_address(hex_key)
        
        # Check if the derived address matches any loaded address
        if address in target_addresses:
            print(f"\n[!] MATCH FOUND: {address}")
            print(f"Private Key (Hex): {hex_key}")
            
            with open("found_keys.txt", "a") as f:
                f.write(f"Private Key: {hex_key} | Address: {address}\n")
        
        scanned_count += 1
        if scanned_count % 1000 == 0:
            print(f"Scanned {scanned_count} keys... Current Hex: {hex_key[:10]}...", end="\r")
            
        current_int += 1
else:
    print("Script halted. No target addresses loaded.")

