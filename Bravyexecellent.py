import hashlib
import sys
import time
from cryptography.hazmat.primitives.asymmetric import ec

# ==========================================
# BIP-173 BECH32 OFFICIAL COMPATIBILITY LAYER
# ==========================================
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values +) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def encode_bech32(hrp, witver, witprog):
    five_bit_data = convertbits(witprog, 8, 5, True)
    data = [witver] + five_bit_data
    checksum = bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in data + checksum])

# ==========================================
# BASE58 CHECK LAYER (LEGACY & P2SH)
# ==========================================
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encode_base58(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = ''
    while n > 0:
        n, r = divmod(n, 58)
        res = BASE58_ALPHABET[r] + res
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + res

def ripemd160_hash(data_bytes: bytes) -> bytes:
    """Helper to cleanly route fast hashing with dynamic system library fallback."""
    sha256_bp = hashlib.sha256(data_bytes).digest()
    try:
        return hashlib.new('ripemd160', sha256_bp).digest()
    except ValueError:
        return hashlib.sha256(sha256_bp).digest()[:20]

def pubkey_to_legacy_address(pubkey_bytes: bytes) -> str:
    """Returns address starting with 1"""
    ripemd160 = ripemd160_hash(pubkey_bytes)
    net_ripemd = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(net_ripemd).digest()).digest()[:4]
    return encode_base58(net_ripemd + checksum)

def pubkey_to_nested_segwit(pubkey_bytes: bytes) -> str:
    """BIP49: Wraps compressed public key in redeemScript to return address starting with 3"""
    ripemd160 = ripemd160_hash(pubkey_bytes)
    # 0x0014 is the structural script pattern prefix for Witness Public Key Hash
    redeem_script = b'\x00\x14' + ripemd160 
    
    # Hash the script structure itself
    redeem_hash = ripemd160_hash(redeem_script)
    
    # 0x05 is the mainnet prefix for P2SH scripts
    net_p2sh = b'\x05' + redeem_hash
    checksum = hashlib.sha256(hashlib.sha256(net_p2sh).digest()).digest()[:4]
    return encode_base58(net_p2sh + checksum)

def pubkey_to_native_segwit(pubkey_bytes: bytes) -> str:
    """BIP84: Returns address starting with bc1q"""
    ripemd160 = ripemd160_hash(pubkey_bytes)
    return encode_bech32("bc", 0, ripemd160)

# ==========================================
# STATE & LOADING MANAGEMENT
# ==========================================
def load_state(default_start=2**255) -> int:
    try:
        with open("last_checked.txt", "r") as f:
            val = f.read().strip()
            if val:
                return int(val, 16)
    except (FileNotFoundError, ValueError):
        pass
    return default_start

def save_state(current_int: int):
    with open("last_checked.txt", "w") as f:
        f.write(hex(current_int))

def load_funded_addresses(filename="funded_address.txt") -> set:
    try:
        with open(filename, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        print(f"Error: '{filename}' not found.")
        return set()

# ==========================================
# EXECUTION CORES
# ==========================================
if __name__ == "__main__":
    target_addresses = load_funded_addresses("funded_address.txt")
    if not target_addresses:
        sys.exit()
        
    start_point = load_state()
    print(f"Loaded {len(target_addresses)} targets from file.")
    print(f"Resuming scanning operations from: {hex(start_point)[:14]}...")
    
    # Simple upfront prefix check for user visibility
    p2sh_count = sum(1 for a in target_addresses if a.startswith('3'))
    print(f"Target list verification: Found {p2sh_count} Nested SegWit ('3...') entries inside target file.")
    
    current_int = start_point
    end_range = 2**256
    total_scanned = 0
    start_time = time.time()
    
    report_interval = 250
    auto_save_interval = 5000  

    try:
        while current_int < end_range:
            hex_key = hex(current_int)[2:].zfill(64)
            privkey_bytes = bytes.fromhex(hex_key)
            
            # Fast Native C-Derivation of Public Key Coordinates
            private_key_obj = ec.derive_private_key(int.from_bytes(privkey_bytes, 'big'), ec.SECP256K1())
            pub_numbers = private_key_obj.public_key().public_numbers()
            x_bytes = pub_numbers.x.to_bytes(32, 'big')
            y_bytes = pub_numbers.y.to_bytes(32, 'big')
            
            # Format 1: Uncompressed Legacy (Starts with 1)
            pub_uncompressed = b'\x04' + x_bytes + y_bytes
            addr_legacy_uncomp = pubkey_to_legacy_address(pub_uncompressed)
            
            # Setup for Compressed-variant generations
            prefix = b'\x02' if pub_numbers.y % 2 == 0 else b'\x03'
            pub_compressed = prefix + x_bytes
            
            # Format 2: Compressed Legacy (Starts with 1)
            addr_legacy_comp = pubkey_to_legacy_address(pub_compressed)
            
            # Format 3: Nested SegWit / P2SH (Starts with 3)
            addr_nested_segwit = pubkey_to_nested_segwit(pub_compressed)
            
            # Format 4: Native SegWit / Bech32 (Starts with bc1q)
            addr_native_segwit = pubkey_to_native_segwit(pub_compressed)
            
            # Evaluate Derived Addresses
            derived_set = {
                addr_legacy_uncomp.lower(), 
                addr_legacy_comp.lower(), 
                addr_nested_segwit.lower(), 
                addr_native_segwit.lower()
            }
            matches = derived_set.intersection(target_addresses)
            
            if matches:
                for match in matches:
                    print(f"\n[!] MATCH FOUND: {match} | Key: {hex_key}")
                    with open("found_keys.txt", "a") as f:
                        f.write(f"Private Key: {hex_key} | Address: {match}\n")
            
            total_scanned += 1
            
            if total_scanned % report_interval == 0:
                elapsed = time.time() - start_time
                speed = total_scanned / elapsed if elapsed > 0 else 0
                print(f"Count: {total_scanned} | Speed: {speed:.1f} k/s | Hex: {hex_key[:8]}...", end="\r")
                sys.stdout.flush()
                
            if total_scanned % auto_save_interval == 0:
                save_state(current_int)
                
            current_int += 1
            
    except KeyboardInterrupt:
        save_state(current_int)
        print(f"\nProgress auto-saved at: {hex(current_int)}")
        print("Scanning paused safely.")
