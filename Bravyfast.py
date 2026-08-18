import hashlib
import multiprocessing
import sys
import time
from cryptography.hazmat.primitives import hashes
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
    """Derives a legacy address using faster cryptography backend."""
    privkey_bytes = bytes.fromhex(privkey_hex.zfill(64))
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    pubkey_bytes = b'\x04' + vk.to_string()
    
    # Fast SHA256 using cryptography library
    digest1 = hashes.Hash(hashes.SHA256())
    digest1.update(pubkey_bytes)
    sha256_bp = digest1.finalize()
    
    # Fast RIPEMD160
    digest2 = hashes.Hash(hashes.RIPEMD160())
    digest2.update(sha256_bp)
    ripemd160 = digest2.finalize()
    
    net_ripemd = b'\x00' + ripemd160
    
    # Double SHA256 for checksum
    d3 = hashes.Hash(hashes.SHA256())
    d3.update(net_ripemd)
    d4 = hashes.Hash(hashes.SHA256())
    d4.update(d3.finalize())
    checksum = d4.finalize()[:4]
    
    return encode_base58(net_ripemd + checksum)

def load_funded_addresses(filename="funded_address.txt") -> set:
    try:
        with open(filename, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"Error: '{filename}' not found.")
        return set()

def worker_scan(core_id, start_range, end_range, target_addresses, progress_dict):
    """Worker function that runs independently on a single CPU core."""
    current_int = start_range
    scanned_count = 0
    
    while current_int < end_range:
        hex_key = hex(current_int)[2:]
        address = privkey_to_address(hex_key)
        
        if address in target_addresses:
            print(f"\n[!] MATCH FOUND ON CORE {core_id}: {address}")
            print(f"Private Key (Hex): {hex_key}")
            with open("found_keys.txt", "a") as f:
                f.write(f"Private Key: {hex_key} | Address: {address}\n")
        
        scanned_count += 1
        if scanned_count % 2000 == 0:
            progress_dict[core_id] = scanned_count
            
        current_int += 1

def monitor_progress(progress_dict, total_cores):
    """Main thread loop to aggregate and display real-world performance."""
    start_time = time.time()
    last_total = 0
    
    while True:
        time.sleep(1)
        # Sum up progress from all running cores
        total_scanned = sum(progress_dict.values())
        elapsed = time.time() - start_time
        
        if elapsed > 0:
            speed = total_scanned / elapsed
            print(f"Total Scanned: {total_scanned} keys | Speed: {speed:.2f} keys/sec", end="\r")
            sys.stdout.flush()

if __name__ == "__main__":
    # Load target file
    target_addresses = load_funded_addresses("funded_address.txt")
    if not target_addresses:
        sys.exit()
        
    num_cores = multiprocessing.cpu_count()
    print(f"Loaded {len(target_addresses)} addresses. Utilizing {num_cores} CPU cores.")
    
    # Range configuration: 2^255 to 2^256-1
    total_start = 2**255
    total_end = 2**256
    total_keyspace = total_end - total_start
    chunk_size = total_keyspace // num_cores
    
    # Shared dictionary for performance tracking
    manager = multiprocessing.Manager()
    progress_dict = manager.dict()
    for i in range(num_cores):
        progress_dict[i] = 0
        
    processes = []
    for i in range(num_cores):
        # Calculate unique sub-range for each individual core
        core_start = total_start + (i * chunk_size)
        core_end = core_start + chunk_size if i < num_cores - 1 else total_end
        
        p = multiprocessing.Process(
            target=worker_scan, 
            args=(i, core_start, core_end, target_addresses, progress_dict)
        )
        processes.append(p)
        p.start()
        
    # Start performance monitor in the main thread
    try:
        monitor_progress(progress_dict, num_cores)
    except KeyboardInterrupt:
        print("\nTerminating scanning processes...")
        for p in processes:
            p.terminate()
