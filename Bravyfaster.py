import hashlib
import multiprocessing
import sys
import time
from cryptography.hazmat.primitives import hashes
from ecdsa import SigningKey, SECP256k1

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
    """Derives a legacy address using cryptography backend."""
    privkey_bytes = bytes.fromhex(privkey_hex.zfill(64))
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    pubkey_bytes = b'\x04' + vk.to_string()
    
    digest1 = hashes.Hash(hashes.SHA256())
    digest1.update(pubkey_bytes)
    sha256_bp = digest1.finalize()
    
    try:
        ripemd160 = hashlib.new('ripemd160', sha256_bp).digest()
    except ValueError:
        import hashlib as hl
        ripemd160 = hl.sha256(sha256_bp).digest()[:20] 

    net_ripemd = b'\x00' + ripemd160
    
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

def worker_scan(core_id, start_range, end_range, target_addresses, queue):
    """Worker function that streams counts out using a thread-safe queue."""
    current_int = start_range
    scanned_count = 0
    
    # Process keys in smaller chunks to avoid freezing the queue
    chunk_size = 500 
    
    while current_int < end_range:
        hex_key = hex(current_int)[2:]
        address = privkey_to_address(hex_key)
        
        if address in target_addresses:
            print(f"\n[!] MATCH FOUND ON CORE {core_id}: {address}")
            with open("found_keys.txt", "a") as f:
                f.write(f"Private Key: {hex_key} | Address: {address}\n")
        
        scanned_count += 1
        if scanned_count >= chunk_size:
            queue.put(scanned_count)
            scanned_count = 0
            
        current_int += 1
        
    if scanned_count > 0:
        queue.put(scanned_count)

if __name__ == "__main__":
    target_addresses = load_funded_addresses("funded_address.txt")
    if not target_addresses:
        sys.exit()
        
    num_cores = multiprocessing.cpu_count()
    print(f"Loaded {len(target_addresses)} addresses. Launching on {num_cores} cores.")
    
    total_start = 2**255
    total_end = 2**256
    total_keyspace = total_end - total_start
    chunk_size = total_keyspace // num_cores
    
    # Use standard Queue for cross-process metrics telemetry
    queue = multiprocessing.Queue()
    processes = []
    
    # Force clean process isolation for Termux compatibility
    ctx = multiprocessing.get_context('spawn')
    
    for i in range(num_cores):
        core_start = total_start + (i * chunk_size)
        core_end = core_start + chunk_size if i < num_cores - 1 else total_end
        
        p = ctx.Process(
            target=worker_scan, 
            args=(i, core_start, core_end, target_addresses, queue)
        )
        processes.append(p)
        p.start()
        
    print("All cores active. Live throughput tracking initiated...\n")
    
    total_scanned = 0
    start_time = time.time()
    
    try:
        while True:
            # Drain the queue to aggregate global keys scanned
            while not queue.empty():
                total_scanned += queue.get()
                
            elapsed = time.time() - start_time
            if elapsed > 0:
                speed = total_scanned / elapsed
                print(f"Total Scanned: {total_scanned} keys | Speed: {speed:.2f} keys/sec", end="\r")
                sys.stdout.flush()
                
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("\nAborting operations...")
        for p in processes:
            p.terminate()
            p.join()
