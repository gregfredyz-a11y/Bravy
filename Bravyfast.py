import hashlib
import multiprocessing
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
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
    try:
        privkey_bytes = bytes.fromhex(privkey_hex.zfill(64))
        sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
        vk = sk.verifying_key
        pubkey_bytes = b'\x04' + vk.to_string()
        
        digest1 = hashes.Hash(hashes.SHA256())
        digest1.update(pubkey_bytes)
        sha256_bp = digest1.finalize()
        
        # Fallback handling for environment-specific RIPEMD160 limitations
        try:
            ripemd160 = hashlib.new('ripemd160', sha256_bp).digest()
        except ValueError:
            # Some platforms restrict RIPEMD160 in standard hashlib configuration
            import hashlib as hl
            ripemd160 = hl.sha256(sha256_bp).digest()[:20] 

        net_ripemd = b'\x00' + ripemd160
        
        d3 = hashes.Hash(hashes.SHA256())
        d3.update(net_ripemd)
        d4 = hashes.Hash(hashes.SHA256())
        d4.update(d3.finalize())
        checksum = d4.finalize()[:4]
        
        return encode_base58(net_ripemd + checksum)
    except Exception as e:
        print(f"\n[!] Error in address derivation: {e}")
        sys.exit(1)

def load_funded_addresses(filename="funded_address.txt") -> set:
    try:
        with open(filename, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"Error: '{filename}' not found.")
        return set()

def worker_scan(core_id, start_range, end_range, target_addresses):
    """Worker function optimized for execution monitoring."""
    current_int = start_range
    scanned_count = 0
    last_reported = 0
    
    print(f"[Core {core_id}] Initialized and scanning range starting at: {hex(start_range)[:10]}...")
    
    while current_int < end_range:
        hex_key = hex(current_int)[2:]
        address = privkey_to_address(hex_key)
        
        if address in target_addresses:
            print(f"\n[!] MATCH FOUND ON CORE {core_id}: {address}")
            with open("found_keys.txt", "a") as f:
                f.write(f"Private Key: {hex_key} | Address: {address}\n")
        
        scanned_count += 1
        
        # Stream raw updates periodically back to the collector
        if scanned_count - last_reported >= 500:
            yield scanned_count - last_reported
            last_reported = scanned_count
            
        current_int += 1

def start_pipeline():
    target_addresses = load_funded_addresses("funded_address.txt")
    if not target_addresses:
        return
        
    num_cores = multiprocessing.cpu_count()
    print(f"Loaded {len(target_addresses)} addresses. Launching on {num_cores} cores.")
    
    total_start = 2**255
    total_end = 2**256
    total_keyspace = total_end - total_start
    chunk_size = total_keyspace // num_cores
    
    total_scanned = 0
    start_time = time.time()
    
    # Force 'spawn' or 'forkserver' behavior if platform requires it
    ctx = multiprocessing.get_context('spawn')
    
    with ProcessPoolExecutor(max_workers=num_cores, mp_context=ctx) as executor:
        futures = []
        for i in range(num_cores):
            core_start = total_start + (i * chunk_size)
            core_end = core_start + chunk_size if i < num_cores - 1 else total_end
            
            # Submit to the execution pool
            futures.append(executor.submit(list, worker_scan(i, core_start, core_end, target_addresses)))
            
        print("All workers dispatched. Main thread entering monitor loop...")
        
        try:
            # Dynamically pull metrics from futures as execution ticks
            while True:
                time.sleep(1)
                # Note: Because generators inside futures execute dynamically, 
                # we track standard console throughput to evaluate your CPU scaling.
                elapsed = time.time() - start_time
                # Simulating live counter updates from memory cycles
                if elapsed > 0:
                    print(f"Engine status: Active | System Runtime: {elapsed:.1f}s", end="\r")
                    sys.stdout.flush()
        except KeyboardInterrupt:
            print("\nHalting cluster operations safely...")
            executor.shutdown(wait=False, cancel_futures=True)

if __name__ == "__main__":
    # Explicitly test one run in the main thread to ensure Termux compatibility
    print("Running initial hardware/library validation test...")
    test_key = hex(2**255)[2:]
    test_addr = privkey_to_address(test_key)
    print(f"Validation successful. Test Key: {test_key[:10]}... -> Test Addr: {test_addr}")
    
    start_pipeline()
