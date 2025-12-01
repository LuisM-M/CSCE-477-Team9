import time
import os
import pandas as pd
import tracemalloc
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

NUM_ITERATIONS = 100
RESULTS_FOLDER = os.path.join(os.getcwd(), "results")
os.makedirs(RESULTS_FOLDER, exist_ok=True)
data_hash = os.urandom(32)

asymmetric_results = []

def benchmark_rsa(key_size_bits):
    print(f"Testing: RSA {key_size_bits}-bit")
    
    # Key Gen
    tracemalloc.start()
    start = time.perf_counter()
    private_key = rsa.generate_private_key(65537, key_size_bits, default_backend())
    key_gen_time = time.perf_counter() - start
    _, key_gen_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    public_key = private_key.public_key()

    # Sign
    tracemalloc.start()
    start = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        sig = private_key.sign(data_hash, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
    sign_time = (time.perf_counter() - start) / NUM_ITERATIONS
    _, sign_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    asymmetric_results.append({
        "Algorithm": "RSA", "Key": f"{key_size_bits}-bit",
        "Key Gen (s)": key_gen_time, "Sign (s)": sign_time,
        "Key Gen Peak (KiB)": key_gen_peak / 1024
    })

def benchmark_ecc(curve, name):
    print(f"Testing: ECC {name}")
    
    # Key Gen
    tracemalloc.start()
    start = time.perf_counter()
    private_key = ec.generate_private_key(curve, default_backend())
    key_gen_time = time.perf_counter() - start
    _, key_gen_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Sign
    tracemalloc.start()
    start = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        private_key.sign(data_hash, ec.ECDSA(hashes.SHA256()))
    sign_time = (time.perf_counter() - start) / NUM_ITERATIONS
    _, sign_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    asymmetric_results.append({
        "Algorithm": "ECC", "Key": name,
        "Key Gen (s)": key_gen_time, "Sign (s)": sign_time,
        "Key Gen Peak (KiB)": key_gen_peak / 1024
    })

# --- Run ---
benchmark_rsa(2048)
benchmark_rsa(3072)
benchmark_ecc(ec.SECP256R1(), "P-256")
benchmark_ecc(ec.SECP384R1(), "P-384")

df = pd.DataFrame(asymmetric_results)
df.to_csv(os.path.join(RESULTS_FOLDER, "asymmetric_benchmark_results.csv"), index=False)
print("\n✅ Enhanced Asymmetric results saved.")