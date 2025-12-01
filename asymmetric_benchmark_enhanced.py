import time
import os
import pandas as pd
import tracemalloc
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
NUM_ITERATIONS_ASYMMETRIC = 100 
print(f"Starting asymmetric benchmark (V3)...")
print(f"Iterations per test: {NUM_ITERATIONS_ASYMMETRIC}\n")

# --- Setup Paths (already done, but good to have for this cell) ---
SCRIPT_DIRECTORY = os.getcwd()
RESULTS_FOLDER = os.path.join(SCRIPT_DIRECTORY, "results")
os.makedirs(RESULTS_FOLDER, exist_ok=True)
print(f"Saving results to: {RESULTS_FOLDER}")

# --- Generate Test Data ---
data_hash = os.urandom(32) # 32-byte hash (simulates SHA-256)
print("Test data (32-byte hash) generated.\n")

# This list will store our results
asymmetric_results = []

def benchmark_rsa(key_size_bits):
    """
    Benchmarks RSA for key generation, signing, and verification.
    Also measures peak memory usage for each.
    
    Returns a dictionary of results.
    """
    print(f"Testing: RSA {key_size_bits}-bit")
    
    # --- 1. Key Generation ---
    tracemalloc.start()
    start_time = time.perf_counter()
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size_bits,
        backend=default_backend()
    )
    
    key_gen_time = time.perf_counter() - start_time
    _, key_gen_peak_mem = tracemalloc.get_traced_memory() # current, peak
    tracemalloc.stop()
    
    public_key = private_key.public_key()
    
    # --- 2. Sign Test ---
    tracemalloc.start()
    start_time = time.perf_counter()
    
    for _ in range(NUM_ITERATIONS_ASYMMETRIC):
        signature = private_key.sign(
            data_hash,
            padding.PSS( 
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
    avg_sign_time = (time.perf_counter() - start_time) / NUM_ITERATIONS_ASYMMETRIC
    _, sign_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    # --- 3. Verify Test ---
    tracemalloc.start()
    start_time = time.perf_counter()
    
    for _ in range(NUM_ITERATIONS_ASYMMETRIC):
        public_key.verify(
            signature,
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
    avg_verify_time = (time.perf_counter() - start_time) / NUM_ITERATIONS_ASYMMETRIC
    _, verify_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    # --- 4. Return results as a dictionary ---
    return {
        "Algorithm": "RSA",
        "Key": f"{key_size_bits}-bit",
        "Security (approx)": f"~{112 if key_size_bits == 2048 else 128}-bit",
        "Key Gen (s)": key_gen_time,
        "Sign (s)": avg_sign_time,
        "Verify (s)": avg_verify_time,
        "Key Gen Peak (KiB)": key_gen_peak_mem / 1024,
        "Sign Peak (KiB)": sign_peak_mem / 1024,
        "Verify Peak (KiB)": verify_peak_mem / 1024
    }

def benchmark_ecc(curve, curve_name, security_equiv):
    """
    Benchmarks ECC for key generation, signing, and verification.
    Also measures peak memory usage for each.
    
    Returns a dictionary of results.
    """
    print(f"Testing: ECC {curve_name}")
    
    # --- 1. Key Generation ---
    tracemalloc.start()
    start_time = time.perf_counter()
    
    private_key = ec.generate_private_key(
        curve, backend=default_backend()
    )
    
    key_gen_time = time.perf_counter() - start_time
    _, key_gen_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    public_key = private_key.public_key()
    
    # --- 2. Sign Test ---
    tracemalloc.start()
    start_time = time.perf_counter()
    
    for _ in range(NUM_ITERATIONS_ASYMMETRIC):
        signature = private_key.sign(
            data_hash,
            ec.ECDSA(hashes.SHA256())
        )
        
    avg_sign_time = (time.perf_counter() - start_time) / NUM_ITERATIONS_ASYMMETRIC
    _, sign_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    # --- 3. Verify Test ---
    tracemalloc.start()
    start_time = time.perf_counter()
    
    for _ in range(NUM_ITERATIONS_ASYMMETRIC):
        public_key.verify(
            signature,
            data_hash,
            ec.ECDSA(hashes.SHA256())
        )
        
    avg_verify_time = (time.perf_counter() - start_time) / NUM_ITERATIONS_ASYMMETRIC
    _, verify_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # --- 4. Return results as a dictionary ---
    return {
        "Algorithm": "ECC",
        "Key": curve_name,
        "Security (approx)": f"~{security_equiv}-bit",
        "Key Gen (s)": key_gen_time,
        "Sign (s)": avg_sign_time,
        "Verify (s)": avg_verify_time,
        "Key Gen Peak (KiB)": key_gen_peak_mem / 1024,
        "Sign Peak (KiB)": sign_peak_mem / 1024,
        "Verify Peak (KiB)": verify_peak_mem / 1024
    }

# --- Run Benchmarks ---
print("Running asymmetric benchmarks, this may take a moment...\n")

# --- RSA Tests ---
asymmetric_results.append(benchmark_rsa(2048))
asymmetric_results.append(benchmark_rsa(3072))

# --- ECC Tests ---
asymmetric_results.append(benchmark_ecc(ec.SECP256R1(), "P-256 (secp256r1)", 128))
asymmetric_results.append(benchmark_ecc(ec.SECP384R1(), "P-384 (secp384r1)", 192))

print("\n--- Asymmetric Benchmark Complete ---")

# --- Display Results in a Clean Table ---
df_asymmetric = pd.DataFrame(asymmetric_results)
df_asymmetric = df_asymmetric.round(6) 

# --- SAVE TO FILE (CSV) ---
output_filename_csv = "asymmetric_benchmark_results.csv"
full_output_path = os.path.join(RESULTS_FOLDER, output_filename_csv)
df_asymmetric.to_csv(full_output_path, index=False)
print(f"\n✅ Asymmetric results successfully saved to: {full_output_path}")
# ---------------------------

print("\n--- Asymmetric Benchmark Results (V3) ---")
try:
    print(df_asymmetric.to_markdown(index=False))
except ImportError:
    print(df_asymmetric)