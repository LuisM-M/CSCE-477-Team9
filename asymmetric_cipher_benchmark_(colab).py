# --- Asymmetric Encryption Benchmark ---
# This script is designed for Google Colab.
# It compares the *operation time* of RSA and ECC.
# We test Key Generation, Signing, and Verifying.

# Step 1: Install the cryptography library
# !pip install cryptography pandas

import time
import os
import pandas as pd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
NUM_ITERATIONS = 100 # These operations are fast, so we do more
print(f"Starting asymmetric benchmark...")
print(f"Iterations per test: {NUM_ITERATIONS}\n")

# --- Generate Test Data ---
# We are "signing" a 32-byte hash, which simulates signing a file.
data_hash = os.urandom(32)
print("Test data (32-byte hash) generated.\n")

results = []

def benchmark_rsa(key_size_bits):
    """
    Benchmarks RSA for key generation, signing, and verification.
    """
    print(f"Testing: RSA {key_size_bits}-bit")

    # --- 1. Key Generation (Timed Separately) ---
    start_time = time.perf_counter()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size_bits,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    key_gen_time = time.perf_counter() - start_time

    # --- 2. Sign Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        signature = private_key.sign(
            data_hash,
            padding.PSS( # PSS is the modern, secure padding
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256() # This specifies the hash was SHA256
        )
    end_time = time.perf_counter()
    avg_sign_time = (end_time - start_time) / NUM_ITERATIONS

    # --- 3. Verify Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        public_key.verify(
            signature,
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    end_time = time.perf_counter()
    avg_verify_time = (end_time - start_time) / NUM_ITERATIONS

    return {
        "Algorithm": "RSA",
        "Key Size": f"{key_size_bits}-bit",
        "Security Equiv. (approx)": f"~{112 if key_size_bits == 2048 else 128}-bit",
        "Avg. Key Gen (s)": key_gen_time,
        "Avg. Sign (s)": avg_sign_time,
        "Avg. Verify (s)": avg_verify_time
    }

def benchmark_ecc(curve, curve_name, security_equiv):
    """
    Benchmarks ECC for key generation, signing, and verification.
    """
    print(f"Testing: ECC {curve_name}")

    # --- 1. Key Generation (Timed Separately) ---
    start_time = time.perf_counter()
    private_key = ec.generate_private_key(
        curve, backend=default_backend()
    )
    public_key = private_key.public_key()
    key_gen_time = time.perf_counter() - start_time

    # --- 2. Sign Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        signature = private_key.sign(
            data_hash,
            ec.ECDSA(hashes.SHA256())
        )
    end_time = time.perf_counter()
    avg_sign_time = (end_time - start_time) / NUM_ITERATIONS

    # --- 3. Verify Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        public_key.verify(
            signature,
            data_hash,
            ec.ECDSA(hashes.SHA256())
        )
    end_time = time.perf_counter()
    avg_verify_time = (end_time - start_time) / NUM_ITERATIONS

    return {
        "Algorithm": "ECC",
        "Key Size": curve_name,
        "Security Equiv. (approx)": f"~{security_equiv}-bit",
        "Avg. Key Gen (s)": key_gen_time,
        "Avg. Sign (s)": avg_sign_time,
        "Avg. Verify (s)": avg_verify_time
    }

# --- Run Benchmarks ---
print("Running benchmarks, this may take a moment...\n")

# --- RSA Tests ---
# We test 2048 (common) and 3072 (recommended)
results.append(benchmark_rsa(2048))
results.append(benchmark_rsa(3072))

# --- ECC Tests ---
# We test P-256 (common, ~128-bit security, equiv. to RSA-3072)
# and P-384 (stronger, ~192-bit security)
results.append(benchmark_ecc(ec.SECP256R1(), "P-256", 128))
results.append(benchmark_ecc(ec.SECP384R1(), "P-384", 192))


print("\n--- Benchmark Complete ---")

# --- Display Results in a Clean Table ---
df = pd.DataFrame(results)
df = df.round(6) # Round to 6 decimal places for these fast operations
print(df.to_markdown(index=False))

print("\n--- Key Takeaways ---")
print(" * ECC key generation is *orders of magnitude* faster than RSA.")
print(" * ECC signing is also significantly faster than RSA.")
print(" * RSA verification is surprisingly fast, often competitive with ECC.")
print(" * Most importantly: ECC provides the *same security* (e.g., P-256 vs RSA-3072) with")
print("   much smaller keys and better performance, which is why it's the modern standard.")