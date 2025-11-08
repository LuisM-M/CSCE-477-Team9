# --- Symmetric Encryption Benchmark ---
# This script is designed for Google Colab.
# It compares the throughput (in MB/s) of AES and ChaCha20.
# We test two popular AES modes: GCM (modern) and CBC (older).

# Step 1: Install the cryptography library
# !pip install cryptography pandas

import os
import time
import pandas as pd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
# We use a 100MB file for a good performance test.
DATA_SIZE_MB = 100
DATA_SIZE_BYTES = DATA_SIZE_MB * 1024 * 1024
NUM_ITERATIONS = 5 # Run 5 times and average

print(f"Starting symmetric benchmark...")
print(f"Data Size: {DATA_SIZE_MB} MB")
print(f"Iterations: {NUM_ITERATIONS}\n")

# --- Generate Test Data ---
# We generate this once to ensure all algorithms test the same data.
print("Generating test data...")
data_to_encrypt = os.urandom(DATA_SIZE_BYTES)
print("Test data generated.\n")

# This list will store our results
results = []

def benchmark_aes_gcm(data, key_size_bits):
    """
    Benchmarks AES-GCM (Authenticated Encryption).
    This is the modern, all-in-one, and secure mode.
    """
    print(f"Testing: AES-{key_size_bits} GCM")
    key_size_bytes = key_size_bits // 8

    # --- Setup (not timed) ---
    key = AESGCM.generate_key(bit_length=key_size_bits)
    aes_gcm = AESGCM(key)
    nonce = os.urandom(12) # GCM standard nonce size

    # --- Encrypt Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        ciphertext = aes_gcm.encrypt(nonce, data, None) # None = no associated data
    end_time = time.perf_counter()

    total_time = end_time - start_time
    total_data_mb = DATA_SIZE_MB * NUM_ITERATIONS
    encrypt_throughput = total_data_mb / total_time

    # --- Decrypt Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        plaintext = aes_gcm.decrypt(nonce, ciphertext, None)
    end_time = time.perf_counter()

    total_time = end_time - start_time
    decrypt_throughput = total_data_mb / total_time

    return {
        "Algorithm": "AES",
        "Key Size": key_size_bits,
        "Mode": "GCM (AEAD)",
        "Encrypt (MB/s)": encrypt_throughput,
        "Decrypt (MB/s)": decrypt_throughput
    }

def benchmark_aes_cbc_hmac(data, key_size_bits):
    """
    Benchmarks AES-CBC (older mode) + HMAC for authentication.
    This is a two-step process: encrypt, then authenticate.
    This shows why AEAD modes like GCM are better.
    """
    print(f"Testing: AES-{key_size_bits} CBC + HMAC-SHA256")
    key_size_bytes = key_size_bits // 8

    # --- Setup (not timed) ---
    # We need separate keys for encryption and authentication
    encrypt_key = os.urandom(key_size_bytes)
    auth_key = os.urandom(32) # HMAC key
    iv = os.urandom(16) # AES block size

    cipher = Cipher(algorithms.AES(encrypt_key), modes.CBC(iv), backend=default_backend())

    # --- Encrypt Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        # 1. Encrypt
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        # 2. Authenticate (generate HMAC tag)
        h = hmac.HMAC(auth_key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        tag = h.finalize()
    end_time = time.perf_counter()

    total_time = end_time - start_time
    total_data_mb = DATA_SIZE_MB * NUM_ITERATIONS
    encrypt_throughput = total_data_mb / total_time

    # --- Decrypt Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        # 1. Verify HMAC tag
        h = hmac.HMAC(auth_key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        h.verify(tag) # Throws an error if invalid
        # 2. Decrypt
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    end_time = time.perf_counter()

    total_time = end_time - start_time
    decrypt_throughput = total_data_mb / total_time

    return {
        "Algorithm": "AES",
        "Key Size": key_size_bits,
        "Mode": "CBC + HMAC",
        "Encrypt (MB/s)": encrypt_throughput,
        "Decrypt (MB/s)": decrypt_throughput
    }

def benchmark_chacha20_poly1305(data):
    """
    Benchmarks ChaCha20-Poly1305 (Authenticated Encryption).
    This is the modern competitor to AES-GCM.
    """
    print(f"Testing: ChaCha20-Poly1305")

    # --- Setup (not timed) ---
    key = ChaCha20Poly1305.generate_key() # 256-bit key
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12) # ChaCha20 standard nonce size

    # --- Encrypt Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        ciphertext = chacha.encrypt(nonce, data, None)
    end_time = time.perf_counter()

    total_time = end_time - start_time
    total_data_mb = DATA_SIZE_MB * NUM_ITERATIONS
    encrypt_throughput = total_data_mb / total_time

    # --- Decrypt Test ---
    start_time = time.perf_counter()
    for _ in range(NUM_ITERATIONS):
        plaintext = chacha.decrypt(nonce, ciphertext, None)
    end_time = time.perf_counter()

    total_time = end_time - start_time
    decrypt_throughput = total_data_mb / total_time

    return {
        "Algorithm": "ChaCha20",
        "Key Size": 256,
        "Mode": "Poly1305 (AEAD)",
        "Encrypt (MB/s)": encrypt_throughput,
        "Decrypt (MB/s)": decrypt_throughput
    }

# --- Run Benchmarks ---
print("Running benchmarks, this may take a moment...\n")

# AES-GCM
results.append(benchmark_aes_gcm(data_to_encrypt, 128))
results.append(benchmark_aes_gcm(data_to_encrypt, 256))

# ChaCha20-Poly1305
results.append(benchmark_chacha20_poly1305(data_to_encrypt))

# AES-CBC-HMAC (This will be noticeably slower)
results.append(benchmark_aes_cbc_hmac(data_to_encrypt, 128))
results.append(benchmark_aes_cbc_hmac(data_to_encrypt, 256))

print("\n--- Benchmark Complete ---")

# --- Display Results in a Clean Table ---
df = pd.DataFrame(results)
df = df.round(2) # Round to 2 decimal places

# --- Display Results in a Clean Table ---
df = pd.DataFrame(results)
df = df.round(6) # Round to 6 decimal places for these fast operations


# --- SAVE TO FILE (CSV) ---
results_folder = "results"
output_filename_csv = "symmetric_benchmark_results.csv"

# 1. Create the 'results' folder if it doesn't already exist
os.makedirs(results_folder, exist_ok=True)

# 2. Create the full path (e.g., "results/symmetric_benchmark_results.csv")
full_output_path = os.path.join(results_folder, output_filename_csv)

# 3. Save the file to that specific path
df.to_csv(full_output_path, index=False)
print(f"\n✅ Results successfully saved to: {full_output_path}")
# ---------------------------

print(df.to_markdown(index=False))

print("\n--- Key Takeaways ---")
print(" * AES-GCM is typically fastest on modern hardware due to CPU support (AES-NI).")
print(" * ChaCha20 is designed for high performance in *software* and may be faster on low-power devices.")
print(" * AES-CBC + HMAC is much slower because it's two separate operations (encrypt then authenticate).")