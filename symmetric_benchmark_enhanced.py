import os
import time
import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# --- Configuration ---
DATA_SIZES_TO_TEST = {
    "1KB": 1024,
    "1MB": 1024 * 1024,
    "100MB": 100 * 1024 * 1024
}
NUM_ITERATIONS_LARGE = 5
NUM_ITERATIONS_SMALL = 100

print(f"Starting symmetric benchmark (Enhanced)...")

# --- Setup Paths ---
RESULTS_FOLDER = os.path.join(os.getcwd(), "results")
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# --- Generate Test Data ---
print("Generating test data...")
test_data = {}
for name, size in DATA_SIZES_TO_TEST.items():
    test_data[name] = os.urandom(size)
print("Test data generated.\n")

symmetric_results = []

def get_iterations(size_bytes):
    return NUM_ITERATIONS_SMALL if size_bytes < (1024 * 1024) else NUM_ITERATIONS_LARGE

def benchmark_aes_gcm(data, data_name, key_size_bits):
    size_bytes = len(data)
    num_iterations = get_iterations(size_bytes)
    print(f"Testing: AES-{key_size_bits} GCM ({data_name})")

    key = AESGCM.generate_key(bit_length=key_size_bits)
    aes_gcm = AESGCM(key)
    nonce = os.urandom(12) 
    
    # Encrypt
    start_time = time.perf_counter()
    for _ in range(num_iterations):
        ciphertext = aes_gcm.encrypt(nonce, data, None)
    end_time = time.perf_counter()
    encrypt_throughput = ((size_bytes * num_iterations) / (1024*1024)) / (end_time - start_time)
    
    # Decrypt
    start_time = time.perf_counter()
    for _ in range(num_iterations):
        aes_gcm.decrypt(nonce, ciphertext, None)
    end_time = time.perf_counter()
    decrypt_throughput = ((size_bytes * num_iterations) / (1024*1024)) / (end_time - start_time)
    
    symmetric_results.append({
        "Algorithm": "AES", "Key Size": key_size_bits, "Mode": "GCM",
        "Data Size": data_name, "Encrypt (MB/s)": encrypt_throughput
    })

def benchmark_chacha20(data, data_name):
    size_bytes = len(data)
    num_iterations = get_iterations(size_bytes)
    print(f"Testing: ChaCha20-Poly1305 ({data_name})")
    
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    
    # Encrypt
    start_time = time.perf_counter()
    for _ in range(num_iterations):
        ciphertext = chacha.encrypt(nonce, data, None)
    end_time = time.perf_counter()
    encrypt_throughput = ((size_bytes * num_iterations) / (1024*1024)) / (end_time - start_time)
    
    # Decrypt
    start_time = time.perf_counter()
    for _ in range(num_iterations):
        chacha.decrypt(nonce, ciphertext, None)
    end_time = time.perf_counter()
    decrypt_throughput = ((size_bytes * num_iterations) / (1024*1024)) / (end_time - start_time)
    
    symmetric_results.append({
        "Algorithm": "ChaCha20", "Key Size": 256, "Mode": "Poly1305",
        "Data Size": data_name, "Encrypt (MB/s)": encrypt_throughput
    })

# --- Run ---
for name, data in test_data.items():
    benchmark_aes_gcm(data, name, 128)
    benchmark_aes_gcm(data, name, 256)
    benchmark_chacha20(data, name)

# --- Save ---
df = pd.DataFrame(symmetric_results)
df.to_csv(os.path.join(RESULTS_FOLDER, "symmetric_benchmark_results.csv"), index=False)
print("\n✅ Enhanced Symmetric results saved.")