import os
import time
import pandas as pd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import matplotlib.pyplot as plt
import sys
# pandas and os were imported in the cells above

# --- Setup Paths ---
SCRIPT_DIRECTORY = os.getcwd()
RESULTS_FOLDER = os.path.join(SCRIPT_DIRECTORY, "results")
SYMMETRIC_CSV = os.path.join(RESULTS_FOLDER, "symmetric_benchmark_results.csv")
ASYMMETRIC_CSV = os.path.join(RESULTS_FOLDER, "asymmetric_benchmark_results.csv")

print("Starting visualization script...")
if not os.path.exists(RESULTS_FOLDER):
    print(f"Error: 'results' folder not found at {RESULTS_FOLDER}", file=sys.stderr)
    # sys.exit(1) # We use 'return' or 'pass' in a notebook
else:
    def plot_symmetric_results(filepath):
        """Plots the symmetric benchmark results."""
        print(f"Plotting symmetric results from {filepath}...")
        try:
            df = pd.read_csv(filepath)
        except FileNotFoundError:
            print(f"Error: Could not find {filepath}. Run Cell 2 first.", file=sys.stderr)
            return

        # We need to pivot the data to make it easy to plot
        # Let's fix the pivot to handle the columns we have
        df_pivot = df.pivot_table(index='Data Size', 
                                  columns=['Algorithm', 'Key Size', 'Mode'], 
                                  values='Encrypt (MB/s)')
        
        # Re-order for a logical chart
        try:
            df_pivot = df_pivot.reindex(['1KB', '1MB', '100MB'])
        except KeyError:
            print("Warning: Not all data sizes (1KB, 1MB, 100MB) were found. Plotting as-is.")

        # --- Plot 1: Encrypt Throughput ---
        ax = df_pivot.plot(kind='bar',
                             title='Symmetric Encrypt Throughput (Higher is Better)',
                             figsize=(15, 8),
                             rot=0,
                             grid=True)
        ax.set_ylabel('Throughput (MB/s) - Log Scale')
        ax.set_xlabel('Data Size')
        ax.set_yscale('log') # Use log scale, 1KB and 100MB results are vastly different
        ax.legend(title='Algorithm', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        
        save_path = os.path.join(RESULTS_FOLDER, 'symmetric_encrypt_throughput.png')
        plt.savefig(save_path)
        print(f"  -> Saved chart to: {save_path}")
        plt.show() # Display the plot inline
        plt.close()

    def plot_asymmetric_results(filepath):
        """Plots the asymmetric benchmark results."""
        print(f"Plotting asymmetric results from {filepath}...")
        try:
            df = pd.read_csv(filepath)
        except FileNotFoundError:
            print(f"Error: Could not find {filepath}. Run Cell 3 first.", file=sys.stderr)
            return

        # --- Plot 1: Key Generation Time ---
        ax = df.plot(kind='bar', x='Key', y='Key Gen (s)',
                       title='Asymmetric Key Generation Time (Lower is Better)',
                       figsize=(10, 6),
                       rot=0,
                       grid=True)
        ax.set_ylabel('Time (seconds)')
        ax.set_xlabel('Key Type and Size')
        plt.tight_layout()
        
        save_path = os.path.join(RESULTS_FOLDER, 'asymmetric_key_gen_time.png')
        plt.savefig(save_path)
        print(f"  -> Saved chart to: {save_path}")
        plt.show() # Display the plot inline
        plt.close()

        # --- Plot 2: Sign & Verify Time ---
        df.plot(kind='bar', x='Key', y=['Sign (s)', 'Verify (s)'],
                title='Asymmetric Sign & Verify Time (Lower is Better)',
                figsize=(10, 6),
                rot=0,
                grid=True)
        plt.ylabel('Time (seconds)')
        plt.xlabel('Key Type and Size')
        plt.tight_layout()
        
        save_path = os.path.join(RESULTS_FOLDER, 'asymmetric_sign_verify_time.png')
        plt.savefig(save_path)
        print(f"  -> Saved chart to: {save_path}")
        plt.show() # Display the plot inline
        plt.close()
        
        # --- Plot 3: Key Generation Memory ---
        ax = df.plot(kind='bar', x='Key', y='Key Gen Peak (KiB)',
                       title='Asymmetric Key Gen Peak Memory (Lower is Better)',
                       figsize=(10, 6),
                       rot=0,
                       grid=True)
        ax.set_ylabel('Peak Memory (Kibibytes)')
        ax.set_xlabel('Key Type and Size')
        plt.tight_layout()
        
        save_path = os.path.join(RESULTS_FOLDER, 'asymmetric_key_gen_memory.png')
        plt.savefig(save_path)
        print(f"  -> Saved chart to: {save_path}")
        plt.show() # Display the plot inline
        plt.close()


    # --- Run Plots ---
    if os.path.exists(SYMMETRIC_CSV):
        plot_symmetric_results(SYMMETRIC_CSV)
    else:
        print(f"Skipping symmetric plots, file not found: {SYMMETRIC_CSV}")

    if os.path.exists(ASYMMETRIC_CSV):
        plot_asymmetric_results(ASYMMETRIC_CSV)
    else:
        print(f"Skipping asymmetric plots, file not found: {ASYMMETRIC_CSV}")

    print("\nVisualization complete. Check the 'results' folder for your .png charts.")