# --- Benchmark Visualization Script (Fixed for macOS) ---

import pandas as pd
import matplotlib
# CRITICAL FIX: Use the 'Agg' backend to prevent macOS window crashes
matplotlib.use('Agg') 
import matplotlib.pyplot as plt
import os
import sys

# --- Setup Paths ---
SCRIPT_DIRECTORY = os.getcwd()
RESULTS_FOLDER = os.path.join(SCRIPT_DIRECTORY, "results")
SYMMETRIC_CSV = os.path.join(RESULTS_FOLDER, "symmetric_benchmark_results.csv")
ASYMMETRIC_CSV = os.path.join(RESULTS_FOLDER, "asymmetric_benchmark_results.csv")

print("Starting visualization script...")
if not os.path.exists(RESULTS_FOLDER):
    print(f"Error: 'results' folder not found at {RESULTS_FOLDER}", file=sys.stderr)
    sys.exit(1)

def plot_symmetric_results(filepath):
    """Plots the symmetric benchmark results."""
    print(f"Plotting symmetric results from {filepath}...")
    try:
        df = pd.read_csv(filepath)
    except FileNotFoundError:
        print(f"Error: Could not find {filepath}", file=sys.stderr)
        return

    # Pivot table logic
    try:
        # Check if 'Key Size' exists to determine pivot columns
        if 'Key Size' in df.columns:
            pivot_cols = ['Algorithm', 'Key Size', 'Mode']
        else:
            pivot_cols = ['Algorithm', 'Mode']

        df_pivot = df.pivot_table(index='Data Size', 
                                  columns=pivot_cols, 
                                  values='Encrypt (MB/s)')
        
        # Re-order logic
        existing_labels = [l for l in ['1KB', '1MB', '100MB'] if l in df_pivot.index]
        if existing_labels:
            df_pivot = df_pivot.reindex(existing_labels)

        # Plot
        ax = df_pivot.plot(kind='bar',
                             title='Symmetric Encrypt Throughput (Higher is Better)',
                             figsize=(12, 7),
                             rot=0,
                             grid=True)
        ax.set_ylabel('Throughput (MB/s) - Log Scale')
        ax.set_xlabel('Data Size')
        ax.set_yscale('log')
        ax.legend(title='Algorithm', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        
        save_path = os.path.join(RESULTS_FOLDER, 'symmetric_encrypt_throughput.png')
        plt.savefig(save_path)
        print(f"  -> Saved chart to: {save_path}")
        plt.close() # Close memory to prevent leaks
    except Exception as e:
        print(f"Failed to plot symmetric results: {e}")

def plot_asymmetric_results(filepath):
    """Plots the asymmetric benchmark results."""
    print(f"Plotting asymmetric results from {filepath}...")
    try:
        df = pd.read_csv(filepath)
    except FileNotFoundError:
        print(f"Error: Could not find {filepath}", file=sys.stderr)
        return

    try:
        # Plot 1: Key Gen Time
        plt.figure() # New figure
        # Simple bar plot
        colors = ['#3b82f6' if 'RSA' in k else '#22c55e' for k in df['Key']]
        plt.bar(df['Key'], df['Key Gen (s)'], color=colors)
        plt.title('Asymmetric Key Generation Time (Lower is Better)')
        plt.ylabel('Time (seconds)')
        plt.xlabel('Key Type')
        plt.xticks(rotation=15)
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        
        save_path = os.path.join(RESULTS_FOLDER, 'asymmetric_key_gen_time.png')
        plt.savefig(save_path)
        print(f"  -> Saved chart to: {save_path}")
        plt.close()

        # Plot 2: Sign/Verify Time (Grouped Bar)
        ax = df.plot(kind='bar', x='Key', y=['Sign (s)', 'Verify (s)'],
                title='Asymmetric Sign & Verify Time (Lower is Better)',
                figsize=(10, 6),
                rot=15,
                grid=True)
        plt.ylabel('Time (seconds)')
        plt.xlabel('Key Type')
        plt.tight_layout()
        
        save_path = os.path.join(RESULTS_FOLDER, 'asymmetric_sign_verify_time.png')
        plt.savefig(save_path)
        print(f"  -> Saved chart to: {save_path}")
        plt.close()
        
        # Plot 3: Memory (if column exists)
        if 'Key Gen Peak (KiB)' in df.columns:
            plt.figure()
            plt.bar(df['Key'], df['Key Gen Peak (KiB)'], color=colors)
            plt.title('Asymmetric Key Gen Peak Memory (Lower is Better)')
            plt.ylabel('Peak Memory (KiB)')
            plt.xlabel('Key Type')
            plt.xticks(rotation=15)
            plt.grid(axis='y', alpha=0.3)
            plt.tight_layout()
            
            save_path = os.path.join(RESULTS_FOLDER, 'asymmetric_key_gen_memory.png')
            plt.savefig(save_path)
            print(f"  -> Saved chart to: {save_path}")
            plt.close()
    except Exception as e:
        print(f"Failed to plot asymmetric results: {e}")


# --- Run Plots ---
if os.path.exists(SYMMETRIC_CSV):
    plot_symmetric_results(SYMMETRIC_CSV)
else:
    print(f"Skipping symmetric plots, file not found: {SYMMETRIC_CSV}")

if os.path.exists(ASYMMETRIC_CSV):
    plot_asymmetric_results(ASYMMETRIC_CSV)
else:
    print(f"Skipping asymmetric plots, file not found: {ASYMMETRIC_CSV}")

print("\nVisualization complete.")