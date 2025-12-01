import pandas as pd
import matplotlib.pyplot as plt
import os

RESULTS_FOLDER = os.path.join(os.getcwd(), "results")
SYM_CSV = os.path.join(RESULTS_FOLDER, "symmetric_benchmark_results.csv")
ASYM_CSV = os.path.join(RESULTS_FOLDER, "asymmetric_benchmark_results.csv")

print("Generating charts...")

# Symmetric Chart
if os.path.exists(SYM_CSV):
    df = pd.read_csv(SYM_CSV)
    # Pivot for grouping: Index=Data Size, Columns=Algorithm
    try:
        df_pivot = df.pivot_table(index='Data Size', columns=['Algorithm', 'Key Size'], values='Encrypt (MB/s)')
        # Reorder manually if possible
        df_pivot = df_pivot.reindex(['1KB', '1MB', '100MB'])
        
        ax = df_pivot.plot(kind='bar', logy=True, figsize=(10,6))
        plt.title('Encryption Throughput (Higher is Better)')
        plt.ylabel('MB/s (Log Scale)')
        plt.tight_layout()
        plt.savefig(os.path.join(RESULTS_FOLDER, "chart_symmetric.png"))
        print(" -> Created chart_symmetric.png")
    except Exception as e:
        print(f"Skipping symmetric chart: {e}")

# Asymmetric Chart (Key Gen Time)
if os.path.exists(ASYM_CSV):
    df = pd.read_csv(ASYM_CSV)
    df.plot(kind='bar', x='Key', y='Key Gen (s)', color='orange', figsize=(8,5))
    plt.title('Key Generation Time (Lower is Better)')
    plt.ylabel('Seconds')
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_FOLDER, "chart_asymmetric_keygen.png"))
    print(" -> Created chart_asymmetric_keygen.png")

print("Visualization complete.")