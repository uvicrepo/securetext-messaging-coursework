import hashlib
import os
import time
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker


def hash_password_pbkdf2(password, salt=None, iterations=600000):
    """Hash password using PBKDF2 with SHA-256."""
    if salt is None:
        salt = os.urandom(32)  # 32 bytes = 256 bits
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)

    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations,
        dklen=32
    )
    return salt.hex(), password_hash.hex(), iterations


def verify_password_pbkdf2(password, stored_salt, stored_hash, iterations):
    """Verify password against PBKDF2 hash."""
    _, new_hash, _ = hash_password_pbkdf2(password, stored_salt, iterations)
    return new_hash == stored_hash


# --- Hash a password ---
print("=== PBKDF2 Password Hashing ===")
password = "SuperSecure123!"
salt, hash_value, iterations = hash_password_pbkdf2(password)
print(f"Password:   {password}")
print(f"Salt:       {salt}")
print(f"Hash:       {hash_value}")
print(f"Iterations: {iterations:,}")

print("\n=== Verification ===")
is_valid = verify_password_pbkdf2(password, salt, hash_value, iterations)
print(f"Password valid? {is_valid}")

# --- Speed comparison ---
print("\n=== Speed Comparison ===")
test_password = "test123"

runs = 100

start = time.perf_counter()
for _ in range(runs):
    hashlib.sha256(test_password.encode()).hexdigest()
sha256_time = time.perf_counter() - start

start = time.perf_counter()
for _ in range(runs):
    hash_password_pbkdf2(test_password)
pbkdf2_time = time.perf_counter() - start

print(f"100 SHA-256 hashes: {sha256_time:.4f} seconds")
print(f"100 PBKDF2 hashes:  {pbkdf2_time:.3f} seconds")
print(f"PBKDF2 is {pbkdf2_time / sha256_time:.1f}x slower")

# --- Benchmark PBKDF2 at increasing iteration counts ---
print("\n=== Timing across iteration counts ===")
iteration_counts = [100_000, 200_000, 300_000, 400_000, 500_000, 600_000]
pbkdf2_times_ms = []

for iters in iteration_counts:
    start = time.perf_counter()
    hash_password_pbkdf2(test_password, iterations=iters)
    elapsed = (time.perf_counter() - start) * 1000
    pbkdf2_times_ms.append(elapsed)
    print(f"  {iters:>7,} iterations: {elapsed:.1f} ms")

sha256_single_ms = (sha256_time / runs) * 1000

# --- Chart ---
PBKDF2_COLOR = "#c0641a"
SHA_COLOR    = "#3a7ebf"

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle("SHA-256 vs PBKDF2: the cost of iterations", fontsize=14, fontweight="bold")

# Left panel: time per iteration count
labels = [f"{i // 1000}k" for i in iteration_counts]
ax1.bar(labels, pbkdf2_times_ms, color=PBKDF2_COLOR, alpha=0.85, label="PBKDF2", zorder=3)
ax1.axhline(sha256_single_ms, color=SHA_COLOR, linewidth=1.8, linestyle="--",
            label=f"SHA-256 ({sha256_single_ms:.4f} ms)", zorder=4)
ax1.set_yscale("log")
ax1.set_xlabel("iterations", fontsize=11)
ax1.set_ylabel("time (ms, log scale)", fontsize=11)
ax1.set_title("Time to hash one password", fontsize=11)
ax1.legend(fontsize=10)
ax1.grid(axis="y", linestyle=":", alpha=0.5, zorder=0)
ax1.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{v:g} ms"))

for label, ms in zip(labels, pbkdf2_times_ms):
    ax1.text(label, ms * 1.15, f"{ms:.0f} ms", ha="center", va="bottom", fontsize=9, color=PBKDF2_COLOR)

# Right panel: line chart showing time vs iteration count (linear relationship)
x_labels = [f"{i // 1000}k" for i in iteration_counts]

ax2.plot(x_labels, pbkdf2_times_ms, color=PBKDF2_COLOR, linewidth=2.5,
        marker="o", markersize=7, label="PBKDF2", zorder=3)
ax2.set_xlabel("iterations", fontsize=11)
ax2.set_ylabel("time (ms)", fontsize=11)
ax2.set_title("Time vs iteration count", fontsize=11)
ax2.legend(fontsize=10)
ax2.grid(axis="y", linestyle=":", alpha=0.5, zorder=0)
ax2.set_ylim(0, max(pbkdf2_times_ms) * 1.2)

for label, ms in zip(x_labels, pbkdf2_times_ms):
    ax2.text(label, ms + 5, f"{ms:.0f} ms", ha="center", va="bottom", fontsize=9, color=PBKDF2_COLOR)

plt.tight_layout()
plt.savefig("pbkdf2_comparison.png", dpi=150, bbox_inches="tight")
print("\nChart saved to pbkdf2_comparison.png")
plt.show()