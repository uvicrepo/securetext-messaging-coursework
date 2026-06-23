import hashlib
import os
import time
from securetext_salted import hash_password

def format_time(seconds):
    if seconds < 60:                return f"{seconds:.2f} sec"
    elif seconds < 3600:            return f"{seconds/60:.2f} min"
    elif seconds < 86400:           return f"{seconds/3600:.2f} hrs"
    elif seconds < 31_536_000:      return f"{seconds/86400:.2f} days"
    yrs = seconds / 31_536_000
    if yrs < 1_000:                 return f"{yrs:.2f} yrs"
    elif yrs < 1_000_000:           return f"{yrs/1_000:.2f}K yrs"
    elif yrs < 1_000_000_000:       return f"{yrs/1_000_000:.2f}M yrs"
    elif yrs < 1_000_000_000_000:   return f"{yrs/1_000_000_000:.2f}B yrs"
    else:                           return f"{yrs/1_000_000_000_000:.2f}T yrs"


DICTIONARY = [
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "dragon", "sunshine", "qwerty",
    "alice123", "bob123", "mallory123", "abc123", "iloveyou"
]

TARGET_PASSWORD = "mallory123"


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

def salted_sha256(text, salt):
    return hashlib.sha256((salt + text).encode()).hexdigest()


# Stored databases
unsalted_db = {
    "Alice":   sha256("alice123"),
    "Bob":     sha256("bob123"),
    "Mallory": sha256("mallory123"),
}

salted_db = {
    "Alice":   {"salt": "x9k2", "hash": salted_sha256("alice123",   "x9k2")},
    "Bob":     {"salt": "m7p1", "hash": salted_sha256("bob123",     "m7p1")},
    "Mallory": {"salt": "q3r8", "hash": salted_sha256("mallory123", "q3r8")},
}


# DICTIONARY ATTACK — UNSALTED
print("=== Dictionary Attack: Unsalted SHA-256 ===\n")
print("Stored hashes:")
for user, h in unsalted_db.items():
    print(f"  {user}: {h}")

print("\nAttacking...")
for word in DICTIONARY:
    candidate = sha256(word)
    for user, h in unsalted_db.items():
        if candidate == h:
            print(f"  MATCH: {user}: '{word}' -> {candidate}")


# DICTIONARY ATTACK — SALTED
print("\n=== Dictionary Attack: Salted SHA-256 ===\n")
print("Stored hashes:")
for user, data in salted_db.items():
    print(f"  {user}: {data['hash']}")

print("\nAttacking (attacker has no knowledge of salts)...")
matched = 0
for word in DICTIONARY:
    candidate = sha256(word)
    for user, data in salted_db.items():
        if candidate == data["hash"]:
            print(f"  MATCH: {user}: '{word}'")
            matched += 1

if matched == 0:
    print("  No matches found.")


# HASH RATE
print("\n=== Hash Rate ===\n")

runs = 10_000
start = time.perf_counter()
for _ in range(runs):
    sha256(TARGET_PASSWORD)
sha256_per_sec = runs / (time.perf_counter() - start)

start = time.perf_counter()
hash_password(TARGET_PASSWORD)
pbkdf2_per_sec = 1 / (time.perf_counter() - start)

print(f"  SHA-256: {sha256_per_sec:>15,.0f} hashes/sec")
print(f"  PBKDF2:  {pbkdf2_per_sec:>15.2f} hashes/sec")


# DICTIONARY ATTACK TIMING
print("\n=== Dictionary Attack: Time to Crack ===\n")

target_hash = sha256(TARGET_PASSWORD)
start = time.perf_counter()
for word in DICTIONARY:
    if sha256(word) == target_hash:
        break
sha256_dict_time = time.perf_counter() - start
print(f"  SHA-256: {sha256_dict_time * 1000:.4f} ms")

target_salt, target_hash_pbkdf2 = hash_password(TARGET_PASSWORD)
start = time.perf_counter()
for word in DICTIONARY:
    _, candidate = hash_password(word, salt=target_salt)
    if candidate == target_hash_pbkdf2:
        break
pbkdf2_dict_time = time.perf_counter() - start
print(f"  PBKDF2:  {pbkdf2_dict_time * 1000:.1f} ms")


# BRUTE FORCE TIMING (theoretical)
print("\n=== Brute Force: Theoretical Time to Exhaust Keyspace ===\n")
print(f"  {'Length':<10} {'Combinations':>20} {'SHA-256':>20} {'PBKDF2':>20}")
print(f"  {'-'*10} {'-'*20} {'-'*20} {'-'*20}")

charset = 62
for length in [4, 6, 8, 10, 12]:
    combos = charset ** length
    print(f"  {length:<10} {combos:>20,} {format_time(combos / sha256_per_sec):>20} {format_time(combos / pbkdf2_per_sec):>20}")