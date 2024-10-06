import os
import hashlib
from argon2 import PasswordHasher, exceptions
from datetime import datetime, timedelta
import time

# Global constants for password complexity
MIN_PASSWORD_LENGTH = 8
MIN_UPPERCASE_CHARS = 1
MIN_DIGITS = 1
KEY_ROTATION_INTERVAL_DAYS = 30  # Rotate keys every 30 days

# Function to generate a cryptographically secure random salt
def generate_salt(length=16):
    return os.urandom(length)

# Function to hash the password with SHA-256 and a salt
def hash_with_sha256(password, salt):
    salted_password = password.encode() + salt
    sha256_hash = hashlib.sha256(salted_password).digest()
    return sha256_hash

# Function to hash the SHA-256 result with Argon2id parameters iteratively
def hash_with_argon2id_iterative(sha256_hash, iterations=1, time_cost=4, memory_cost=16384, parallelism=2):
    ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)
    argon2id_hash = sha256_hash.hex()
    for _ in range(iterations):
        argon2id_hash = ph.hash(argon2id_hash)
    return argon2id_hash

# Function to check if password meets complexity requirements
def check_password_complexity(password):
    errors = []

    # Check minimum length
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")

    # Check for uppercase letters
    if sum(1 for c in password if c.isupper()) < MIN_UPPERCASE_CHARS:
        errors.append(f"Password must contain at least {MIN_UPPERCASE_CHARS} uppercase letter(s).")

    # Check for digits
    if sum(1 for c in password if c.isdigit()) < MIN_DIGITS:
        errors.append(f"Password must contain at least {MIN_DIGITS} digit(s).")

    return errors

# Combined function to hash the password using both SHA-256 and Argon2id iteratively
def combined_hash_password(password, salt, iterations=1, time_cost=4, memory_cost=16384, parallelism=2):
    start_time = time.time()
    sha256_hash = hash_with_sha256(password, salt)
    argon2id_hash = hash_with_argon2id_iterative(sha256_hash, iterations, time_cost, memory_cost, parallelism)
    execution_time = time.time() - start_time

    # Calculating space complexity
    # SHA-256 space complexity is O(1)
    sha256_space_complexity = 32  # Size of SHA-256 output in bytes
    # Argon2id space complexity is approximately O(p * m), where p is parallelism and m is memory cost
    argon2id_space_complexity = parallelism * memory_cost

    return argon2id_hash, execution_time, sha256_space_complexity, argon2id_space_complexity

# Function to verify the password using the combined hashing approach
def combined_verify_password(stored_hash, password, salt, iterations=1, time_cost=4, memory_cost=16384, parallelism=2):
    start_time = time.time()
    sha256_hash = hash_with_sha256(password, salt)
    ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)
    try:
        is_valid = ph.verify(stored_hash, sha256_hash.hex()) and check_password_complexity(password) == []
    except exceptions.VerifyMismatchError:
        is_valid = False
    verification_time = time.time() - start_time

    # Calculating space complexity
    # SHA-256 space complexity is O(1)
    sha256_space_complexity = 32  # Size of SHA-256 output in bytes
    # Argon2id space complexity is approximately O(p * m), where p is parallelism and m is memory cost
    argon2id_space_complexity = parallelism * memory_cost

    return is_valid, verification_time, sha256_space_complexity, argon2id_space_complexity

# Function to check if key rotation is needed
def is_key_rotation_needed(last_rotation_date):
    return (datetime.now() - last_rotation_date).days >= KEY_ROTATION_INTERVAL_DAYS

# Function to update salts and rehash passwords if key rotation is needed
def rotate_keys(username, stored_hash, salt, password):
    new_salt = generate_salt()
    new_combined_hashed_password, _, _, _ = combined_hash_password(password, new_salt)
    # Update storage with new hash and salt (in real-world, update the database)
    return new_combined_hashed_password, new_salt

# Prompting for user input and demonstrating password hashing and verification
if __name__ == "__main__":
    last_rotation_date = datetime.now() - timedelta(days=KEY_ROTATION_INTERVAL_DAYS + 1)  # Simulating last rotation date

    while True:
        # Prompt user for username and password
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        # Validate password complexity
        complexity_errors = check_password_complexity(password)
        if complexity_errors:
            print("\nPassword complexity errors:")
            for error in complexity_errors:
                print("-", error)
            continue

        # Generate a random salt
        salt = generate_salt()

        # Hash the password using the combined method and measure execution time
        combined_hashed_password, hashing_time, sha256_space, argon2id_space = combined_hash_password(password, salt)

        # Store the hash and salt (in real-world, store securely like in a database)
        print("\nStored Combined Hash:", combined_hashed_password)
        print("Stored Salt:", salt.hex())
        print("Hashing Time:", hashing_time, "seconds")
        print("SHA-256 Space Complexity:", sha256_space, "bytes")
        print("Argon2id Space Complexity:", argon2id_space, "bytes")

        # Simulate successful login
        print("\nSimulating successful login...")

        # Verify the password using the combined method and measure execution time
        entered_password = input("\nEnter the password again to verify: ")
        verification_result, verification_time, _, _ = combined_verify_password(combined_hashed_password, entered_password, salt)

        if verification_result:
            print("Password verification successful!")
            
            # Check if key rotation is needed
            if is_key_rotation_needed(last_rotation_date):
                print("\nKey rotation needed. Rotating keys...")
                combined_hashed_password, salt = rotate_keys(username, combined_hashed_password, salt, password)
                last_rotation_date = datetime.now()
                print("New Combined Hash:", combined_hashed_password)
                print("New Salt:", salt.hex())
                print("Keys rotated successfully.")
            
            break
        else:
            print("Password verification failed.")

        print("Verification Time:", verification_time, "seconds")
