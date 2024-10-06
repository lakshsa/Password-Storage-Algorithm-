import hashlib
import time

# Function to hash a password using SHA-1
def sha1_hash_password(password):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(password.encode('utf-8'))
    return sha1_hash.hexdigest()

# Example passwords with prompts for complexity levels
passwords = [
    ("Simple", "password1"),
    ("Moderate", "P@ssw0rd2"),
    ("Complex", "Str0ngP@$$"),
    ("Advanced", "C0mp13xP@$$!"),
    ("Highly Advanced", "MyP@ssw0rd!2023"),
    ("Basic", "abcdef123"),
    ("Intermediate", "!@#QWEasd"),
    ("Intricate", "987654!@#"),
    ("Advanced Complex", "p@$$w0rd!2023"),
    ("Sophisticated Complex", "qwerty123456!@#$")
]

# Test each password and measure execution time
results = []
for complexity, password in passwords:
    start_time = time.time()
    hashed_password = sha1_hash_password(password)
    end_time = time.time()
    execution_time = end_time - start_time
    results.append((complexity, password, hashed_password, execution_time))

# Print results with prompts for complexity levels
for result in results:
    print(f"Password: {result[1]}\nComplexity Level: {result[0]}\nSHA-1 Hash: {result[2]}\nExecution Time: {result[3]:.6f} seconds\n")
