import hashlib
import time

# Function to hash a password using MD5
def md5_hash_password(password):
    md5_hash = hashlib.md5()
    md5_hash.update(password.encode('utf-8'))
    return md5_hash.hexdigest()

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
    hashed_password = md5_hash_password(password)
    end_time = time.time()
    execution_time = end_time - start_time
    results.append((complexity, password, hashed_password, execution_time))

# Print results with prompts for complexity levels
for result in results:
    print(f"Password: {result[1]}\nComplexity Level: {result[0]}\nMD5 Hash: {result[2]}\nExecution Time: {result[3]:.6f} seconds\n")
clwea