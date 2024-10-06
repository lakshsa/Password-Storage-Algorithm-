# Password Hashing Algorithm: SHA-256 and Argon2id Combination

## Introduction

Password security is an essential aspect of modern computing systems, especially with the increasing frequency of data breaches and cyber-attacks. A strong and secure password hashing system is crucial for ensuring that user credentials are protected, even if the underlying system is compromised. Traditional password hashing algorithms like **MD5** and **SHA-1** were once considered secure but have since been proven vulnerable to modern cryptographic attacks, such as collision and rainbow table attacks. These vulnerabilities necessitated the development of more secure hashing methods, such as **SHA-256** and **Argon2id**.

This repository implements an enhanced password hashing algorithm that combines **SHA-256** and **Argon2id** to leverage the benefits of both. The result is a highly secure hashing process that is resistant to brute-force, dictionary, and rainbow table attacks. This repository also includes a comparative analysis of legacy algorithms, such as MD5 and SHA-1, to demonstrate how the enhanced method significantly improves security.

## Overview of Password Hashing

Password hashing is a one-way cryptographic process that transforms a password into a fixed-size hash value. Once hashed, it is computationally infeasible to reverse the process and retrieve the original password. The key idea is that even if the hashed value is stolen, the attacker will not be able to easily recover the original password.

There are several common hashing algorithms, but not all of them are equally secure. For instance:
- **MD5**: This algorithm produces a 128-bit hash value and was once widely used for password hashing. However, MD5 is now considered broken because it is vulnerable to collision attacks, where two different inputs produce the same hash.
- **SHA-1**: An improvement over MD5, SHA-1 produces a 160-bit hash value. Despite its initial robustness, SHA-1 has also been found vulnerable to collision attacks. Major browsers and institutions have deprecated its use.
- **SHA-256**: Part of the SHA-2 family, SHA-256 produces a 256-bit hash value, making it much more secure against collision attacks. It is widely used in modern security protocols such as TLS and SSL.
- **Argon2id**: Argon2id is a state-of-the-art password hashing algorithm designed to be memory-hard, meaning that it requires a significant amount of memory to compute. This characteristic makes it highly resistant to brute-force and side-channel attacks, which use specialized hardware (such as GPUs) to crack passwords.

The enhanced password hashing method implemented in this project combines **SHA-256** for initial hashing with **Argon2id** for iterative, memory-hard processing, resulting in an even more secure approach to password storage.

## Features of the Enhanced Algorithm

The combined SHA-256 and Argon2id algorithm offers the following key features:

1. **SHA-256 Hashing**: SHA-256 is a cryptographic hash function that transforms the input password into a 256-bit hash. By itself, SHA-256 is highly secure and resistant to collision attacks, but in this project, it serves as the first step in the password hashing process.

2. **Argon2id**: Argon2id is the winner of the Password Hashing Competition (PHC) in 2015 and is designed to be secure against both GPU and side-channel attacks. It combines the advantages of Argon2i (optimized for resistance to side-channel attacks) and Argon2d (optimized for resistance to GPU attacks). By incorporating Argon2id after SHA-256 hashing, the resulting hash is much more secure and resistant to a wide range of attacks.

3. **Salting**: A salt is a randomly generated string of bytes that is added to the password before hashing. The use of salts ensures that even if two users have the same password, their hashed values will be different, making it impossible for an attacker to use precomputed hash tables (rainbow tables) to crack the passwords.

4. **Iterative Hashing**: Argon2id allows for dynamic adjustment of time and memory costs, meaning that the number of iterations and the amount of memory required to compute the hash can be increased as needed to keep up with advances in computing power. This makes it more difficult for attackers to crack passwords using brute-force methods.

5. **Password Complexity Checking**: The algorithm ensures that passwords meet a minimum complexity threshold, including length, uppercase characters, and digits. This helps prevent users from choosing weak passwords that are easily guessable or vulnerable to dictionary attacks.

## Requirements

To run the project, you need **Python 3.x** and the following Python libraries:

- `argon2-cffi`: This is a Python library for Argon2 password hashing. It provides an easy-to-use interface for implementing Argon2id in Python programs.
- `pytest`: This is a testing framework for Python that allows you to write simple test cases to ensure that the code works as expected.

You can install all dependencies by running the following command:

```bash
pip install -r requirements.txt
