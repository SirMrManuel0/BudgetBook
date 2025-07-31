from mfence import Encryptor
import base64
import secrets
from argon2.low_level import hash_secret_raw, Type
import os
import hmac

def argon2id_hash(password: bytes):
    hash_len = 64
    t_cost = 3        # iterations
    p_cost = 3        # parallelism
    m_cost = 65536    # memory cost in KiB (64 MiB)
    salt_len = 16

    salt = os.urandom(salt_len)

    hash_bytes = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=p_cost,
        hash_len=hash_len,
        type=Type.ID
    )

    return hash_bytes

def byte_to_b64(byte_data: bytes) -> str:
        """Convert bytes to a Base64 string."""
        return base64.b64encode(byte_data).decode('ascii')
def byte_to_utf(byte_data: bytes) -> str:
        """Convert bytes to a UTF-8 string."""
        return byte_data.decode('utf-8')

#e = Encryptor(True)
#print(base64.b64encode(Encryptor.hash_pw(b"hallo", 32)[-32:]).decode('ascii'))

""" from datetime import datetime

its = 100
print("========== Rust ==========")
start = datetime.now()

for _ in range(its):
    print(Encryptor.hash_pw(b"hallo", 64, None))

end = datetime.now()

elapsed_rust = end - start
print(f"Time taken: {elapsed_rust.total_seconds()} seconds.")
print(f"Average Time: {elapsed_rust.total_seconds()/its} seconds.")

print("========== Python ==========")

start = datetime.now()

for _ in range(its):
    print(base64.b64encode(argon2id_hash(b"hallo")).decode('ascii'))

end = datetime.now()

elapsed_python = end - start
print(f"Time taken: {elapsed_python.total_seconds()} seconds.")
print(f"Average Time: {elapsed_python.total_seconds()/its} seconds.")

print("========== Python vs Rust ==========")

print(f"Rust Total: {elapsed_rust.total_seconds()}")
print(f"Python Total: {elapsed_python.total_seconds()}")
print(f"Difference (Python - Rust): {elapsed_python.total_seconds() - elapsed_rust.total_seconds()}")

print(f"Rust Average: {elapsed_rust.total_seconds() / its}")
print(f"Python Average: {elapsed_python.total_seconds() / its}")
print(f"Difference (Python - Rust): {elapsed_python.total_seconds() / its - elapsed_rust.total_seconds() / its}") """


print()
print("========== Check Encryption / Decryption with XChaCha20 Poly1305 ==========")

key = secrets.token_bytes(32)
plain = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111".encode()

nonce, cipher = Encryptor.encrypt_chacha(key, plain, None, None)
print(f"Nonce: {byte_to_b64(nonce)}\nKey: {byte_to_b64(key)}\nCipher: {byte_to_b64(cipher)}")
print()

decrypted = Encryptor.decrypt_chacha(key, cipher, nonce, None)

diff = ""

for a in range(len(decrypted)):
    if a > len(plain):
        diff += decrypted[a]
        continue
    if plain[a] != decrypted[a]:
        diff += decrypted[a]
    else:
        diff += "_"

while len(diff) < len(plain):
    diff += plain[len(diff)]

print(f"Decrpyted:  {byte_to_utf(decrypted)}")
print(f"Original:   {byte_to_utf(plain)}")
print(f"Difference: {diff}")

