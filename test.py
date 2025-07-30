from mfence import Encryptor
import base64

from argon2.low_level import hash_secret_raw, Type
import os

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

#e = Encryptor(True)
#print(base64.b64encode(Encryptor.hash_pw(b"hallo", 32)[-32:]).decode('ascii'))

from datetime import datetime

its = 100
print("========== Rust ==========")
start = datetime.now()

for _ in range(its):
    print(base64.b64encode(Encryptor.hash_pw(b"hallo", 64)[-64:]).decode('ascii'))

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
print(f"Difference (Python - Rust): {elapsed_python.total_seconds() / its - elapsed_rust.total_seconds() / its}")
