import secrets
from budget_book import RustEncryptor
from mfence import PyVaultType

e = RustEncryptor(test=True)
key = secrets.token_bytes(32)
vt = PyVaultType.chacha_key
nonce = secrets.token_bytes(24)
plaintext = b"Praise the Fool!!!"

vt2 = PyVaultType("EncryptWith")
vt3 = PyVaultType("StoreHere")

e.add_secret(vt, key)
e.add_secret(vt2, key)

n, ciphertext = e.encrypt_chacha(plaintext, nonce)

print(n)
print(len(n))
print(ciphertext)
print(len(ciphertext))

pl = e.decrypt_chacha(ciphertext, n, vt)

print(pl.decode())

no, cipher = e.encrypt_key_chacha(vt2, vt3, vt)

plain_key = e.decrypt_chacha(cipher, no, vt)

retrieved = e.get_secret(vt3)
no_ret = retrieved[:24]
cipher_ret = retrieved[24:]

print(cipher == cipher_ret)

de_ret = e.decrypt_chacha(cipher_ret, no_ret, vt)
print(plain_key == key == de_ret)


