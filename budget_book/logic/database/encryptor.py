import secrets
import base64
from pydoc import plaintext

import keyring
import hashlib

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from argon2 import PasswordHasher, exceptions
from argon2.low_level import hash_secret, Type
from typing import Iterable, Optional, Union, Literal

from pylix.errors import to_test

from budget_book import RustEncryptor, VaultType


class Converter:
    @classmethod
    def b64_to_utf(cls, b64: str) -> str:
        """Decode a base64-encoded string to a UTF-8 string."""
        decoded_bytes = base64.b64decode(b64)
        return decoded_bytes.decode('utf-8')

    @classmethod
    def utf_to_b64(cls, utf: str) -> str:
        """Encode a UTF-8 string to a Base64 string."""
        utf_bytes = utf.encode('utf-8')
        b64_bytes = base64.b64encode(utf_bytes)
        return b64_bytes.decode('ascii')

    @classmethod
    def hex_to_b64(cls, hex_: str) -> str:
        """Convert a hex string to a Base64 string."""
        raw_bytes = bytes.fromhex(hex_)
        b64_bytes = base64.b64encode(raw_bytes)
        return b64_bytes.decode('ascii')

    @classmethod
    def b64_to_hex(cls, b64: str) -> str:
        """Convert a Base64 string to a hex string."""
        raw_bytes = base64.b64decode(b64)
        return raw_bytes.hex()

    @classmethod
    def hex_to_byte(cls, hex_: str) -> bytes:
        """Convert a hex string to bytes."""
        return bytes.fromhex(hex_)

    @classmethod
    def byte_to_hex(cls, byte_data: bytes) -> str:
        """Convert bytes to a hex string."""
        return byte_data.hex()

    @classmethod
    def utf_to_byte(cls, utf: str) -> bytes:
        """Convert a UTF-8 string to bytes."""
        return utf.encode('utf-8')

    @classmethod
    def byte_to_utf(cls, byte_data: bytes) -> str:
        """Convert bytes to a UTF-8 string."""
        return byte_data.decode('utf-8')

    @classmethod
    def b64_to_byte(cls, b64: str) -> bytes:
        """Convert a Base64 string to bytes."""
        return base64.b64decode(b64 + "===")

    @classmethod
    def byte_to_b64(cls, byte_data: bytes) -> str:
        """Convert bytes to a Base64 string."""
        return base64.b64encode(byte_data).decode('ascii')

    @classmethod
    def int_to_b64(cls, value: int, signed: bool,
                   byteorder: Literal["little", "big"] = "big", length: Optional[int] = None) -> str:
        if length is None:
            length = (value.bit_length() + 7) // 8 or 1
        byte_data = value.to_bytes(length, byteorder=byteorder, signed=signed)
        return base64.b64encode(byte_data).decode('ascii')

    @classmethod
    def b64_to_int(cls, b64: str, signed: bool, byteorder: Literal["little", "big"] = "big") -> int:
        byte_data = base64.b64decode(b64 + "===")
        return int.from_bytes(byte_data, byteorder=byteorder, signed=signed)

    @classmethod
    def int_to_hex(cls, value: int) -> str:
        return hex(value)[2:]

    @classmethod
    def hex_to_int(cls, hex_: str) -> int:
        return int(hex_, 16)

    @classmethod
    def int_to_bytes(cls, value: int, signed: bool, length: int = None, byteorder: Literal["little", "big"] = 'big') -> bytes:
        """Convert an integer to bytes.

        If length is None, minimal bytes are used.
        """
        if length is None:
            length = (value.bit_length() + 7) // 8 or 1
        return value.to_bytes(length, byteorder=byteorder, signed=signed)

    @classmethod
    def bytes_to_int(cls, byte_data: bytes, signed: bool, byteorder: Literal["little", "big"] = 'big') -> int:
        """Convert bytes to an integer."""
        return int.from_bytes(byte_data, byteorder=byteorder, signed=signed)

class HashingAlgorithm:
    @classmethod
    def sha256(cls, data: bytes, _) -> bytes:
        hash_ = hashlib.sha256()
        hash_.update(data)
        return hash_.digest()

    @classmethod
    def sha512(cls, data: bytes, _) -> bytes:
        hash_ = hashlib.sha512()
        hash_.update(data)
        return hash_.digest()

    @classmethod
    def argon2id(cls, data: bytes, hash_: str) -> bool:
        ph = PasswordHasher()
        try:
            ph.verify(hash_, data)
            return True
        except exceptions.VerifyMismatchError:
            return False

class Encryptor:
    def __init__(self, test=False):
        """
        The encryptor of the database.

        :param test: If tests are programmed, the parameter test must be True.
        """
        self._test = test
        self._encryptor = RustEncryptor(test)
        self._set_system_key()

    def _access_encryptor(self) -> Optional[RustEncryptor]:
        if self._test:
            return self._encryptor
        return None

    def _set_system_key(self) -> None:
        key = None
        if not self._test:
            key = Converter.b64_to_byte(keyring.get_password("BudgetBook", "system_key"))
        else:
            # test key
            key = Converter.b64_to_byte("8pHtu2f1vbc4FEUgmENrMPhhXuAbHghtT3R3SLZyNV7zNIHGtKyBL4NxKAhe9mfwC64ZDBviuFBqKl"
                                        "WQp0PQ/0dg2CFrS4wPElL9itHhMy9lV4dMNocrQQ4pp2RFjBK4vQz+EN3JnbBbU560/TGIDNlwSJnW"
                                        "pb1ppqNBPxiPQ8TTdMjAQsFjB0pF+Yes3Wm+pZvqvpQkaPWl0Pzfu/+dT+8aYPUSR+khLanJtSMsqj"
                                        "jwbjhvMY4Q1LlAFqoycK0Y3WhUAQCBm9iguo4XaqYBEJZ4pJaRWfdnrgTSTL1ATnsbh3IYMaWvKRri"
                                        "V+dBkgC2Atk0g5liPgxTgFkHOfg8KA==")
        self._encryptor.add_secret(VaultType.system_key(), key)

    def add_secret(self, vt: VaultType, secret: bytes) -> None:
        self._encryptor.add_secret(vt, secret)

    def compare_with_secret(self, a: VaultType, b: bytes):
        self._encryptor.add_secret(VaultType("temp_comparer"), b, True)
        compared = self.compare_secret(a, VaultType("temp_comparer"))
        self._encryptor.remove_secret(VaultType("temp_comparer"))
        return compared

    def compare_secret(self, a: VaultType, b: VaultType):
        return self._encryptor.compare_secrets(a, b)

    def generate_username_key(self, username: bytes, secret_name: str, salt: Optional[bytes] = None) -> bytes:
        """
        This method is used to generate the key for the username (usernames are encrypted with themselves)

        :param secret_name: The secret_name must be known in order to access the username key.
        :param username: The username must be given as bytes
        :param salt: If this is not the first time, the salt of the first salt generation must be given as bytes
        :return: It returns the salt, with which the username key was derived
        """
        salt_ = secrets.token_bytes(16) if salt is None else salt
        self._encryptor.add_secret(VaultType("temp_username"), username, True)
        self._encryptor.derive_key(VaultType(secret_name), VaultType("temp_username"), salt_)
        self._encryptor.remove_secret(VaultType("temp_username"))
        return salt_

    def encrypt_username(self, de_username: bytes, secret_name: str, salt: Optional[bytes] = None, nonce: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
        """
        In order to encrypt the username it needs to be given together with the salt and nonce, if it is not the first time.

        :param secret_name: This is the name of the VaultType reference, under which the userkey will also be saved.
        :param salt: The salt must be given, if it is not the first time, as bytes
        :param de_username: The username must be given as bytes
        :param nonce: The nonce must be given, if it is not the first time, as bytes
        :return: It returns in the same order as bytes: the ciphertext, the nonce, the salt
        """
        salt_ = self.generate_username_key(username=de_username, secret_name=secret_name, salt=salt)
        nonce_ = nonce if nonce is not None else secrets.token_bytes(24)
        _, ciphertext = self._encryptor.encrypt_chacha(de_username, nonce_, key=VaultType(secret_name))

        return ciphertext, nonce_, salt_

    def decrypt_username(self, en_username: bytes, nonce: bytes, user_key: str) -> bytes:
        """
        This method is used to decrypt the username.


        :param en_username: The encrypted username must be given as bytes
        :param nonce: The nonce must be given as bytes
        :param user_key: This is the name of the VaultType reference which points to the userkey.
        :return: This function returns the username as bytes
        """
        plaintext = self._encryptor.decrypt_chacha(en_username, nonce, VaultType(user_key))
        return plaintext

    def encrypt_system_data(self, data: bytes, nonce: Optional[bytes] = None, aad_opt: Optional[bytes] = None) -> bytes:
        """
        All system datas are encrypted with this function.

        :param data: The data must be given as bytes
        :param nonce: The nonce must be given if it is not the first time. It must be given as bytes
        :param aad_opt: The aad is optional and can be given as bytes.
        If it is given during encryption, it MUST be given during decryption.
        :return: It returns the encrypted data as bytes.
        """
        nonce_ = secrets.token_bytes(24) if nonce is None else nonce
        self._encryptor.remove_secret(VaultType("temp_hashed_system_key"))
        self._encryptor.derive_key(VaultType("temp_hashed_system_key"), VaultType.system_key())
        _, ciphertext = self._encryptor.encrypt_chacha(data, nonce_, aad_opt, VaultType("temp_hashed_system_key"))
        self._encryptor.remove_secret(VaultType("temp_hashed_system_key"))
        return nonce_ + ciphertext

    def decrypt_system_data(self, en_data: bytes, nonce_len: int = 32) -> bytes:
        """
        This function decrypts system data which was encrypted with Encryptor.encrypt_system_data(data, nonce_len=32, nonce=None).

        :param en_data: The data needs to be given as bytes.
        :param nonce_len: The nonce_len is standardised at 32, but can be increased.
        :return: It returns the decrypted data as bytes
        """
        nonce_ = en_data[:nonce_len]
        data_and_tag = en_data[nonce_len:]
        key_ = self._get_system_key()
        hashed_key = hashlib.sha256()
        hashed_key.update(key_)
        hashed_key = hashed_key.digest()
        aes_gcm = AESGCM(hashed_key)
        plaintext = aes_gcm.decrypt(nonce_, data_and_tag, associated_data=None)
        return plaintext

    @classmethod
    def validate_hash(cls, data: bytes, hash_: Union[bytes, str], hashing_algo) -> bool:
        """
        In order to validate hashes use this function.

        :param data: The data (e.g. the password, the data) which was hashed.
        :param hash_: The hash. If it was not argon2id the hash should be given as bytes. If it is argon2id, it should be given as string.
        :param hashing_algo: To know how to validate the hash, pass the hashing algorithm from HashingAlgorithm. You need to pass the function. E.g. pass HashingAlgorithm.argon2id and not HashingAlgorithm.argon2id()
        :return: It returns True if it is the correct hash and False otherwise.
        """

        ret: Union[bytes, bool] = hashing_algo(data, hash_)
        if isinstance(ret, bytes):
            return ret == hash_
        else:
            return ret

    @classmethod
    def hash_pw(cls, pw: bytes, hash_len=64) -> str:
        """
        Passwords given into this function are hashed with argon2id.

        :param pw: The password needs to given as bytes
        :param hash_len: The length of the hash is standardised at 64 bytes, but can vary.
        :return: The function returns the hash as utf-8 string.
        """
        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=3, hash_len=hash_len)
        return ph.hash(pw)

    @classmethod
    def recreate_hash(cls, pw: bytes, salt: bytes,
                      time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 3, hash_len: int = 64) -> str:
        """
        In order to recreate an argon2id hash you need to pass the password and salt as bytes. The hash_len needs to be correct. The rest can be changed, but should not.

        :param pw: The password needs to be passed as bytes.
        :param salt: The salt needs to be passed as bytes.
        :param time_cost: default 3, can vary
        :param memory_cost: default 65536, can vary
        :param parallelism: default 3, can vary
        :param hash_len: default 64 bytes, can vary
        :return: It returns the hash as string.
        """
        return hash_secret(
            secret=pw,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Type.ID,
        ).decode()

    @classmethod
    def create_private_key(cls) -> RSAPrivateKey:
        """
        This function creates the private key.

        :return: It is returned as RSAPrivateKey
        """
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    @classmethod
    def serialize_private_key(cls, private_key: RSAPrivateKey) -> bytes:
        """
        The private key needs to be serialized in order for it to be converted to bytes.

        :param private_key: The private key as RSAPrivateKey
        :return: The private key as bytes
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @classmethod
    def deserialize_private_key(cls, pem_data: bytes) -> RSAPrivateKey:
        """
        This function deserializes the private key; it turns it from bytes to a RSAPrivateKey object.

        :param pem_data: The private key as bytes
        :return: It returns the private key as RSAPrivateKey object.
        """
        return serialization.load_pem_private_key(
            pem_data,
            password=None
        )

    @classmethod
    def serialize_public_key(cls, public_key: RSAPublicKey) -> bytes:
        """
        The public key needs to be serialized in order for it to be converted to bytes.

        :param public_key: The public key as RSAPrivateKey
        :return: The public key as bytes
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

    @classmethod
    def deserialize_public_key(cls, pem_data: bytes) -> RSAPublicKey:
        """
        This function deserializes the public key; it turns it from bytes to a RSAPublicKey object.

        :param pem_data: The public key as bytes
        :return: It returns the public key as RSAPublicKey object.
        """
        return serialization.load_pem_public_key(pem_data)

    def encrypt_private_key(self, password: bytearray,
                            private_key: Optional[RSAPrivateKey] = None,
                            user_id: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
        """
        This function encrypts the private key with Chacha20-Poly1305.

        :param password: The password needs to be passed as bytearray. (bytearray(b"example"))
        :param private_key: The private key can be passed. If not a new one will be generated. It needs to be passed as RSAPrivateKey object.
        :param user_id: The user_id ... can be passed, but i dont think it should be. as bytes
        :return: The funtion returns in the same order: The encrypted private key as bytes, the salt as bytes, the nonce as bytes.
        """
        if private_key is not None:
            private_key: bytes = self.serialize_private_key(private_key)
        else:
            private_key: bytes = self.serialize_private_key(self.create_private_key())
        hash_pw = self.hash_pw(bytes(password), hash_len=32)

        hash_pw = hash_pw.split("$")
        salt = Converter.b64_to_byte(hash_pw[-2])
        key = Converter.b64_to_byte(hash_pw[-1])

        chacha = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)
        aad = user_id

        return chacha.encrypt(nonce, private_key, aad), salt, nonce

    def decrypt_private_key(self, password: bytearray,
                            private_key: bytes,
                            nonce: bytes, salt: bytes,
                            user_id: Optional[bytes] = None) -> bytes:
        """
        This function decrypts the private key.


        :param password: The password needs to be passed as bytearray. (bytearray(b"example"))
        :param private_key: The private key as bytes
        :param nonce: The nonce as bytes
        :param salt: The salt as bytes
        :param user_id: The user_id ... can be passed, but i dont think it should be. as bytes
        :return: The private key as bytes. (it still needs to be deserialised)
        """
        hash_pw = self.recreate_hash(bytes(password), salt, hash_len=32)
        hash_pw = hash_pw.split("$")
        key = Converter.b64_to_byte(hash_pw[-1])
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, private_key, user_id)

    @classmethod
    @to_test
    def decrypt_rsa(cls, private_key: RSAPrivateKey, ciphertext: bytes, label: Optional[bytes] = None) -> bytes:
        """
        This function decrypts with the private key. Used for user data.

        :param private_key: The private key as RSAPrivateKey
        :param ciphertext: The text which needs to be decrypted as bytes
        :param label: An optional label as bytes
        :return: The decrypted text as bytes
        """
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label
            )
        )

    @classmethod
    @to_test
    def encrypt_rsa(cls, public_key: RSAPublicKey, plaintext: bytes, label: Optional[bytes] = None) -> bytes:
        """
        This function encrypts with the private key. Used for user data.

        :param public_key: The private key as RSAPublicKey
        :param plaintext: The text which needs to be encrypted as bytes
        :param label: An optional label as bytes
        :return: The encrypted text as bytes
        """
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label
            )
        )

    @classmethod
    @to_test
    def decrypt_chacha20(cls, key: bytes, nonce: bytes, encrypted_data: bytes,
                         authenticated: Optional[bytes] = None) -> bytes:
        """
        This function decrypts ciphertext, which was encrypted with ChaCha20-Poly1305.

        :param key: The key needs to be given as bytes.
        :param nonce: The nonce must be given as bytes.
        :param encrypted_data: the encrypted_data needs to be given as bytes.
        :param authenticated: An optional piece of data, which is authenticated, but not encrypted, needs to be given as bytes.
        :return: The decrypted plaintext as bytes.
        """
        return ChaCha20Poly1305(key).decrypt(nonce, encrypted_data, authenticated)

    @classmethod
    @to_test
    def encrypt_chacha20(cls, clear_text: bytes, authenticated: Optional[bytes] = None,
                         nonce: Optional[bytes] = None, key: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
        """
        This function encrypts plaintext with ChaCha20-Poly1305.

        :param clear_text: The clear_text needs to be given as bytes.
        :param authenticated: The optional authenticated data needs to be given as bytes.
        :param nonce: The optional nonce needs to be given as bytes.
        :param key: The key needs to be given as bytes.
        :return: This function returns in the same order as bytes: the key, the nonce, the encrypted data.
        """
        if nonce is None:
            nonce = secrets.token_bytes(24)
        if key is None:
            key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        return key, nonce, chacha.encrypt(nonce, clear_text, authenticated)
