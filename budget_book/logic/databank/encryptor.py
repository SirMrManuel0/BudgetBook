import secrets
import base64
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
        self._test = test

    def _get_system_key(self) -> bytes:
        if not self._test:
            return Converter.b64_to_byte(keyring.get_password("BudgetBook", "system_key"))
        else:
            # test key
            return Converter.hex_to_byte("f291edbb67f5bdb73814452098436b30f8615ee01b1e086d4f747748b672355ef33481c6b4a"
                                         "c812f837128085ef667f00bae190c1be2b8506a2a5590a743d0ff4760d8216b4b8c0f1252fd"
                                         "8ad1e1332f6557874c36872b410e29a764458c12b8bd0cfe10ddc99db05b539eb4fd31880cd"
                                         "9704899d6a5bd69a6a3413f188f43c4d374c8c042c163074a45f987acdd69bea59beabe9424"
                                         "68f5a5d0fcdfbbff9d4fef1a60f51247e9212da9c9b5232caa38f06e386f318e10d4b94016a"
                                         "a3270ad18dd68540100819bd8a0ba8e176aa601109678a4969159f767ae04d24cbd404e7b1b8"
                                         "7721831a5af291ae257e7419200b602d9348399623e0c5380590739f83c28")

    @classmethod
    def _ascii_addition_bytes(cls, *args: bytes) -> bytes:
        # Convert all to bytearrays for mutability
        byte_args = [bytearray(arg) for arg in args]

        # Find the longest one
        longest = max(byte_args, key=len)
        result = bytearray(longest)  # make a copy to modify

        for arg in byte_args:
            if arg is longest:
                continue  # skip the base

            arg_len = len(arg)
            if arg_len == 0:
                continue

            n = 0
            while True:
                # Calculate start index according to your rule:
                # offset = (len(arg) - 1) + (n-1)*len(arg) + (n-2)*len(arg)
                offset = (arg_len - 1) + n * arg_len + (n - 1) * arg_len if n > 0 else 0
                if offset >= len(result):
                    break

                for i, b in enumerate(arg):
                    idx = offset + i
                    if idx >= len(result):
                        break
                    result[idx] = (result[idx] + b) % 256

                n += 1

        return bytes(result)

    def generate_username_key(self, username: bytes, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """

        :param username: as bytse
        :param salt:  as bytes
        :return: bytes
        """
        system_key = self._get_system_key()
        salt_ = ""
        time_cost = 3
        memory_cost = 65536
        parallelism = 3
        hash_len = 32
        user_key = ""
        hashed = list()
        if salt is not None:
            salt_ = salt
            hashed = hash_secret(
                secret=self._ascii_addition_bytes(username, system_key),
                salt=salt_,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=hash_len,
                type=Type.ID,
            ).decode().split("$")
        else:
            ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=hash_len)
            hashed = ph.hash(self._ascii_addition_bytes(username, system_key)).split("$")

        salt_ = hashed[4]
        user_key = hashed[5]
        return Converter.b64_to_byte(user_key), Converter.b64_to_byte(salt_)

    def encrypt_username(self, de_username: bytes, salt: Optional[bytes] = None, nonce: Optional[bytes] = None) -> tuple[bytes, bytes, bytes, bytes]:
        """

        :param salt: as bytes
        :param de_username: as bytes
        :param nonce: as bytes
        :return: bytes
        """
        key_, salt_ = self.generate_username_key(username=de_username, salt=salt)
        en_username = ""
        nonce_ = nonce
        tag = None
        if nonce_ is not None:
            cipher = Cipher(algorithms.AES(key_), modes.GCM(nonce_))
            encryptor = cipher.encryptor()
            en_username = encryptor.update(de_username) + encryptor.finalize()
            tag = encryptor.tag
        else:
            nonce_ = secrets.token_bytes(32)
            cipher = Cipher(algorithms.AES(key_), modes.GCM(nonce_))
            encryptor = cipher.encryptor()
            en_username = encryptor.update(de_username) + encryptor.finalize()
            tag = encryptor.tag
        return en_username, nonce_, tag, salt_

    @classmethod
    def decrypt_username(cls, en_username: bytes, nonce: bytes, tag: bytes, user_key: bytes) -> bytes:
        aes_gcm = AESGCM(user_key)
        plaintext = aes_gcm.decrypt(nonce, en_username + tag, associated_data=None)
        return plaintext

    def encrypt_system_data(self, data: bytes, nonce_len: int = 32, nonce: Optional[bytes] = None) -> bytes:
        key_ = self._get_system_key()
        hashed_key = hashlib.sha256()
        hashed_key.update(key_)
        hashed_key = hashed_key.digest()
        nonce_ = secrets.token_bytes(nonce_len) if nonce is None else nonce
        cipher = Cipher(algorithms.AES(hashed_key), modes.GCM(nonce_))
        encryptor = cipher.encryptor()
        en_data = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        return nonce_ + en_data + tag

    def decrypt_system_data(self, en_data: bytes, nonce_len: int = 32):
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

        :param data:
        :param hash_:
        :param hashing_algo: from HashingAlgorithm
        :return:
        """

        ret: Union[bytes, bool] = hashing_algo(data, hash_)
        if isinstance(ret, bytes):
            return ret == hash_
        else:
            return ret

    @classmethod
    def hash_pw(cls, pw: bytes, hash_len=64) -> str:
        """

        :param pw: as b64
        :param hash_len: as b64
        :return: as b64
        """
        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=3, hash_len=hash_len)
        return ph.hash(pw)

    @classmethod
    def recreate_hash(cls, pw: bytes, salt: bytes,
                      time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 3, hash_len: int = 64) -> str:
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
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    @classmethod
    def serialize_private_key(cls, private_key: RSAPrivateKey) -> bytes:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @classmethod
    def deserialize_private_key(cls, pem_data: bytes) -> RSAPrivateKey:
        return serialization.load_pem_private_key(
            pem_data,
            password=None
        )

    def encrypt_private_key(self, password: bytearray,
                            private_key: Optional[RSAPrivateKey] = None,
                            user_id: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
        """

        :param password:
        :param private_key:
        :param user_id:
        :return: encrypted, salt, nonce
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
        hash_pw = self.recreate_hash(bytes(password), salt, hash_len=32)
        hash_pw = hash_pw.split("$")
        key = Converter.b64_to_byte(hash_pw[-1])
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, private_key, user_id)

    @classmethod
    @to_test
    def decrypt_rsa(cls, private_key: RSAPrivateKey, ciphertext: bytes, label: Optional[bytes] = None) -> bytes:
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
        return ChaCha20Poly1305(key).decrypt(nonce, encrypted_data, authenticated)

    @classmethod
    @to_test
    def encrypt_chacha20(cls, clear_text: bytes, authenticated: Optional[bytes] = None,
                         nonce: Optional[bytes] = None, key: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
        """

        :param clear_text:
        :param authenticated:
        :param nonce:
        :param key:
        :return: key, nonce, encrypted
        """
        if nonce is None:
            nonce = secrets.token_bytes(24)
        if key is None:
            key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        return key, nonce, chacha.encrypt(nonce, clear_text, authenticated)
