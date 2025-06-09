import secrets
import base64
import keyring

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pylix.errors import TODO
from argon2 import PasswordHasher
from argon2.low_level import hash_secret, Type
from typing import Iterable, Optional

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
        return base64.b64decode(b64)

    @classmethod
    def byte_to_b64(cls, byte_data: bytes) -> str:
        """Convert bytes to a Base64 string."""
        return base64.b64encode(byte_data).decode('ascii')

class Encryptor:
    def __init__(self, test=False):
        self._test = test

    def _get_system_key(self) -> str:
        if not self._test:
            return keyring.get_password("BudgetBook", "system_key")
        else:
            # test key
            return "f291edbb67f5bdb73814452098436b30f8615ee01b1e086d4f747748b672355ef33481c6b4ac812f837128085ef667f00b"\
                   "ae190c1be2b8506a2a5590a743d0ff4760d8216b4b8c0f1252fd8ad1e1332f6557874c36872b410e29a764458c12b8bd0c"\
                   "fe10ddc99db05b539eb4fd31880cd9704899d6a5bd69a6a3413f188f43c4d374c8c042c163074a45f987acdd69bea59bea"\
                   "be942468f5a5d0fcdfbbff9d4fef1a60f51247e9212da9c9b5232caa38f06e386f318e10d4b94016aa3270ad18dd685401"\
                   "00819bd8a0ba8e176aa601109678a4969159f767ae04d24cbd404e7b1b87721831a5af291ae257e7419200b602d9348399"\
                   "623e0c5380590739f83c28"

    def _ascii_addition(self, *args: Iterable[str]) -> str:
        # set the longest argument to be final_
        final_ = list()
        max_ = -1
        for arg in args:
            a = max_
            max_ = max(max_, len(arg))
            if a != max_:
                final_ = [*arg]

        final_ = [ord(char) for char in final_]

        # addition
        for arg in args:
            for start in range(0, len(final_), len(arg) * 3):
                if start + len(arg) >= len(final_): break
                for i, char in enumerate(arg[start:]):
                    i += start
                    final_[i] += ord(char)
                    final_[i] = final_[i] % 128
        final_ = [chr(c) for c in final_]
        return "".join(final_)

    @TODO
    def _generate_username_key(self, username: str, salt: Optional[str] = None) -> tuple[str, str]:
        """

        :param username: as b64
        :param salt:  as b64
        :return: b64
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
                secret=self._ascii_addition(username, system_key).encode(),
                salt=salt_.encode(),
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=hash_len,
                type=Type.ID,
            ).decode().split("$")
        else:
            ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=hash_len)
            hashed = ph.hash(self._ascii_addition(username, system_key)).split("$")

        salt_ = hashed[4]
        user_key = hashed[5]
        return user_key, salt_

    @TODO
    def encrypt_username(self, de_username: str, nonce: Optional[str] = None) -> tuple[str, str, str]:
        """

        :param de_username: as b64
        :param nonce: as b64
        :return: b64
        """
        key_, _ = self._generate_username_key(username=de_username)
        en_username = ""
        nonce_ = nonce
        tag = None
        if nonce_ is not None:
            cipher = Cipher(algorithms.AES(Converter.b64_to_byte(key_)), modes.GCM(Converter.b64_to_byte(nonce_)))
            encryptor = cipher.encryptor()
            en_username = encryptor.update(Converter.b64_to_byte(de_username)) + encryptor.finalize()
            en_username = Converter.byte_to_b64(en_username)
            tag = Converter.byte_to_b64(encryptor.tag)
        else:
            nonce_ = secrets.token_bytes(32)
            cipher = Cipher(algorithms.AES(Converter.b64_to_byte(key_)), modes.GCM(nonce_))
            encryptor = cipher.encryptor()
            en_username = encryptor.update(Converter.b64_to_byte(de_username)) + encryptor.finalize()
            en_username = Converter.byte_to_b64(en_username)
            nonce_ = Converter.byte_to_b64(nonce_)
            tag = Converter.byte_to_b64(encryptor.tag)
        return en_username, nonce_, tag

    @TODO
    def decrypt_username(self, en_username: str, nonce: str) -> str:
        ...

    def hash_pw(self, pw: str) -> str:
        """

        :param pw: as b64
        :return: as b64
        """
        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=3, hash_len=64)
        return ph.hash(Converter.b64_to_byte(pw))
