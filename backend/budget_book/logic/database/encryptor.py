import json
import secrets
import base64
import pandas

import keyring
import hashlib

from argon2 import PasswordHasher, exceptions
from typing import Optional, Union, Literal
from io import BytesIO, TextIOWrapper

from pylix.errors import to_test, TODO

from backend.budget_book import RustEncryptor, VaultType, get_file_versions
from backend.budget_book.errors import CorruptionError
from backend.budget_book.errors.errors import StateError

FILE_ID_LEN: int = 5
FILE_VERSION_LEN: int = 3

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
    def __init__(self, is_system: bool, test=False):
        """
        The encryptor of the database.

        :param is_system: This is a variable set to verify an instance to be the systems instance.
        :param test: If tests are programmed, the parameter test must be True.
        """
        self._is_system: bool = is_system
        self._test: bool = test
        self._encryptor: RustEncryptor = RustEncryptor(test)
        self._key_file: Optional[dict] = None
        if is_system:
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
            key = Converter.b64_to_byte("yz0Hw1TSUbMYwCohnSwken5AlXFKExjtqK117IjsOI8=")
        self._encryptor.add_secret(VaultType.system_key(), key)

    def set_key_file(self, password: Union[str, VaultType], key_file: bytes) -> int:
        """
        The key file stores all keys for all files (within the scope).

         Format:

         Version 1:
        version_len (3 bytes) + version (any bytes >I) + nonce (24 bytes) + cipher (32 bytes + 24 bytes + 16 bytes)
         + file ({ file id: { key_salt: 25 bytes, key_nonce: 24 bytes, nonce: 24 bytes, key: 32 bytes + 16 bytes, hash: 64 bytes } })


        :param password:
        :param key_file:
        :return:
        """
        password: VaultType = password if isinstance(password, VaultType) else VaultType(password)
        current = 0
        version_len: bytes = key_file[:3]
        current += 3
        limit_: int = Converter.bytes_to_int(version_len, False)
        version: bytes = key_file[current: limit_ + current]
        current += limit_
        version: int = Converter.bytes_to_int(version, False)
        nonce: bytes = key_file[current: 24 + current]
        current += 24
        cipher: bytes = key_file[current: 32 + 24 + 16 + current]
        current += 32 + 24 + 16
        file: bytes = key_file[current:]

        nonce_file = self._encryptor.decrypt_into_key(cipher, nonce, VaultType("temp_key_file_pw"), password, None)
        half_decrypted: bytes = self._encryptor.decrypt_chacha(file, nonce_file, VaultType("temp_key_file_pw"))
        self._encryptor.remove_secret(VaultType("temp_key_file_pw"))
        half_decrypted: dict = json.loads(half_decrypted)
        key_file: dict = dict()

        for k, v in half_decrypted.items():
            self._encryptor.derive_key(VaultType("temp_file_key_key"), password,
                                       salt=Converter.b64_to_byte(v["key_salt"]))
            key_file[k] = { "nonce": v["nonce"] }
            key_file[k]["hash"] = v["hash"]
            self._encryptor.decrypt_into_key(
                Converter.b64_to_byte(v["key"]),
                nonce=Converter.b64_to_byte(v["key_nonce"]),
                store=VaultType(f"key_file_{k}"),
                key=VaultType("temp_file_key_key")
            )
            key_file[k]["key"] = VaultType(f"key_file_{k}")
            self._encryptor.remove_secret(VaultType("temp_file_key_key"))

        self._key_file = key_file

        return version

    def _new_entry(self) -> str:
        if self._key_file is None:
            raise StateError("There is no key file.")

        max_ = -1
        for id_ in self._key_file.keys():
            id_: int = Converter.b64_to_int(id_, False)
            max_ = max(id_, max_)
        new_id = max_ + 1
        id_b = Converter.int_to_b64(new_id, False)
        self._key_file[id_b] = { "nonce": secrets.token_bytes(24), "key": VaultType(f"key_file_{id_b}"), "hash": "" }
        self._encryptor.create_key(VaultType(f"key_file_{id_b}"))
        return id_b

    def _add_file_verification(self, file: bytes):
        """
        !Important! The file must already be the same as defined in docs/file_types.md (including the file id!)
        :param file:
        :return:
        """
        hash_ = hashlib.sha512(file)
        hashed: bytes = hash_.digest()
        id_len = Converter.bytes_to_int(file[:FILE_ID_LEN], False)
        id_bytes = file[FILE_ID_LEN : FILE_ID_LEN + id_len]
        file_id = Converter.bytes_to_int(id_bytes, False)
        file_id = Converter.int_to_b64(file_id, False)
        self._key_file[file_id]["hash"] = Converter.byte_to_b64(hashed)

    def _verify_file(self, data: bytes) -> bool:
        hash_ = hashlib.sha512(data)
        hashed: bytes = hash_.digest()
        hashed: str = Converter.byte_to_b64(hashed)
        id_len: bytes = data[:FILE_ID_LEN]
        id_len: int = Converter.bytes_to_int(id_len, False)
        id_bytes: bytes = data[FILE_ID_LEN:FILE_ID_LEN+id_len]
        id_b64: str = Converter.byte_to_b64(id_bytes)
        correct_hash = self._key_file.get(id_b64, {"hash": -1})["hash"]
        if correct_hash == -1: raise CorruptionError("File does not exist in for this keyfile.")
        return hashed == correct_hash

    def generate_key_file(self) -> None:
        self._key_file = dict()

    def get_key_file(self, password: Union[str, VaultType]) -> bytes:
        password: VaultType = password if isinstance(password, VaultType) else VaultType(password)
        version = 1
        half_encrypted: dict = dict()
        for file_id, values in self._key_file.items():
            salt = secrets.token_bytes(25)
            self._encryptor.derive_key(VaultType("temp_file_key"), password, salt)
            key_nonce, ciphertext = self._encryptor.encrypt_key_chacha(
                values["key"],
                VaultType("_"),
                VaultType("temp_file_key"),
                None,
                None
            )
            self._encryptor.remove_secret(VaultType("_"))
            self._encryptor.remove_secret(VaultType("temp_file_key"))
            half_encrypted[file_id] = {
                "key_nonce": Converter.byte_to_b64(key_nonce),
                "key_salt": Converter.byte_to_b64(salt),
                "key": Converter.byte_to_b64(ciphertext),
                "nonce": Converter.byte_to_b64(values["nonce"]),
                "hash": values["hash"]
            }
        half_encrypted: str = json.dumps(half_encrypted)
        half_encrypted: bytes = Converter.utf_to_byte(half_encrypted)
        file_nonce, ciphertext = self._encryptor.encrypt_chacha(half_encrypted, key=VaultType("temp_file_key"))
        nonce, cipher = self._encryptor.encrypt_key_and_more(file_nonce, VaultType("temp_file_key"), key=password)
        self._encryptor.remove_secret(VaultType("temp_file_key"))

        version_bytes = Converter.int_to_bytes(version, False)
        enc_key_file = Converter.int_to_bytes(len(version_bytes), False, length=3) + version_bytes
        enc_key_file += nonce + cipher + ciphertext

        return enc_key_file

    def is_no_longer_system(self):
        self._is_system = False
        self._encryptor.remove_secret(VaultType.system_key())

    def add_secret(self, vt: VaultType, secret: bytes) -> None:
        self._encryptor.add_secret(vt, secret)

    def remove_secret(self, vt: VaultType) -> None:
        self._encryptor.remove_secret(vt)

    def compare_with_secret(self, a: VaultType, b: bytes):
        self._encryptor.add_secret(VaultType("temp_comparer"), b, True)
        compared = self.compare_secret(a, VaultType("temp_comparer"))
        self._encryptor.remove_secret(VaultType("temp_comparer"))
        return compared

    def compare_secret(self, a: VaultType, b: VaultType):
        return self._encryptor.compare_secrets(a, b)

    def generate_username_key(self, secret_name: str, salt: Optional[bytes] = None) -> bytes:
        """
        This method is used to generate the key for the username (usernames are encrypted with themselves)

        :param secret_name: The secret_name must be known in order to access the username key.
        :param salt: If this is not the first time, the salt of the first salt generation must be given as bytes.
        Default length: 32 bytes
        :return: It returns the salt, with which the username key was derived
        """
        if not self._is_system:
            raise StateError("Only the system can call this method.")
        salt_ = secrets.token_bytes(32) if salt is None else salt
        self._encryptor.derive_key(VaultType(secret_name), VaultType.system_key(), salt_)
        return salt_

    def encrypt_username(self, de_username: bytes, salt: Optional[bytes] = None, nonce: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
        """
        In order to encrypt the username it needs to be given together with the salt and nonce, if it is not the first time.

        :param salt: The salt must be given, if it is not the first time, as bytes
        :param de_username: The username must be given as bytes
        :param nonce: The nonce must be given, if it is not the first time, as bytes
        :return: It returns in the same order as bytes: the ciphertext, the nonce, the salt
        """
        if not self._is_system:
            raise StateError("Only the system can call this method.")
        self._encryptor.remove_secret(VaultType("temp_user_key"))
        salt_ = self.generate_username_key(secret_name="temp_user_key", salt=salt)
        nonce_ = nonce if nonce is not None else secrets.token_bytes(24)
        _, ciphertext = self._encryptor.encrypt_chacha(de_username, nonce_, key=VaultType("temp_user_key"))
        self._encryptor.remove_secret(VaultType("temp_user_key"))
        return ciphertext, nonce_, salt_

    def decrypt_username(self, en_username: bytes, salt_: bytes, nonce: bytes) -> bytes:
        """
        This method is used to decrypt the username.


        :param en_username: The encrypted username must be given as bytes
        :param nonce: The nonce must be given as bytes
        :param salt_: The salt for the username key generation.
        :return: This function returns the username as bytes
        """
        if not self._is_system:
            raise StateError("Only the system can call this method.")
        self._encryptor.remove_secret(VaultType("temp_user_key"))
        salt_ = self.generate_username_key(secret_name="temp_user_key", salt=salt_)
        plaintext = self._encryptor.decrypt_chacha(en_username, nonce, VaultType("temp_user_key"))
        self._encryptor.remove_secret(VaultType("temp_user_key"))
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

    def hash_pw(self, secret_name: str, hash_len: Optional[int] = None, salt_len: Optional[int] = None) -> str:
        """
        Passwords given into this function are hashed with argon2id.

        :param secret_name: The name of the secret to be hashed as string.
        :param hash_len: The length of the hash is standardised at 64 bytes, but can vary.
        :param salt_len: The length of the salt. default is: 16
        :return: The function returns the hash as utf-8 string.
        """
        return self._encryptor.hash_pw(VaultType(secret_name), hash_len, salt_len)

    def recreate_hash(self, secret_name: str, salt: bytes, salt_len: Optional[int] = None, hash_len: Optional[int] = None) -> str:
        """
        In order to recreate an argon2id hash you need to pass the password and salt as bytes. The hash_len needs to be correct. The rest can be changed, but should not.

        :param salt_len: The length of the salt should be passed as int.
        :param secret_name: The name of the password as string.
        :param salt: The salt needs to be passed as bytes.
        :param hash_len: default 64 bytes, can vary
        :return: It returns the hash as string.
        """
        return self._encryptor.hash_pw(VaultType(secret_name), hash_len, salt_len, salt)

    def gen_ecc_private_key(self, store_in: VaultType):
        """
        This method generates an ECC private key with the Rust x25516_dalek Crate.

        :param store_in: This is the VaultType reference where the private key will be stored in.
        :return:
        """
        self._encryptor.gen_static_private_key(store_in)

    def transfer_secret(self, encryptor: RustEncryptor, vt: VaultType):
        """
        This function transfers a secret from one RustEncryptor to another.
        It transfers it from the param to self.


        :param encryptor: The encryptor in which the secret was originally stored.
        :param vt: This is the VaultType reference under which the secret is stored.
        :return:
        """
        self._encryptor.transfer_secret(encryptor, vt)

    def _encrypt_et_ej_wrapper(self, data: bytes) -> bytes:
        id_: str = self._new_entry()
        key_vt: VaultType = self._key_file[id_]["key"]
        key_nonce: bytes = self._key_file[id_]["nonce"]
        version: str = get_file_versions()
        id_bytes: bytes = Converter.b64_to_byte(id_)
        id_len: bytes = Converter.int_to_bytes(len(id_bytes), False, FILE_ID_LEN)
        version_bytes: bytes = Converter.utf_to_byte(version)
        version_len: bytes = Converter.int_to_bytes(len(version_bytes), False, FILE_VERSION_LEN)
        _, ciphertext = self._encryptor.encrypt_chacha(data, key_nonce, None, key_vt)
        file: bytes = id_len + id_bytes + version_len + version_bytes + ciphertext
        self._add_file_verification(file)
        return file

    def encrypt_et(self, data: pandas.DataFrame) -> bytes:
        buffer = BytesIO()
        with TextIOWrapper(buffer, encoding='utf-8', write_through=True) as text_buf:
            data.to_csv(text_buf, index=False)
            text_buf.seek(0)
            csv_bytes = Converter.utf_to_byte(text_buf.read())
        return self._encrypt_et_ej_wrapper(csv_bytes)

    def encrypt_ej(self, data: dict) -> bytes:
        dumped: str = json.dumps(data)
        data_bytes: bytes = Converter.utf_to_byte(dumped)
        return self._encrypt_et_ej_wrapper(data_bytes)

    def _decrypt_et_ej_wrapper(self, data: bytes) -> bytes:
        if not self._verify_file(data):
            raise CorruptionError("This file has been corrupted.")
        id_len: bytes = data[:FILE_ID_LEN]
        id_len: int = Converter.bytes_to_int(id_len, False)
        id_bytes: bytes = data[FILE_ID_LEN:FILE_ID_LEN+id_len]
        current: int = FILE_ID_LEN + id_len
        version_len: bytes = data[current:current+FILE_VERSION_LEN]
        version_len: int = Converter.bytes_to_int(version_len, False)
        current += FILE_VERSION_LEN
        version_bytes: bytes = data[current:current+version_len]
        current += version_len
        file: bytes = data[current:]
        version: str = Converter.byte_to_utf(version_bytes)
        id_b64: str = Converter.byte_to_b64(id_bytes)
        key_vt: VaultType = self._key_file[id_b64]["key"]
        key_nonce: bytes = self._key_file[id_b64]["nonce"]
        return self._encryptor.decrypt_chacha(file, key_nonce, key_vt, None)

    def decrypt_et(self, data: bytes) -> pandas.DataFrame:
        file = self._decrypt_et_ej_wrapper(data)
        return pandas.read_csv(BytesIO(file), encoding="utf-8")

    def decrypt_ej(self, data: bytes) -> dict:
        file = self._decrypt_et_ej_wrapper(data)
        return json.loads(file)

    def __del__(self):
        for k in self._encryptor.show_all_keys():
            self._encryptor.remove_secret(VaultType(k))
