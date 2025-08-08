from mfence import Encryptor, PyVaultType

class RustEncryptor:
    def __init__(self, test: bool = False):
        self._encryptor = Encryptor(test)

    def add_secret(self, key: PyVaultType, secret_: bytes) -> None:
        self._encryptor.add_secret(key, secret_)

    def remove_secret(self, key: PyVaultType) -> None:
        self._encryptor.remove_secret(key)

    def clear_secrets(self) -> None:
        self._encryptor.clear_secrets()

    def encrypt_key_chacha(self, key_from: PyVaultType, store: PyVaultType,
                           key: PyVaultType = None, nonce_: bytes = None, aad_opt: bytes = None) -> tuple[bytes, bytes]:
        return self._encryptor.encrypt_key_chacha(key, key_from, store, nonce_, aad_opt)

    def get_secret(self, key: PyVaultType, insecure: bool = False) -> bytes:
        return self._encryptor.get_secret(key, insecure)

    def encrypt_chacha(self, plaintext: bytes,
                       nonce_: bytes = None, aad_opt: bytes = None, key: PyVaultType = None) -> tuple[bytes, bytes]:
        return self._encryptor.encrypt_chacha(plaintext, nonce_, aad_opt, key)

    def decrypt_chacha(self, ciphertext: bytes, nonce_: bytes, from_key: PyVaultType,
                       aad_opt: bytes = None) -> bytes:
        return self._encryptor.decrypt_chacha(ciphertext, nonce_, aad_opt, from_key)

    def gen_static_private_key(self, store: PyVaultType) -> None:
        self._encryptor.gen_static_private_key(store)

    def gen_eph_private_key(self, store: PyVaultType) -> None:
        self._encryptor.gen_eph_private_key(store)

    def find_shared_secret(self, store: PyVaultType, from_a: PyVaultType, from_b: PyVaultType, is_b_pub: bool) -> None:
        self._encryptor.find_shared_secret(store, from_a, from_b, is_b_pub)

    def derive_key(self, store: PyVaultType, from_key: PyVaultType) -> None:
        self._encryptor.derive_key(store, from_key)

    def hash_pw(self,  from_key: PyVaultType,
                hash_len: int = None, salt: bytes = None) -> str:
        return self._encryptor.hash_pw(from_key, hash_len, salt)

    @staticmethod
    def is_eq_argon(data: bytes, hash_: str) -> bool:
        return Encryptor.is_eq_argon(data, hash_)