from mfence import Encryptor, PyVaultType

class VaultType:
    """
    Python wrapper for the Rust PyVaultType class.
    Provides convenient factory methods and string conversion.
    """

    def __init__(self, name: str):
        self._inner = PyVaultType(name)

    @classmethod
    def private_key(cls):
        return cls._from_inner(PyVaultType.private_key)

    @classmethod
    def public_key(cls):
        return cls._from_inner(PyVaultType.public_key)

    @classmethod
    def password(cls):
        return cls._from_inner(PyVaultType.password)

    @classmethod
    def shared_secret(cls):
        return cls._from_inner(PyVaultType.shared_secret)

    @classmethod
    def chacha_key(cls):
        return cls._from_inner(PyVaultType.chacha_key)

    @classmethod
    def system_key(cls):
        return cls._from_inner(PyVaultType.system_key)

    @classmethod
    def static_private_key(cls):
        return cls._from_inner(PyVaultType.static_private_key)

    @classmethod
    def eph_private_key(cls):
        return cls._from_inner(PyVaultType.eph_private_key)

    @classmethod
    def _from_inner(cls, inner: PyVaultType):
        obj = cls.__new__(cls)
        obj._inner = inner
        return obj

    def __eq__(self, other):
        if not isinstance(other, VaultType):
            return NotImplemented
        return self._inner == other._inner

    def __hash__(self):
        return hash(self._inner)

    def __str__(self):
        return str(self._inner)

    def __repr__(self):
        return repr(self._inner)

    @property
    def inner(self) -> PyVaultType:
        """Access the underlying Rust PyVaultType object."""
        return self._inner

class RustEncryptor:
    def __init__(self, test: bool = False):
        self._encryptor = Encryptor(test)

    def add_secret(self, key: VaultType, secret_: bytes) -> None:
        self._encryptor.add_secret(key.inner, secret_)

    def remove_secret(self, key: VaultType) -> None:
        self._encryptor.remove_secret(key.inner)

    def clear_secrets(self) -> None:
        self._encryptor.clear_secrets()

    def encrypt_key_chacha(self, key_from: VaultType, store: VaultType,
                           key: VaultType = None, nonce_: bytes = None, aad_opt: bytes = None) -> tuple[bytes, bytes]:
        return self._encryptor.encrypt_key_chacha(key.inner if key is not None else None, key_from.inner, store.inner, nonce_, aad_opt)

    def get_secret(self, key: VaultType, insecure: bool = False) -> bytes:
        return self._encryptor.get_secret(key.inner, insecure)

    def encrypt_chacha(self, plaintext: bytes,
                       nonce_: bytes = None, aad_opt: bytes = None, key: VaultType = None) -> tuple[bytes, bytes]:
        return self._encryptor.encrypt_chacha(plaintext, nonce_, aad_opt, key.inner if key is not None else None)

    def decrypt_chacha(self, ciphertext: bytes, nonce_: bytes, from_key: VaultType,
                       aad_opt: bytes = None) -> bytes:
        return self._encryptor.decrypt_chacha(ciphertext, nonce_, aad_opt, from_key.inner)

    def gen_static_private_key(self, store: VaultType) -> None:
        self._encryptor.gen_static_private_key(store.inner)

    def gen_eph_private_key(self, store: VaultType) -> None:
        self._encryptor.gen_eph_private_key(store.inner)

    def find_shared_secret(self, store: VaultType, from_a: VaultType, from_b: VaultType, is_b_pub: bool) -> None:
        self._encryptor.find_shared_secret(store.inner, from_a.inner, from_b.inner, is_b_pub)

    def derive_key(self, store: VaultType, from_key: VaultType) -> None:
        self._encryptor.derive_key(store.inner, from_key.inner)

    def hash_pw(self,  from_key: VaultType,
                hash_len: int = None, salt_len: int = None, salt: bytes = None) -> str:
        return self._encryptor.hash_pw(from_key.inner, hash_len, salt_len, salt)

    def is_eq_argon(self, from_key: VaultType, hash_: str) -> bool:
        return self._encryptor.is_eq_argon(from_key.inner, hash_)

    def show_all_keys(self) -> list[str]:
        return self._encryptor.show_all_keys()

    def compare_secrets(self, a: VaultType, b: VaultType) -> bool:
        return self._encryptor.compare_secrets(a.inner, b.inner)
