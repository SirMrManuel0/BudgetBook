import secrets
from typing import Self

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

    def copy(self) -> Self:
        return VaultType._from_inner(self._inner.clone())

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
        """
        This RustEncryptor takes in a bool, which indicates whether or not it is a test case.

        To use the RustEncryptor you MUST first add the Secret with the add_secret function and can then use it in the
        functions via the corresponding VaultType.

        :param test:
        """
        self._encryptor = Encryptor(test)

    def add_secret(self, key: VaultType, secret_: bytes, force: bool = False) -> None:
        """
        This function adds a secret to the SecretVault.


        :param key: The key is essential, because only with this can you access the key. It should be passed as VaultType.
        :param secret_: The secret must be passed as bytes.
        :param force: If this boolean is True, any secret saved with the same name will be deleted.
        :return:
        """
        self._encryptor.add_secret(key.inner, secret_, force)

    def remove_secret(self, key: VaultType) -> None:
        """
        This method removes a secret based on the given VaultType.
        :param key: The VaultType with which the secret is referenced.
        :return:
        """
        self._encryptor.remove_secret(key.inner)

    def clear_secrets(self) -> None:
        self._encryptor.clear_secrets()

    def encrypt_key_chacha(self, key_from: VaultType, store: VaultType,
                           key: VaultType = None, nonce_: bytes = None, aad_opt: bytes = None) -> tuple[bytes, bytes]:
        """
        This function encrypts a secret with XChaCha20 Poly1305.

        The secret will be copied. The copy will be encrypted and saved with a new key.

        :param key_from: This is the key from where the secret will be copied to encrypt.
        :param store: Here the secret will be saved.
        :param key: With this key the encryption key will be accessed.
        :param nonce_: The nonce is optional. if it is given, it MUST be 24 bytes.
        :param aad_opt: The aad is optional. This is additional authenticated data.
        If it is given at encryption, it must be given at decryption.
        :return: It returns in the same order: the nonce, the ciphertext (both as bytes)
        """
        return self._encryptor.encrypt_key_chacha(key.inner if key is not None else None, key_from.inner, store.inner, nonce_, aad_opt)

    def get_secret(self, key: VaultType, insecure: bool = False) -> bytes:
        """
        This returns a secret.

        If a secret with ImportantTags::Safe tag is returned (aka a secret which was encrypted with encrypt_key_chacha),
        the secret will be in this format: nonce (first 24 bytes) + ciphertext (rest).

        :param key: This is the key under which the secret is saved.
        :param insecure: If this flag stays at False, only secrets with the ImportantTags::Safe tag can be returned.
        This tag indicates, that the secret has been encrypted with encrypt_key_chacha.
        :return: It returns the secret as bytes.
        """
        return self._encryptor.get_secret(key.inner, insecure)

    def encrypt_chacha(self, plaintext: bytes,
                       nonce_: bytes = None, aad_opt: bytes = None, key: VaultType = None) -> tuple[bytes, bytes]:
        """
        This function encrypts with XChaCha20 Poly1305.

        :param plaintext: The plaintext needs to be given as bytes.
        :param nonce_: The nonce can be given as bytes; it has to be 24 bytes! If it is not given, it will be random (as it should be!).
        :param aad_opt: The aad can be given as bytes. This additional authenticated data will have some authentication
        through the ciphertext. If it is given during encryption, it will be required during decryption.
        :param key: The key can be given through a VaultType reference. If it is given it should be 32 bytes.
        The VaultType can also just indicate, where the key should be saved. Default is VaultType.chacha_key().
        :return: It return in the same order: nonce, ciphertext both as bytes.
        """
        return self._encryptor.encrypt_chacha(plaintext, nonce_, aad_opt, key.inner if key is not None else None)

    def decrypt_chacha(self, ciphertext: bytes, nonce_: bytes, from_key: VaultType,
                       aad_opt: bytes = None) -> bytes:
        """
        This method decrypts the with XChaCha20 Poly1305.


        :param ciphertext: The ciphertext needs to be given as bytes.
        :param nonce_: The nonce also needs to be given as bytes.
        :param from_key: This key is a VaultType which references the secret.
        :param aad_opt: The aad needs to be given, if it was used during encryption. as bytes.
        :return: It returns the plaintext as bytes.
        """
        return self._encryptor.decrypt_chacha(ciphertext, nonce_, aad_opt, from_key.inner)

    def gen_static_private_key(self, store: VaultType) -> None:
        """
        This method generates a private ECC key witch the x25519_dalek crate from rust.

        :param store: This is the reference where the key will be stored at.
        :return:
        """
        self._encryptor.gen_static_private_key(store.inner)

    def gen_eph_private_key(self, store: VaultType) -> None:
        """
        ... This method does the same as  gen_static_private_key...

        But for clearer distinction here it is lol. (It was planned that it does something else.... ig

        :param store: This is the reference where the key will be stored at.
        :return:
        """
        self._encryptor.gen_static_private_key(store.inner)

    def find_shared_secret(self, store: VaultType, from_a: VaultType, from_b: VaultType, is_b_pub: bool) -> None:
        """
        This method is part of ECDHE.

        With 2 private keys or 1 private and 1 public key it will find the shared secret.
        This secret should be used to derive a key.

        :param store: This is a VaultType where the shared secret should be saved.
        :param from_a: This is one private key. IT MUST BE A PRIVATE KEY. Of course just the reference as a VaultType.
        :param from_b: This can be either a private key or a public key.
        This depends on the bool. Use a VaultType as reference.
        :param is_b_pub: This bool indicates whether from_b points to a public key or a private key.
        :return:
        """
        self._encryptor.find_shared_secret(store.inner, from_a.inner, from_b.inner, is_b_pub)

    def derive_key(self, store: VaultType, from_key: VaultType, salt: bytes = None) -> None:
        """
        This method allows to derive a key. Under the hood SHA256 is used; a 32 bytes key will be generated.

        A salt can be given for a bit more randomization.

        :param store: This is the VaultType reference which points at the storage for the derived key.
        :param from_key: This is the VaultType which points at the data from which the key is derived.
        :param salt:
        :return:
        """
        self._encryptor.derive_key(store.inner, from_key.inner, salt)

    def hash_pw(self,  from_key: VaultType,
                hash_len: int = None, salt_len: int = None, salt: bytes = None) -> str:
        """
        This method hashes passwords with argon2id.

        :param from_key: This is a VaultType which references the secret to be hashed.
        :param hash_len: The hash length can be given as int (max u32 calculate yourself). Default 64 bytes
        :param salt_len: The salt length can be given as int (max u32). Default 16.
        :param salt: The salt can of course be given as bytes.
        :return: It returns the hash in the standard argon 2id layout.
        (can be splitted with '$' [-1] is the hash. [-2] is the salt both are in b64)
        """
        return self._encryptor.hash_pw(from_key.inner, hash_len, salt_len, salt)

    def is_eq_argon(self, from_key: VaultType, hash_: str) -> bool:
        """
        This method checks whether a secret was the secret with which the hash was created.
        :param from_key: The VaultType reference to the secret.
        :param hash_: The argon str which is returned by hash_pw.
        :return: If True, it is the correct secret.
        """
        return self._encryptor.is_eq_argon(from_key.inner, hash_)

    def show_all_keys(self) -> list[str]:
        """
        This method returns a list of all VaultType references.
        :return: A list of strings which represent the VaultTypes.
        """
        return self._encryptor.show_all_keys()

    def compare_secrets(self, a: VaultType, b: VaultType) -> bool:
        """
        This methods compares 2 secrets in constant time
        (to be more exact as O(n), but here is n the max of the two lengths.
        This is seen as constant time, because timing attacks become hard to impossible.=

        :param a: A VaultType reference to one secret.
        :param b: A VaultType reference to the other secret.
        :return: If True, the secrets are the same.
        """
        return self._encryptor.compare_secrets(a.inner, b.inner)

    def ascii_add_secrets(self, a: VaultType, b: VaultType, store: VaultType):
        """
        This methods adds two secrets in a weird manner and stores it as a new secret.


        :param a: A VaultType reference to one secret.
        :param b: A VaultType reference to the other secret.
        :param store: The VaultType reference where the result should be saved.
        :return:
        """
        return self._encryptor.ascii_add_secrets(store.inner, a.inner, b.inner)

    def decrypt_into_key(self, ciphertext: bytes, nonce: bytes, store: VaultType, key: VaultType,
                         aad_opt: bytes = None) -> bytes:
        """
        This function decrypts with XChaCha20 Poly1305 and saves the key in the vault.

        Note the structure of the ciphertext needs to be:

        key (32 bytes) + nonce (24 bytes)

        :param ciphertext: The ciphertext should be given as bytes in the format as seen above.
        :param nonce: The nonce must be 24 bytes.
        :param store: This is the VaultType reference to the decrypted key.
        :param key: This is the VaultType reference to the key, which decrypts.
        :param aad_opt: The aad only needs to be given, if it was present during encryption. It should be passed as bytes.
        :return: It returns the nonce as bytes
        """
        return self._encryptor.decrypt_into_key(store.inner, key.inner, nonce, ciphertext, aad_opt)

    def encrypt_key_and_more(self, extra: bytes, from_key: VaultType,
                             nonce: bytes = None, aad_opt: bytes = None, key: VaultType = None) -> tuple[bytes, bytes]:
        """
        This method is used to add more stuff when encrypting a key.

        The addition will be in the format of:

        key + extra data

        :param extra: The extra data to be encrypted as bytes.
        :param from_key: The VaultType reference to the key, which shall be encrypted.
        :param nonce: The nonce can be given as bytes.
        :param aad_opt: The aad can be given as bytes. If it is given, it MUST be given at decryption.
        :param key: The VaultType reference to the key which shall be encrypted. (If none is given VaultType.chacha_key() is the default)
        :return: It returns in the same order: nonce, ciphertext both as bytes.
        """
        return self._encryptor.encrypt_key_and_more(extra, from_key.inner, nonce, aad_opt, key.inner)

    def get_public_key(self, private_key: VaultType) -> bytes:
        """
        This function returns the public key of the corresponding private key.

        :param private_key: The VaultType reference which points at the private key.
        :return: It returns the public key as bytes.
        """
        return self._encryptor.get_public_key(private_key.inner)

    def transfer_secret(self, encryptor: Self, vt: VaultType) -> None:
        """
        This function transfers a secret from one RustEncryptor to another.
        It transfers it from the param to self.


        :param encryptor: The encryptor in which the secret was originally stored.
        :param vt: This is the VaultType reference under which the secret is stored.
        :return:
        """
        self._encryptor.transfer_secret(encryptor._encryptor, vt.inner)
        encryptor.remove_secret(vt)

    def create_key(self, store: VaultType) -> None:
        """
        This function creates a 32 byte random key.

        :param store: The VaultType reference where the key should be stored.
        :return:
        """
        self._encryptor.create_key(store.inner)
