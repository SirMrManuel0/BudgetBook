import hashlib
import json
import os.path
import secrets
import json

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pylix.errors import TODO, to_test
from typing import Optional, Literal, Union

from budget_book.errors.errors import CorruptionError, DatabaseError
from budget_book.logic.database import Encryptor
from budget_book.logic.database.encryptor import Converter, HashingAlgorithm
from budget_book.logic.database.file_manager import FileManager
from budget_book.path_manager import get_path_abs


# User lookup file: up/up.hb | nonce len: 32 | validation hash sha512 (64 bytes)

def require_reference(func):
    """
    A decorator to enforce a state.

    :param func:
    :return:
    """
    def wrapper(self, *args, **kwargs):
        if self._reference == "":
            raise DatabaseError("A reference needs to be given for this action.")
        return func(self, *args, **kwargs)

    return wrapper

def require_set_user(func):
    """
    A decorator to enforce a state.

    :param func:
    :return:
    """
    def wrapper(self, *args, **kwargs):
        if self._user_id is None:
            raise DatabaseError("A user needs to be set for this action.")
        return func(self, *args, **kwargs)

    return wrapper

def require_private_key(func):
    """
    A decorator to enforce a state.

    :param func:
    :return:
    """
    def wrapper(self, *args, **kwargs):
        if self._private_key is None:
            raise DatabaseError("The private key is needed.")
        return func(self, *args, **kwargs)

    return wrapper

def require_public_key(func):
    """
    A decorator to enforce a state.

    :param func:
    :return:
    """
    def wrapper(self, *args, **kwargs):
        if self._public_key is None:
            raise DatabaseError("The public key is needed.")
        return func(self, *args, **kwargs)

    return wrapper


USER_PRIVATE_KEY_FILE_NAME: str = "user_key.k_hb"
RECOVERY_PRIVATE_KEY_FILE_NAME: str = "recovery_key.k_hb"
TRADE_ENTITIES_FILE_NAME: str = "trade_entities.ej"


class Database:
    def __init__(self, test=False, reference=""):
        """

        :param test: If you create tests, set this True.
        :param reference:  If you already know the users reference, set it here.
        """
        self._permanent_storage = get_path_abs("../permanent_storage/deploy/") \
            if not test else get_path_abs("../permanent_storage/test/")
        self._encryptor = Encryptor(test)
        self._test = test
        self._file_manager_ps = FileManager(test=test)
        self._file_manager_ps.force_directory_path = self._permanent_storage
        self._file_manager_reference = FileManager(test=test)
        self._reference = reference
        self._private_key: Optional[RSAPrivateKey] = None
        self._public_key = None
        self._user_id: Optional[str] = None
        self._user_id_bytes: Optional[bytes] = None
        self._id_len: int = 4

    def add_user(self, username_utf: str, password: bytearray, reference: str) -> None:
        """
        Create a new user.

        :param username_utf: The username as a string in the UTF-8 encoding.
        :param password: The password as a bytearray.
        :param reference: The reference to the users key as UTF-8 string. e.g. "path/to/the/key"
        :return: no return
        """
        content_dict = self.get_all_users()

        en_username, nonce_, tag, salt_ = self._encryptor.encrypt_username(username_utf.encode())
        hashed_pw = self._encryptor.hash_pw(bytes(password))
        id_max = -1
        if len(content_dict) > 0:
            for user_id, _ in content_dict.items():
                user_id = Converter.b64_to_int(user_id, False)
                id_max = max(user_id, id_max)
        id_: int = id_max + 1
        id_: bytes = Converter.int_to_bytes(id_, False, self._id_len)

        if reference == "":
            reference = os.path.join(self._permanent_storage, "user_data/", Converter.byte_to_b64(id_))
        else:
            reference = os.path.join(reference, f"BB_u_data_{Converter.byte_to_b64(id_)}")

        valid_ = hashlib.sha256()
        valid_.update(salt_)
        valid_.update(nonce_)
        valid_.update(tag)
        valid_.update(hashed_pw.encode())
        valid_.update(reference.encode())
        valid_.update(id_)
        valid_ = valid_.digest()
        content_dict[Converter.byte_to_b64(id_)] = {
            "username": Converter.byte_to_b64(en_username),
            "salt_username": Converter.byte_to_b64(salt_),
            "nonce_username": Converter.byte_to_b64(nonce_),
            "tag_username": Converter.byte_to_b64(tag),
            "pw": Converter.utf_to_b64(hashed_pw),
            "reference": Converter.utf_to_b64(reference),
            "validation": Converter.byte_to_b64(valid_)
        }

        de_content = json.dumps(content_dict)
        hash_ = hashlib.sha512()
        hash_.update(de_content.encode())
        hash_ = hash_.digest()
        en_content = self._encryptor.encrypt_system_data(de_content.encode())
        self._file_manager_ps.write(file_path="up/up.hb", data=en_content + hash_)

    def get_all_users(self) -> dict:
        """
        To get all the users. No parameter.
        It returns the dictionary as defined in permanent_storage/test/up/up.hb.template
        :return:
        """
        en_content, hash_ = self._file_manager_ps.read(file_path="up/up.hb", validator_len=64)
        content_dict = dict()
        if not (len(en_content) == 0 and len(hash_) == 0):
            de_content = self._encryptor.decrypt_system_data(Converter.b64_to_byte(en_content))
            if not self._encryptor.validate_hash(de_content, Converter.b64_to_byte(hash_), HashingAlgorithm.sha512):
                raise CorruptionError()

            content_dict = json.loads(de_content)
            del de_content
            del en_content
            del hash_

            return content_dict
        else:
            return dict()

    def validate_user(self, username_utf: str, password: bytearray) -> bool:
        """
        This method validates a user; testing if the user exists.

        :param username_utf: The username needs to be given as a string in the UTF-8 encoding.
        :param password: The password needs to be given as bytearray
        :return: it returns True, if the user exists
        """
        users: dict = self.get_all_users()
        username_bytes: bytes = username_utf.encode()

        is_user: bool = False

        for k, v in users.items():
            is_user = is_user or self.test_user(v, username_utf.encode(), password)

        return is_user

    def test_user(self, user_candidate: dict, username_bytes: bytes, password: bytearray) -> bool:
        """
        This method should mostly only be called within Databank.
        It tests whether the given candidate fits the password and username.

        :param user_candidate: The candidate needs to be given in a dict as defined in permanent_storage/test/up/up.hb.template
        :param username_bytes: The username needs to be passed in bytes.
        :param password: The password needs to be passed as a bytearray
        :return: It returns True, if the user fits.
        """
        name_candidate: bytes = Converter.b64_to_byte(user_candidate["username"])
        u_key, _ = self._encryptor.generate_username_key(username_bytes,
                                                         Converter.b64_to_byte(user_candidate["salt_username"]))
        try:
            de_username = self._encryptor.decrypt_username(
                name_candidate,
                Converter.b64_to_byte(user_candidate["nonce_username"]),
                Converter.b64_to_byte(user_candidate["tag_username"]),
                u_key
            )
        except InvalidTag as e:
            return False

        has_same_username: bool = de_username == username_bytes

        pw_hash: str = Converter.b64_to_utf(user_candidate["pw"])
        has_same_pw: bool = self._encryptor.validate_hash(bytes(password), pw_hash, HashingAlgorithm.argon2id)

        return has_same_pw and has_same_username

    def get_user(self, username_utf: str = None, password: bytearray = None, user_id: str = None) -> tuple[str, dict]:
        """
        The method needs to be given the username as a string in UTF-8 encoding and password as bytearray
        or only the user_id as string in b64 encoding.

        Returns:
        "id as b64",
        {

            "username": "b64",

            "salt_username": "b64",

            "nonce_username": "b64",

            "tag_username": "b64",

            "pw": "hash argon2id as utf8",

            "reference": "utf8",

            "validation": "sha256 b64"

        }
        :param user_id: The user_id needs to be given as b64 encoded string.
        :param username_utf: The username needs to be given as UTF-8 encoded string.
        :param password: The password needs to be given as a bytearray.
        :raises DatabankError: if user does not exist
        :return: It returns in the same order: user id as b64 string, dict as seen above.
        """
        if username_utf is not None and password is not None:
            if not self.validate_user(username_utf, password):
                raise DatabaseError(f"This User '{username_utf}' does not exist.")

            username_bytes: bytes = username_utf.encode()
            users: dict = self.get_all_users()

            for id_, data in users.items():
                if not self.test_user(data, username_bytes, password):
                    continue

                data["pw"] = Converter.b64_to_utf(data["pw"])
                data["reference"] = Converter.b64_to_utf(data["reference"])
                return id_, data
        elif user_id is not None:
            all_user = self.get_all_users()
            for id_, data in all_user.items():
                if id_ == user_id:
                    data["reference"] = Converter.b64_to_utf(data["reference"])
                    data["pw"] = Converter.b64_to_utf(data["pw"])
                    return user_id, data

        raise DatabaseError(f"This User does not exist.")

    def get_reference(self, id_: str) -> str:
        """
        This method returns the reference of an id.

        :param id_: The id needs to be passed as a b64 string.
        :return: The reference is returned as a b64 string.
        """
        dict_: dict = self.get_all_users()
        return Converter.b64_to_utf(dict_[id_]["reference"])

    def set_reference(self, reference: Optional[str] = None, id_: Optional[str] = None) -> None:
        """
        The reference is the folder where the key.k_hb is stored.

        This method sets the reference of the Database

        :param reference: The reference needs to be passed as an UTF-8 string.
        :param id_: The id needs to be passed as a b64 string.
        :return: It returns nothing.
        """
        if id_ is not None or reference is not None:
            self._reference = self.get_reference(id_) if id_ is not None else reference
            self._file_manager_reference.force_directory_path = self._reference
        else:
            raise DatabaseError("A reference or id needs to be given.")

    def set_user(self, username_utf: str, password: bytearray) -> None:
        """
        This function sets the user_id of the Database.

        :param username_utf: The username needs to be passed as an UTF-8 string.
        :param password: The password needs to be passed as a bytearray.
        :return:
        """
        self.validate_user(username_utf, password)
        self._user_id = self.get_user(username_utf, password)[0]
        self._user_id_bytes = Converter.b64_to_byte(self._user_id)

    def edit_user(self, field_to_change: Literal["username", "pw", "reference"], value: Union[str, bytearray],
                  username_utf: str = None, password: bytearray = None, id_: str = None):
        """
        This method edits a user. It either needs the username as utf-8 string and the password or the id.

        Only the password, the reference and the username can be changed.
        If the password is changed, a bytearray needs to be passed, otherwise a string;
        the username and the reference should be UTF-8 strings.

        IMPORTANT:
        EDITING THE PASSWORD HERE, WILL NOT CHANGE THE PASSWORD WHICH ENCRYPTS THE PRIVATE KEY.
        THIS NEEDS TO BE DONE THROUGH THE METHOD Database.change_password.

        :param field_to_change: username, pw or reference
        :param value: if password, bytearray, else utf-8 string
        :param username_utf: This needs to be passed as an utf-8 string
        :param password: This needs to be passed as a bytearray
        :param id_: This needs to be passed as an b64 string
        :return:
        """
        all_user = self.get_all_users()
        user_salt = None
        user_nonce = None
        user_tag = None

        if field_to_change == "username":
            if not isinstance(value, str):
                raise DatabaseError("To change the username an utf-8 string needs to be passed.")
            value, user_nonce, user_tag, user_salt = self._encryptor.encrypt_username(value.encode())
            value, user_nonce = Converter.byte_to_b64(value), Converter.byte_to_b64(user_nonce)
            user_tag, user_salt = Converter.byte_to_b64(user_tag), Converter.byte_to_b64(user_salt)
        elif field_to_change == "pw":
            if not isinstance(value, bytearray):
                raise DatabaseError("To change the password a bytearray needs to be passed as value.")
            value = bytes(value)
            hashed = self._encryptor.hash_pw(value)
            value = Converter.utf_to_b64(hashed)
        elif field_to_change == "reference":
            value = Converter.utf_to_b64(value)
        else:
            raise DatabaseError("The method Database.edit_user only accepts username, pw or reference to change.")

        if id_ is not None:
            ...
        elif username_utf is not None and password is not None:
            id_, user = self.get_user(username_utf, password)
        else:
            raise DatabaseError("username and password or id_ needs to be given.")

        if field_to_change == "username":
            all_user[id_]["username"] = value
            all_user[id_]["salt_username"] = user_salt
            all_user[id_]["nonce_username"] = user_nonce
            all_user[id_]["tag_username"] = user_tag
        else:
            all_user[id_][field_to_change] = value

        valid_ = hashlib.sha256()
        valid_.update(Converter.b64_to_byte(all_user[id_]["salt_username"]))
        valid_.update(Converter.b64_to_byte(all_user[id_]["nonce_username"]))
        valid_.update(Converter.b64_to_byte(all_user[id_]["tag_username"]))
        valid_.update(Converter.b64_to_byte(all_user[id_]["pw"]))
        valid_.update(Converter.b64_to_byte(all_user[id_]["reference"]))
        valid_.update(Converter.b64_to_byte(id_))
        valid_ = valid_.digest()

        all_user[id_]["validation"] = Converter.byte_to_b64(valid_)

        de_content = json.dumps(all_user)
        hash_ = hashlib.sha512()
        hash_.update(de_content.encode())
        hash_ = hash_.digest()
        en_content = self._encryptor.encrypt_system_data(de_content.encode())
        self._file_manager_ps.write(file_path="up/up.hb", data=en_content + hash_)

    @to_test
    def _write_private_key(self, private_key: RSAPrivateKey, file: str, password: bytearray, user_id: bytes,
                           file_manager: Optional[FileManager] = None):
        """
        This method writes and encrypts the private key to a file.


        :param private_key: The private key needs to be given as RSAPrivateKey object.
        :param file: This is the file, where the private key is supposed to be saved as utf-8 string.
        :param password: The password, with which the private key is encrypted, needs to be passed as bytearray.
        :param user_id: The user_id needs to be given as bytes.
        :param file_manager: If no file manager is passed, the default self._file_manager_reference will be used. (note: this means a force_directory will be enforced).
        :return:
        """
        if file_manager is None:
            file_manager = self._file_manager_reference
        enc_private, salt, nonce = self._encryptor.encrypt_private_key(password, private_key, user_id)
        file_manager.write(salt + nonce + enc_private, file)

    @to_test
    def _read_private_key(self, file: str, file_manager: Optional[FileManager] = None) -> tuple[str, str, str]:
        """
        This method reads but does not decrypt the private key from a file.

        :param file: The file where it is saved as utf-8 string.
        :param file_manager: If no file manager is passed, the default self._file_manager_reference will be used. (note: this means a force_directory will be enforced).
        :return: It returns in the same order: the salt as b64 string, the nonce as b64 string, the key as b64 string
        """
        if file_manager is None:
            file_manager = self._file_manager_reference
        return file_manager.read(file, salt_len=16, nonce_len=12)

    @to_test
    def _load_recovery_private_key(self, key: str) -> RSAPrivateKey:
        """
        This method lods the private key from the default recovery file using the recovery key.

        :param key: The recovery key as b64 string.
        :return: It returns the private key as RSAPrivateKey object.
        """
        key = Converter.b64_to_byte(key)
        id_ = key[:self._id_len]
        id_ = Converter.byte_to_b64(id_)
        reference = self.get_reference(id_)
        file_manager = FileManager(test=self._test)
        file_manager.force_directory_path = reference
        salt, nonce, (enc_private) = self._read_private_key(RECOVERY_PRIVATE_KEY_FILE_NAME, file_manager)
        private_key = self._encryptor.decrypt_private_key(bytearray(key), Converter.b64_to_byte(enc_private),
                                                          Converter.b64_to_byte(nonce), Converter.b64_to_byte(salt),
                                                          Converter.b64_to_byte(id_))
        return self._encryptor.deserialize_private_key(private_key)

    @to_test
    @require_set_user
    @require_reference
    def load_private_key(self, password: bytearray) -> None:
        """
        This method loads the private key into the database._private_key.

        Note this method requires:

        - A set user
        - A set reference

        :param password: The password with which the private key is encrypted as bytearray
        :return:
        """
        salt, nonce, enc_priv = self._read_private_key(USER_PRIVATE_KEY_FILE_NAME)
        self._private_key = self._encryptor.decrypt_private_key(password, Converter.b64_to_byte(enc_priv),
                                                                Converter.b64_to_byte(nonce),
                                                                Converter.b64_to_byte(salt),
                                                                Converter.b64_to_byte(self._user_id))
        self._private_key = self._encryptor.deserialize_private_key(self._private_key)
        self._public_key = self._private_key.public_key()

    @to_test
    @require_set_user
    @require_reference
    def create_private_key(self, password: bytearray) -> str:
        """
        This method creates, encrypts and saves the private key.

        saved key layout = salt, nonce, enc_key

        In "user_key.k_hb" the private key is saved, which is encrypted with the user password.

        In "recovery_key.k_hb" the private key is saved, which is encrypted with the recovery key.

        Both are constants of this file.

        Note this method requires:

        - A set user

        - A set reference

        :param password: THe user password, with which the user private key is encrypted as bytearray.
        :return: The recovery key as b64 string.
        """
        priv = self._encryptor.create_private_key()
        self._public_key = priv.public_key()
        self._write_private_key(priv, USER_PRIVATE_KEY_FILE_NAME, password, Converter.b64_to_byte(self._user_id))
        random_key = secrets.token_bytes(56)
        random_key = Converter.b64_to_byte(self._user_id) + random_key
        self._write_private_key(priv, RECOVERY_PRIVATE_KEY_FILE_NAME, bytearray(random_key),
                                Converter.b64_to_byte(self._user_id))
        return Converter.byte_to_b64(random_key)

    @to_test
    @require_private_key
    def delete_private_key(self):
        """
        This method deletes the private key.

        Note this method requires:

        - A set private key

        :return:
        """
        del self._private_key
        self._private_key = None

    @to_test
    def recover_password(self, recovery_key: str, new_password: bytearray) -> str:
        """
        This method recovers the private key, if the user password was forgotten.

        :param recovery_key: The recovery key needs to be given as b64 string.
        :param new_password: The new password needs to be passed as bytearray.
        :return: It returns the new recovery key as b64 string.
        """
        private_key = self._load_recovery_private_key(recovery_key)
        id_ = Converter.b64_to_byte(recovery_key)[:self._id_len]
        id_ = Converter.byte_to_b64(id_)
        id_bytes = Converter.b64_to_byte(id_)
        reference = self.get_reference(id_)
        file_manager = FileManager(test=self._test)
        file_manager.force_directory_path = reference
        new_recovery_key = secrets.token_bytes(56)
        new_recovery_key = id_bytes + new_recovery_key
        self._write_private_key(private_key, USER_PRIVATE_KEY_FILE_NAME, new_password, id_bytes, file_manager)
        self._write_private_key(private_key, RECOVERY_PRIVATE_KEY_FILE_NAME, bytearray(new_recovery_key), id_bytes,
                                file_manager)
        self.edit_user("pw", Converter.utf_to_b64(self._encryptor.hash_pw(bytes(new_password))))

        return Converter.byte_to_b64(new_recovery_key)

    @to_test
    @require_set_user
    @require_reference
    def change_password(self, old_password: bytearray, new_password: bytearray):
        """
        This method changes the user password.

        Note the method requires:

        - A set user

        - A set reference

        :param old_password: The old password needs to be passed as bytearray.
        :param new_password: Th new password needs to be passed as bytearray.
        :return:
        """
        salt, nonce, enc_private = self._read_private_key(USER_PRIVATE_KEY_FILE_NAME)
        private_key = self._encryptor.decrypt_private_key(old_password, Converter.b64_to_byte(enc_private),
                                                          Converter.b64_to_byte(nonce), Converter.b64_to_byte(salt),
                                                          self._user_id_bytes)
        private_key = self._encryptor.deserialize_private_key(private_key)
        self._write_private_key(private_key, USER_PRIVATE_KEY_FILE_NAME, new_password, self._user_id_bytes)
        self.edit_user("pw", new_password)

    @to_test
    @require_private_key
    @require_reference
    def _read_ej(self, path: str) -> dict:
        """
        This method reads encryptes json files (.ej).

        Note this method requires:

        - A set private key

        - A set reference

        :param path: The path to the encryptes json needs to be passed as utf-8 string.
        :return: It returns the decrypted json as dictionary.
        """
        header, enc_dict = self._file_manager_reference.read(
            path,
            header_len=256
        )

        key_len: int = 32
        nonce_len: int = 12
        validation_hash_len: int = 64

        decrypted: bytes = self._encryptor.decrypt_rsa(self._private_key, header)
        key = decrypted[:key_len]
        nonce = decrypted[key_len : key_len+nonce_len]
        validation_hash = decrypted[key_len+nonce_len : key_len+nonce_len+validation_hash_len]

        decrypted_content: bytes = self._encryptor.decrypt_chacha20(key, nonce, enc_dict)

        hash_ = hashlib.sha512()
        hash_.update(decrypted_content)
        hash_ = hash_.digest()

        if validation_hash != hash_:
            raise CorruptionError("The files content has been corrupted.")

        return json.loads(decrypted_content.decode())

    @to_test
    @require_reference
    @require_public_key
    def _write_ej(self, path: str, data: dict, key: Optional[bytes] = None, nonce: Optional[bytes] = None) -> None:
        """
        This method writes encrypted json files (.ej).

        Note this method requires:

        - A set reference

        - A set public key

        :param path: The path needs to be given as utf-8 string.
        :param data: The data needs to be given as a dictionary.
        :param key: The key is optional and can be given as bytes.
        :param nonce: The nonce is optional and can be given as bytes.
        :return: nothing.
        """
        data = json.dumps(data)
        data = data.encode()
        key, nonce, enc_data = self._encryptor.encrypt_chacha20(data, key=key, nonce=nonce)
        validation = hashlib.sha512()
        validation.update(data)
        validation = validation.digest()
        header = self._encryptor.encrypt_rsa(self._public_key, key + nonce + validation)
        self._file_manager_reference.write(header + enc_data, path)

    @to_test
    @require_reference
    @require_private_key
    def get_all_trade_entities(self) -> dict:
        """
        This method returns all the trade entities of the user.

        Note this method requires:

        - A set reference

        - A set private key

        :return: It returns all trade entities as a dictionary.
        Defined in permanent_storage/test/user_data/templates/trade_entities.ej
        """
        return self._read_ej(TRADE_ENTITIES_FILE_NAME)

    @to_test
    @require_reference
    @require_private_key
    def add_trade_entity(self, name: str, kind: Optional[str] = None,
                         description: Optional[str] = None, relationship: Optional[str] = None,
                         iban: Optional[str] = None, tags: Optional[list] = None) -> None:
        """
        This method adds a trading entity to the database.

        Note this method requires:

        - A set reference

        - A set private key


        :param name: The name of the trading entity has to be passed as an UTF-8 encoded string.
        :param kind: The kind of the trading entity has to be passed as an UTF-8 encoded string.
        :param description: The description has to be passed as an UTF-8 encoded string.
        :param relationship: The relationship has to be passed as an UTF-8 encoded string.
        :param iban: The iban should be passed as an UTF-8 encoded string.
        :param tags: The tags should be passed as a list of tag objects.
        :return:
        """
        all_ = self.get_all_trade_entities()
        new_id: int = -1
        for key in all_.keys():
            new_id = max(new_id, Converter.b64_to_int(key, False))
        new_id += 1
        new_id_b64: str = Converter.int_to_b64(new_id, False)

        new_iban = ""
        for c in iban:
            if c == "":
                continue
            new_iban += c

        all_[new_id_b64] = {
            "name": Converter.utf_to_b64(name),
            "description": Converter.utf_to_b64(description) if description is not None else "",
            "kind": Converter.utf_to_b64(kind) if kind is not None else "",
            "relationship": Converter.utf_to_b64(relationship) if relationship is not None else "",
            "iban": Converter.utf_to_b64(new_iban) if new_iban is not None else "",
            "tags": tags if tags is not None else list()
        }

        self._write_ej(TRADE_ENTITIES_FILE_NAME, all_)
