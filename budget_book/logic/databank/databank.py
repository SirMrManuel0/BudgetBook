import hashlib
import json
import os.path
import secrets
import uuid
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from pylix.errors import TODO, to_test

from budget_book.errors.errors import CorruptionError, DatabankError
from budget_book.logic.databank import Encryptor
from budget_book.logic.databank.encryptor import Converter, HashingAlgorithm
from budget_book.logic.databank.file_manager import FileManager
from budget_book.path_manager import get_path_abs

# User lookup file: up/up.hb | nonce len: 32 | validation hash sha512 (64 bytes)

def require_reference(func):
    def wrapper(self, *args, **kwargs):
        if self._reference == "":
            raise DatabankError("A reference needs to be given for this action.")
        return func(self, *args, **kwargs)
    return wrapper

def require_set_user(func):
    def wrapper(self, *args, **kwargs):
        if self._user_id is None:
            raise DatabankError("A user needs to be set for this action.")
        return func(self, *args, **kwargs)
    return wrapper


class Databank:
    def __init__(self, test=False, reference=""):
        self._permanent_storage = get_path_abs("../permanent_storage/deploy/")\
            if not test else get_path_abs("../permanent_storage/test/")
        self._encryptor = Encryptor(test)
        self._test = test
        self._file_manager_ps = FileManager(test=test)
        self._file_manager_ps.force_directory_path = self._permanent_storage
        self._file_manager_reference = FileManager(test=test)
        self._reference = reference
        self._private_key = None
        self._public_key = None
        self._user_id: Optional[str] = None
        self._id_len: int = 4

    def add_user(self, username_utf: str, password: bytearray, reference: str):
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
        self._file_manager_ps.write(file_path="up/up.hb", data=en_content+hash_)

    def get_all_users(self) -> dict:
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
        users: dict = self.get_all_users()
        username_bytes: bytes = username_utf.encode()

        is_user: bool = False

        for k, v in users.items():
            is_user = is_user or self.test_user(v, username_utf.encode(), password)

        return is_user

    def test_user(self, user_candidate: dict, username_bytes: bytes, password: bytearray) -> bool:
        name_candidate: bytes = Converter.b64_to_byte(user_candidate["username"])
        u_key, _ = self._encryptor.generate_username_key(username_bytes, Converter.b64_to_byte(user_candidate["salt_username"]))
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
        :param user_id:
        :param username_utf:
        :param password:
        :raises DatabankError: if user does not exist
        :return:
        """
        if username_utf is not None and password is not None:
            if not self.validate_user(username_utf, password):
                raise DatabankError(f"This User '{username_utf}' does not exist.")

            username_bytes: bytes = username_utf.encode()
            users: dict = self.get_all_users()

            for id_, data in users.items():
                if not self.test_user(data, username_bytes, password):
                    continue

                data["pw"] = Converter.b64_to_utf(data["pw"])
                data["reference"] = Converter.b64_to_utf(data["reference"])

                return id_, data
        elif user_id is not None:
            all_users = self.get_all_users()
            return user_id, all_users[user_id]
        raise DatabankError(f"This User does not exist.")

    def get_reference(self, id_: str) -> str:
        """

        :param id_: as b64
        :return: as b64
        """
        dict_: dict = self.get_all_users()
        return Converter.b64_to_utf(dict_[id_]["reference"])

    def set_reference(self, reference: Optional[str] = None, id_: Optional[str] = None) -> None:
        """
        The reference is the folder where the key.k_hb is stored.

        :param reference: as utf
        :param id_: as b64
        :return:
        """
        if id_ is not None or reference is not None:
            self._reference = self.get_reference(id_) if id_ is not None else reference
            self._file_manager_reference.force_directory_path = self._reference
        else:
            raise DatabankError("A reference or id needs to be given.")

    def set_user(self, username_utf: str, password: bytearray):
        self.validate_user(username_utf, password)
        self._user_id = self.get_user(username_utf, password)[0]

    @to_test
    def edit_user(self, field_to_change: str, value, username_utf: str = None, password: bytearray = None, id_: str = None):
        all_user = self.get_all_users()
        if id_ is not None:
            all_user[id_][field_to_change] = value
        elif username_utf is not None and password is not None:
            id_, user = self.get_user(username_utf, password)
            all_user[id_][field_to_change] = value
        else:
            raise DatabankError("username and password or id_ needs to be given.")

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
    @require_set_user
    @require_reference
    def load_private_key(self, password: bytearray) -> None:
        salt, nonce, enc_priv = self._file_manager_reference.read("user_key.k_hb")
        self._private_key = self._encryptor.decrypt_private_key(password, enc_priv, nonce, salt, Converter.b64_to_byte(self._user_id))
        self._private_key = self._encryptor.deserialize_private_key(self._private_key)
        self._public_key = self._private_key.public_key()

    @to_test
    @require_set_user
    @require_reference
    def create_private_key(self, password: bytearray) -> str:
        """
        saved key layout = salt, nonce, enc_key
        "user_key.k_hb"
        "recovery_key.k_hb"
        :param password:
        :return:
        """
        priv = self._encryptor.create_private_key()
        self._public_key = priv.public_key()
        en_user_priv, salt, nonce = self._encryptor.encrypt_private_key(password, priv, Converter.b64_to_byte(self._user_id))
        self._file_manager_reference.write(salt + nonce + en_user_priv, "user_key.k_hb")
        random_key = secrets.token_bytes(56)
        random_key = Converter.b64_to_byte(self._user_id) + random_key
        en_recovery_priv, rec_salt, rec_nonce = self._encryptor.encrypt_private_key(bytearray(random_key), priv, Converter.b64_to_byte(self._user_id))
        self._file_manager_reference.write(rec_salt + rec_nonce + en_recovery_priv, "recovery_key.k_hb")
        return Converter.byte_to_b64(random_key)

    @to_test
    def delete_private_key(self):
        del self._private_key
        self._private_key = None

    @to_test
    def _load_recovery_private_key(self, key: str) -> EllipticCurvePrivateKey:
        key = Converter.b64_to_byte(key)
        id_ = key[:self._id_len]
        id_ = Converter.byte_to_b64(id_)
        reference = self.get_reference(id_)
        file_manager = FileManager(test=self._test)
        file_manager.force_directory_path = reference
        salt, nonce, enc_private = file_manager.read("recovery_key.k_hb", salt_len=16, nonce_len=12)
        private_key = self._encryptor.decrypt_private_key(bytearray(key), enc_private, nonce, salt, Converter.b64_to_byte(id_))
        return self._encryptor.deserialize_private_key(private_key)

    @to_test
    def recover_password(self, recovery_key: str, new_password: bytearray):
        private_key = self._load_recovery_private_key(recovery_key)
        id_ = Converter.b64_to_byte(recovery_key)[:self._id_len]
        id_ = Converter.byte_to_b64(id_)
        id_bytes = Converter.b64_to_byte(id_)
        reference = self.get_reference(id_)
        file_manager = FileManager(test=self._test)
        file_manager.force_directory_path = reference
        enc_user_private_key, salt, nonce = self._encryptor.encrypt_private_key(new_password, private_key, id_bytes)
        new_recovery_key = secrets.token_bytes(56)
        new_recovery_key = id_bytes + new_recovery_key
        enc_recovery_private_key, salt_rec, nonce_rec = self._encryptor.encrypt_private_key(bytearray(new_recovery_key), private_key, id_bytes)
        file_manager.write(salt + nonce + enc_user_private_key, "user_key.k_hb")
        file_manager.write(salt_rec + nonce_rec + enc_recovery_private_key, "recovery_key.k_hb")

        self.edit_user("pw", Converter.utf_to_b64(self._encryptor.hash_pw(bytes(new_password))))

        return new_recovery_key
