import hashlib
import json
import os.path
import uuid

from cryptography.exceptions import InvalidTag
from pylix.errors import TODO, to_test

from budget_book.errors.errors import CorruptionError
from budget_book.logic.databank import Encryptor
from budget_book.logic.databank.encryptor import Converter, HashingAlgorithm
from budget_book.logic.databank.file_manager import FileManager
from budget_book.path_manager import get_path_abs

# User lookup file: up/up.hb | nonce len: 32 | validation hash sha512 (64 bytes)

class Databank:
    def __init__(self, test=False):
        self._permanent_storage = get_path_abs("../permanent_storage/deploy/")\
            if not test else get_path_abs("../permanent_storage/test/")
        self._encryptor = Encryptor(test)
        self._test = test
        self._file_manager_ps = FileManager(test=test)
        self._file_manager_ps.force_directory_path = self._permanent_storage

    def add_user(self, username_utf: str, password: bytearray, reference: str):
        content_dict = self.get_all_users()

        en_username, nonce_, tag, salt_ = self._encryptor.encrypt_username(username_utf.encode())
        hashed_pw = self._encryptor.hash_pw(bytes(password))
        id_ = uuid.uuid4()
        id_ = id_.bytes

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
        content_dict[Converter.byte_to_b64(en_username)] = {
            "salt_username": Converter.byte_to_b64(salt_),
            "nonce_username": Converter.byte_to_b64(nonce_),
            "tag_username": Converter.byte_to_b64(tag),
            "pw": Converter.utf_to_b64(hashed_pw),
            "reference": Converter.utf_to_b64(reference),
            "id": Converter.byte_to_b64(id_),
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

        def test_user(name: str, user: dict) -> bool:
            name: bytes = Converter.b64_to_byte(name)
            u_key, _ = self._encryptor.generate_username_key(username_bytes, Converter.b64_to_byte(user["salt_username"]))
            try:
                de_username = self._encryptor.decrypt_username(
                    name,
                    Converter.b64_to_byte(user["nonce_username"]),
                    Converter.b64_to_byte(user["tag_username"]),
                    u_key
                )
            except InvalidTag as e:
                return False

            has_same_username: bool = de_username == username_bytes

            pw_hash: str = Converter.b64_to_utf(user["pw"])
            has_same_pw: bool = self._encryptor.validate_hash(bytes(password), pw_hash, HashingAlgorithm.argon2id)

            return has_same_pw and has_same_username

        is_user: bool = False

        for k, v in users.items():
            is_user = is_user or test_user(k, v)

        return is_user
