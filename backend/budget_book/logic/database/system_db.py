import json
from typing import Optional

from backend.budget_book.logic.database import Encryptor, Converter
from backend.budget_book.logic.database.file_manager import FileManager


class SystemDatabase:
    def __init__(self, test: bool = False):
        self._test: bool = test
        self._encryptor: Encryptor = Encryptor(is_system=True, test=test)
        self._filemanager: FileManager = FileManager(test=test)
        self._filemanager.force_directory_path = "permanent_storage/" + "deploy/" if not self._test else "test/"

    def add_user(self, username: str, secret_name: str, reference: Optional[str] = None):
        all_users: dict = self.get_all_user()

        new_id: int = -1
        for c, _ in all_users.items():
            new_id = max(new_id, c)
        new_id += 1

        all_users[new_id]: dict = {
            "username": username,
            "hashed_password": "",
            "reference": reference
        }
        self.save_all_users()

    def get_all_user(self) -> dict:
        """
        This function returns all users. They will be in the format of:

        id as uint: {
            "username": username as utf-8,

            "hashed_password": argon2id hash as utf-8,

            "reference": reference as utf-8
        }

        :return:
        """
        enc: str = self._filemanager.read("up.hb")
        version, all_users, encryption_header, aad = self._encryptor.decrypt_system_data(Converter.b64_to_byte(enc))
        all_users_d: dict = json.loads(all_users)
        deformatted: dict = dict()

        for id_, body in all_users_d.items():
            id_int: int = Converter.b64_to_int(id_, False)
            username_b: bytes = Converter.b64_to_byte(body["username"])
            salt: bytes = Converter.b64_to_byte(body["salt_username"])
            nonce: bytes = Converter.b64_to_byte(body["nonce_username"])
            username_b: bytes = self._encryptor.decrypt_username(username_b, salt, nonce)
            username: str = Converter.byte_to_utf(username_b)
            reference: str = Converter.b64_to_utf(body["reference"])
            hashed_pw: str = Converter.b64_to_utf(body["hashed_password"])
            deformatted[id_int] = {
                "username": username,
                "hashed_password": hashed_pw,
                "reference": reference
            }

        return deformatted

    def save_all_users(self):
        ...
