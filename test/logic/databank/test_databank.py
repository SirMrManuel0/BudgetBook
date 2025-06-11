import json

import pytest

from budget_book.logic.databank import Encryptor
from budget_book.logic.databank.databank import Databank
from budget_book.logic.databank.encryptor import Converter
from budget_book.logic.databank.file_manager import FileManager
from budget_book.path_manager import get_path_abs


def test_add_user():
    u_name = "Thomas Erdbeere"
    databank = Databank(True)
    databank.add_user(u_name, bytearray(b"SuperSicher"), "")
    f_manager = FileManager(True)
    f_manager.force_file_path = get_path_abs("../permanent_storage/test/up/up.hb")
    en_content, hash_ = f_manager.read(validator_len=64)
    de_content = Encryptor(True).decrypt_system_data(Converter.b64_to_byte(en_content))
    content_dict: dict = json.loads(de_content)
    for k, v in content_dict.items():
        u_key, _ = Encryptor(True).generate_username_key(
            u_name.encode(),
            Converter.b64_to_byte(v["salt_username"])
        )
        de_username = Encryptor(True).decrypt_username(
            Converter.b64_to_byte(k),
            Converter.b64_to_byte(v["nonce_username"]),
            Converter.b64_to_byte(v["tag_username"]),
            u_key
        )
        assert de_username == u_name.encode()

