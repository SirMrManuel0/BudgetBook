import json
import os

import pytest

from budget_book.logic.databank import Encryptor
from budget_book.logic.databank.databank import Databank
from budget_book.logic.databank.encryptor import Converter, HashingAlgorithm
from budget_book.logic.databank.file_manager import FileManager
from budget_book.path_manager import get_path_abs


def test_add_user():
    with open("permanent_storage/test/up/up.hb", "rb") as f:
        byt = f.read()
    with open("permanent_storage/test/up/up.hb", "wb") as f:
        f.write(b"")

    databank: Databank = Databank(True)
    users_to_add: list[tuple[str, bytearray, str]] = [
        ("Thomas Erdbeere", bytearray(b"SuperSicher"), "permanent_storage"),
        ("Valerie Dino", bytearray(b"SichererGehtEs Nicht <3"), "permanent_storage"),
        ("Michael Steiner", bytearray(b"Dinosauriar"), "permanent_storage")
    ]
    for username, pw, reference in users_to_add:
        databank.add_user(username, pw, reference)

    f_manager = FileManager(True)
    f_manager.force_file_path = get_path_abs("../permanent_storage/test/up/up.hb")
    en_content, hash_ = f_manager.read(validator_len=64)
    de_content = Encryptor(True).decrypt_system_data(Converter.b64_to_byte(en_content))
    content_dict: dict = json.loads(de_content)
    for index, (k, v) in enumerate(content_dict.items()):
        assert databank.validate_user(users_to_add[index][0], users_to_add[index][1])

    with open("permanent_storage/test/up/up.hb", "wb") as f:
        f.write(byt)

def test_get_all_user():
    with open("permanent_storage/test/up/up.hb", "rb") as f:
        byt = f.read()
    with open("permanent_storage/test/up/up.hb", "wb") as f:
        f.write(b"")

    databank: Databank = Databank(True)
    users_to_add: list[tuple[str, bytearray, str]] = [
        ("Thomas Erdbeere", bytearray(b"SuperSicher"), "permanent_storage"),
        ("Valerie Dino", bytearray(b"SichererGehtEs Nicht <3"), "permanent_storage"),
        ("Michael Steiner", bytearray(b"Dinosauriar"), "permanent_storage")
    ]
    for username, pw, reference in users_to_add:
        databank.add_user(username, pw, reference)

    all_users = databank.get_all_users()

    for index, (id_, data) in enumerate(all_users.items()):
        reference = os.path.join(users_to_add[index][2], f"BB_u_data_{id_}")
        assert Converter.b64_to_utf(data["reference"]) == reference
        assert Encryptor(True).validate_hash(
            bytes(users_to_add[index][1]),
            Converter.b64_to_utf(data["pw"]),
            HashingAlgorithm.argon2id
        )

    with open("permanent_storage/test/up/up.hb", "wb") as f:
        f.write(byt)

def test_validate_user():
    with open("permanent_storage/test/up/up.hb", "rb") as f:
        byt = f.read()
    with open("permanent_storage/test/up/up.hb", "wb") as f:
        f.write(b"")

    databank: Databank = Databank(True)
    users_to_add: list[tuple[str, bytearray, str]] = [
        ("Thomas Erdbeere", bytearray(b"SuperSicher"), "permanent_storage"),
        ("Valerie Dino", bytearray(b"SichererGehtEs Nicht <3"), "permanent_storage"),
        ("Michael Steiner", bytearray(b"Dinosauriar"), "permanent_storage")
    ]

    for username, password, reference in users_to_add:
        databank.add_user(username, password, reference)

    for username, password, _ in users_to_add:
        assert databank.validate_user(username, password)

    with open("permanent_storage/test/up/up.hb", "wb") as f:
        f.write(byt)

def test_get_user():
    with open("permanent_storage/test/up/up.hb", "rb") as f:
        byt = f.read()
    with open("permanent_storage/test/up/up.hb", "wb") as f:
        f.write(b"")

    databank: Databank = Databank(True)
    users_to_add: list[tuple[str, bytearray, str]] = [
        ("Thomas Erdbeere", bytearray(b"SuperSicher"), "permanent_storage"),
        ("Valerie Dino", bytearray(b"SichererGehtEs Nicht <3"), "permanent_storage"),
        ("Michael Steiner", bytearray(b"Dinosauriar"), "permanent_storage")
    ]
    for username, pw, reference in users_to_add:
        databank.add_user(username, pw, reference)

    for name, pw, reference in users_to_add:
        id_, data = databank.get_user(name, pw)
        reference = os.path.join(reference, f"BB_u_data_{id_}")
        assert data["reference"] == reference
        assert Encryptor(True).validate_hash(
            bytes(pw),
            data["pw"],
            HashingAlgorithm.argon2id
        )

    with open("permanent_storage/test/up/up.hb", "wb") as f:
        f.write(byt)
