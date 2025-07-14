import os.path
import hashlib

from budget_book.logic.database.encryptor import Converter
from budget_book.logic.database.file_manager import FileManager


def test__path_setter():
    manager = FileManager(test=True)
    assert manager._path_setter(file_path="LICENSE.md") == "LICENSE.md"
    manager.force_file_path = "LICENSE.md"
    assert manager._path_setter() == "LICENSE.md"

def test_write():
    manager = FileManager(test=True)
    manager.force_directory_path = "permanent_storage/test/file_manager_test/"
    manager.write(b"Halli Hallo", file_path="test_wo_validator")

def test_read_wo_validator():
    manager = FileManager(test=True)
    manager.force_directory_path = "permanent_storage/test/file_manager_test/"
    a = manager.read_wo_validator(file_path="test_wo_validator")
    assert a == Converter.byte_to_b64(b"Halli Hallo")

def test_read():
    manager = FileManager(test=True)
    manager.force_file_path = "permanent_storage/test/file_manager_test/test_w_validator"
    to_write = b"mit validator"
    hashed = hashlib.sha256()
    hashed.update(to_write)
    hashed = hashed.digest()
    manager.write(to_write + hashed)

    content, hash_ = manager.read()
    assert content == Converter.byte_to_b64(to_write)
    assert hash_ == Converter.byte_to_b64(hashed)
