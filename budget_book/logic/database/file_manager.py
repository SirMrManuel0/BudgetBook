import os.path
from typing import Optional, Union

from budget_book.errors import PathError
from budget_book.logic.database.encryptor import Converter
from budget_book.path_manager import get_path_abs

class FileManager:
    def __init__(self, test=False):
        self._test = test
        self.force_file_path: Optional[str] = None
        self.force_directory_path: Optional[str] = None

    def _path_setter(self, file_path: Optional[str] = None, must_exist: bool = True):
        path = ""
        if self.force_directory_path is not None:
            if file_path is not None:
                path = os.path.join(self.force_directory_path, file_path)
                path = os.path.abspath(path)
            if must_exist and not os.path.isfile(path):
                raise PathError(f"A forceful directory path was given, but there is no file with the path"
                                f" '{file_path}'", file_path)
            return path
        if self.force_file_path is not None:
            path = self.force_file_path
            if must_exist and not os.path.isfile(path):
                raise PathError(f"A forceful file path was given, but there is no file with the path"
                                f" '{self.force_file_path}'", self.force_file_path)
            return path
        path = file_path
        if path == "" or (must_exist and not os.path.isfile(path)):
            raise PathError("No valid path was in any way given!", path)
        return path

    def read_wo_validator(self, file_path: Optional[str] = None) -> str:
        """

        :param file_path:
        :return: as b64
        """
        path = self._path_setter(file_path=file_path)

        with open(path, "rb") as f:
            bin_ = f.read()
        return Converter.byte_to_b64(bin_)

    def read(self, file_path: Optional[str] = None, nonce_len: int = 24,
             salt_len: int = 16) -> Union[tuple[str, str], tuple[str, str, str, str], tuple[str, str, str], str]:
        """

        :param salt_len:
        :param nonce_len:
        :param file_path:
        :return: content, hash or header, content | all as b64
        """
        path = self._path_setter(file_path=file_path)
        with open(path, "rb") as f:
            bin_ = f.read()
        if path.endswith(".ej"):
            return Converter.byte_to_b64(bin_)
        elif path.endswith(".k_hb"):
            salt = bin_[:salt_len]
            nonce = bin_[salt_len:salt_len+nonce_len]
            key = bin_[salt_len+nonce_len:]
            return Converter.byte_to_b64(salt), Converter.byte_to_b64(nonce), Converter.byte_to_b64(key)
        else:
            return Converter.byte_to_b64(bin_)

    def write(self, data: bytes, file_path: Optional[str] = None):
        path = self._path_setter(file_path=file_path, must_exist=False)

        with open(path, "wb") as f:
            f.write(data)
