 from budget_book.rust_encryptor import RustEncryptor, VaultType
from budget_book.logic.database.encryptor import Encryptor, Converter
from budget_book.logic.database.file_manager import FileManager


class UserDatabase:
    def __init__(self, reference: str, encryptor: RustEncryptor, user_password_vt: VaultType, test: bool = False):
        """
        Important: The user password needs to have the VaultType reference of: VaultType.password()
        :param reference:
        :param encryptor:
        :param user_password_vt:
        :param test:
        """
        self._test: bool = test
        self._encryptor: Encryptor = Encryptor(test=test)
        self._encryptor.is_no_longer_system()
        self._filemanager: FileManager = FileManager(test=test)
        self._filemanager.force_directory_path = reference

        self._encryptor.transfer_secret(encryptor, user_password_vt)

    def set_user_key(self):
        
