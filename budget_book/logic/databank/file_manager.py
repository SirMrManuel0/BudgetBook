from budget_book.path_manager import get_path_abs

class FileManager:
    def __init__(self, test=False, file_path: str = "", directory_path: str = ""):
        self._source_path = get_path_abs("../permanent_storage/deploy")
        if test:
            self._source_path = get_path_abs("../permanent_storage/test")
        self._test = test
        self.file_path: str = file_path
        self.directory_path: str = directory_path

