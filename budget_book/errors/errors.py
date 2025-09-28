class BaseError(Exception):
    def __init__(self, msg=""):
        super().__init__(msg)

class PathError(BaseError):
    def __init__(self, msg="", path=""):
        self.path = path
        if msg == "":
            msg = f"The path '{path}' is not valid!"
        super().__init__(msg)

class CorruptionError(BaseError):
    def __init__(self, msg=""):
        if msg == "":
            msg = "The data was corrupted. Please load a backup."
        super().__init__(msg)

class DatabaseError(BaseError):
    def __init__(self, msg=""):
        if msg == "":
            msg = "This was a faulty request."
        super().__init__(msg)

class StateError(BaseError):
    def __init__(self, msg=""):
        if msg == "":
            msg = "An invalid state was reached."
        super().__init__(msg)
