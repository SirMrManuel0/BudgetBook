from typing import Optional

class BaseError(Exception):
    def __init__(self, msg="", trace_error: Optional[Exception] = None):
        self.trace_error = trace_error
        super().__init__(msg)

class PathError(BaseError):
    def __init__(self, msg="", path="", trace_error: Optional[Exception] = None):
        self.path = path
        if msg == "":
            msg = f"The path '{path}' is not valid!"
        super().__init__(msg, trace_error=trace_error)

class CorruptionError(BaseError):
    def __init__(self, msg="", trace_error: Optional[Exception] = None):
        if msg == "":
            msg = "The data was corrupted. Please load a backup."
        super().__init__(msg, trace_error=trace_error)

class DatabaseError(BaseError):
    def __init__(self, msg="", trace_error: Optional[Exception] = None):
        if msg == "":
            msg = "This was a faulty request."
        super().__init__(msg, trace_error=trace_error)

class StateError(BaseError):
    def __init__(self, msg="", trace_error: Optional[Exception] = None):
        if msg == "":
            msg = "An invalid state was reached."
        super().__init__(msg, trace_error=trace_error)

class FileError(BaseError):
    def __init__(self, msg="", trace_error: Optional[Exception] = None):
        if msg == "":
            msg = "An invalid file was read."
        super().__init__(msg, trace_error=trace_error)
