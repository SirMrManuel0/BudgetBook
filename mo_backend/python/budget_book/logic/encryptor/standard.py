from dataclasses import dataclass
from enum import Enum
from typing import Self

from .converter import Converter
from backend.budget_book.errors import FileError

class FileTypes(Enum):
    ET = ("BB_ET", ".et", b"BB_ET")
    EJ = ("BB_EJ", ".ej", b"BB_EJ")
    EPNG = ("BB_EPNG", ".epng", b"BB_EPNG")
    KHB = ("BB_KHB", ".khb", b"BB_KHB")
    HB = ("BB_HB", ".hb", b"BB_HB")

    @property
    def magic(self) -> str:
        return self.value[0]

    @property
    def extension(self) -> str:
        return self.value[1]

    @property
    def magic_bytes(self) -> bytes:
        return self.value[2]


ID_LEN: int = 5
VERSION_LEN: int = 3

@dataclass
class FileHeader:
    type: FileTypes
    id_: str
    major: int
    minor: int = 0

    def encode(self) -> bytes:
        id_: bytes = Converter.b64_to_byte(self.id_)
        major: bytes = Converter.int_to_bytes(self.major, False)
        minor: bytes = Converter.int_to_bytes(self.minor, False)
        return (
            Converter.utf_to_byte(self.type.magic)
            + Converter.int_to_bytes(len(id_), False, length=ID_LEN)
            + id_
            + Converter.int_to_bytes(len(major), False, length=VERSION_LEN)
            + major
            + Converter.int_to_bytes(len(minor), False, length=VERSION_LEN)
            + minor
        )

    @classmethod
    def decode(cls, file: bytes) -> Self:
        """
        If the file does not start with a FileTypes.magic, this function raises a FileError.

        :param file: The file whose header should be decoded.
        """
        type_: FileTypes | None = None
        after: bytes | None = None
        offset: int = 0
        for ftype in FileTypes:
            if file.startswith(ftype.magic_bytes):
                type_ = ftype
                offset = len(ftype.magic)
                break
        if type_ is None:
            raise FileError("This is an incorrect file type.")
        try:
            id_len: int = Converter.bytes_to_int(file[offset: offset + ID_LEN], False)
            offset += ID_LEN
            id_: str = Converter.byte_to_b64(file[offset: offset + id_len])
            offset += id_len
            major_len: int = Converter.bytes_to_int(file[offset: offset + VERSION_LEN], False)
            offset += VERSION_LEN
            major: int = Converter.bytes_to_int(file[offset: offset + major_len], False)
            offset += major_len
            minor_len: int = Converter.bytes_to_int(file[offset: offset + VERSION_LEN], False)
            offset += VERSION_LEN
            minor: int = Converter.bytes_to_int(file[offset: offset + minor_len], False)
        except (IndexError, ValueError) as e:
            raise FileError(f"The file does not seem to be in the correct format: {e}", trace_error=e)
        except Exception as e:
            raise FileError(f"There was an unexpected error: {e}", trace_error=e)
        return FileHeader(type=type_, major=major, minor=minor, id_=id_)

class StandardManager:
    ...
