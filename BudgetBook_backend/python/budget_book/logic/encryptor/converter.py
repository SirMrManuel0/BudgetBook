import base64

from typing import Literal, Optional

class Converter:
    @classmethod
    def b64_to_utf(cls, b64: str) -> str:
        """Decode a base64-encoded string to a UTF-8 string."""
        decoded_bytes = base64.b64decode(b64)
        return decoded_bytes.decode('utf-8')

    @classmethod
    def utf_to_b64(cls, utf: str) -> str:
        """Encode a UTF-8 string to a Base64 string."""
        utf_bytes = utf.encode('utf-8')
        b64_bytes = base64.b64encode(utf_bytes)
        return b64_bytes.decode('ascii')

    @classmethod
    def hex_to_b64(cls, hex_: str) -> str:
        """Convert a hex string to a Base64 string."""
        raw_bytes = bytes.fromhex(hex_)
        b64_bytes = base64.b64encode(raw_bytes)
        return b64_bytes.decode('ascii')

    @classmethod
    def b64_to_hex(cls, b64: str) -> str:
        """Convert a Base64 string to a hex string."""
        raw_bytes = base64.b64decode(b64)
        return raw_bytes.hex()

    @classmethod
    def hex_to_byte(cls, hex_: str) -> bytes:
        """Convert a hex string to bytes."""
        return bytes.fromhex(hex_)

    @classmethod
    def byte_to_hex(cls, byte_data: bytes) -> str:
        """Convert bytes to a hex string."""
        return byte_data.hex()

    @classmethod
    def utf_to_byte(cls, utf: str) -> bytes:
        """Convert a UTF-8 string to bytes."""
        return utf.encode('utf-8')

    @classmethod
    def byte_to_utf(cls, byte_data: bytes) -> str:
        """Convert bytes to a UTF-8 string."""
        return byte_data.decode('utf-8')

    @classmethod
    def b64_to_byte(cls, b64: str) -> bytes:
        """Convert a Base64 string to bytes."""
        return base64.b64decode(b64 + "===")

    @classmethod
    def byte_to_b64(cls, byte_data: bytes) -> str:
        """Convert bytes to a Base64 string."""
        return base64.b64encode(byte_data).decode('ascii')

    @classmethod
    def int_to_b64(cls, value: int, signed: bool,
                   byteorder: Literal["little", "big"] = "big", length: Optional[int] = None) -> str:
        if length is None:
            length = (value.bit_length() + 7) // 8 or 1
        byte_data = value.to_bytes(length, byteorder=byteorder, signed=signed)
        return base64.b64encode(byte_data).decode('ascii')

    @classmethod
    def b64_to_int(cls, b64: str, signed: bool, byteorder: Literal["little", "big"] = "big") -> int:
        byte_data = base64.b64decode(b64, validate=True)
        return int.from_bytes(byte_data, byteorder=byteorder, signed=signed)

    @classmethod
    def int_to_hex(cls, value: int) -> str:
        return hex(value)[2:]

    @classmethod
    def hex_to_int(cls, hex_: str) -> int:
        return int(hex_, 16)

    @classmethod
    def int_to_bytes(cls, value: int, signed: bool, length: int = None, byteorder: Literal["little", "big"] = 'big') -> bytes:
        """Convert an integer to bytes.

        If length is None, minimal bytes are used.
        """
        if length is None:
            length = (value.bit_length() + 7) // 8 or 1
        return value.to_bytes(length, byteorder=byteorder, signed=signed)

    @classmethod
    def bytes_to_int(cls, byte_data: bytes, signed: bool, byteorder: Literal["little", "big"] = 'big') -> int:
        """Convert bytes to an integer."""
        return int.from_bytes(byte_data, byteorder=byteorder, signed=signed)
