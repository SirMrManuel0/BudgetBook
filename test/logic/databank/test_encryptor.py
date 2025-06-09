import pytest
from budget_book.logic.databank.encryptor import Encryptor, Converter

# ------------------- Converter ----------------------------------------------------------------------------------------
# UTF <-> B64
@pytest.mark.parametrize("utf,expected_b64", [
    ("hello", "aGVsbG8="),
    ("äöü", "w6TDtsO8"),
    ("", ""),
])
def test_utf_to_b64_and_back(utf, expected_b64):
    b64 = Converter.utf_to_b64(utf)
    assert b64 == expected_b64
    assert Converter.b64_to_utf(b64) == utf

# HEX <-> B64
@pytest.mark.parametrize("hex_,expected_b64", [
    ("68656c6c6f", "aGVsbG8="),
    ("", ""),
    ("c3a4c3b6c3bc", "w6TDtsO8"),  # hex of "äöü"
])
def test_hex_to_b64_and_back(hex_, expected_b64):
    b64 = Converter.hex_to_b64(hex_)
    assert b64 == expected_b64
    assert Converter.b64_to_hex(b64) == hex_

# HEX <-> BYTES
@pytest.mark.parametrize("hex_,expected_bytes", [
    ("68656c6c6f", b"hello"),
    ("", b""),
    ("00ff", b"\x00\xff"),
])
def test_hex_byte_conversion(hex_, expected_bytes):
    assert Converter.hex_to_byte(hex_) == expected_bytes
    assert Converter.byte_to_hex(expected_bytes) == hex_

# UTF <-> BYTES
@pytest.mark.parametrize("utf,expected_bytes", [
    ("hello", b"hello"),
    ("ä", b"\xc3\xa4"),
    ("", b""),
])
def test_utf_byte_conversion(utf, expected_bytes):
    assert Converter.utf_to_byte(utf) == expected_bytes
    assert Converter.byte_to_utf(expected_bytes) == utf

# B64 <-> BYTES
@pytest.mark.parametrize("b64,expected_bytes", [
    ("aGVsbG8=", b"hello"),
    ("", b""),
    ("AA==", b"\x00"),
])
def test_b64_byte_conversion(b64, expected_bytes):
    assert Converter.b64_to_byte(b64) == expected_bytes
    assert Converter.byte_to_b64(expected_bytes) == b64
