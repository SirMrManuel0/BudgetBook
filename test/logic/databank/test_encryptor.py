import hashlib

import pytest
from budget_book.logic.databank.encryptor import Encryptor, Converter, HashingAlgorithm


@pytest.mark.parametrize(
    "inputs,expected,custom_check",
    [
        # test_basic_addition
        ((b"abcd", b"\x01\x01\x01\x01"), b"bcde", None),

        # test_wraparound_mod_256
        ((b"\xFF\xFF", b"\x01\x01"), b"\x00\x00", None),

        # test_multiple_additions (equality between two runs)
        ((b"hello world!", b"abc"), None, lambda out: out == Encryptor._ascii_addition_bytes(b"hello world!", b"abc")),

        # test_uneven_lengths
        ((b"123456789", b"ab", b"XY"), None, lambda out: isinstance(out, bytes) and len(out) == 9),

        # test_with_empty
        ((b"abcdef", b""), b"abcdef", None),

        # test_only_one_argument
        ((b"single",), b"single", None),

        # test_all_same_length
        ((b"1111", b"2222", b"3333"), None, lambda out: isinstance(out, bytes) and len(out) == 4),

        # test_result_type_and_length
        ((b"longest string wins", b"short"), None, lambda out: isinstance(out, bytes) and len(out) == len(b"longest string wins")),
    ]
)
def test_ascii_addition_bytes(inputs, expected, custom_check):
    result = Encryptor._ascii_addition_bytes(*inputs)
    if custom_check is not None:
        assert custom_check(result)
    else:
        assert result == expected

@pytest.mark.parametrize(
    "username,salt_,expected",
    [
        (b"BOB", "8GIB0nWfBIpu+nwuo/Wiqg==", "4gXItT7UElI54BDjpIHfaDphLM4oZc7W1H9R7Veq2lM="),
        (b"John", "Qbaf5hrwHGNviSKP+v71/w==", "SWsk8Rt9xx8WbeggY9QUNu5HhkTnYMhjk8/1usFUKVM="),
        (b"Marie :)", "5LpsadjfH4SIovl6oA2hqA==", "HEd6rO1Z/wp+9960zavpXbD9JQZeHsBcixWJErUN8xE="),
        (b"Valerie", "vejTfpREG3JRPbuuw5Yuqw==", "u2OzXzcG2NLT5yHKTCUjJvOOFTfKmeDry+7IWx/qWhc=")
    ]
)
def test_generate_username_key(username, salt_, expected):
    salt_ = Converter.b64_to_byte(salt_)
    key, salt = Encryptor(True).generate_username_key(username, salt=salt_)
    assert Converter.byte_to_b64(key) == expected and salt == salt_

@pytest.mark.parametrize(
    "username,salt_,nonce_,expected",
    [
        (b"BOB", "8GIB0nWfBIpu+nwuo/Wiqg==", "ZJjRIavpNbVg9E1wb7pe4pA5C10tvtW4DAdvyUeGQBc=", "M7rc"),
        (b"John", "Qbaf5hrwHGNviSKP+v71/w==", "7hpvhw0h4WGcs0mmI7VKa9ZFTon/bZG/zPv94uajx8E=", "hUbLWg=="),
        (b"Marie :)", "5LpsadjfH4SIovl6oA2hqA==", "iAjDj3/vfmeDFytQA7oKa4DHU2uQsYoMvSNrbmhVgD0=", "Fg0SaOm/cqI="),
        (b"Valerie", "vejTfpREG3JRPbuuw5Yuqw==", "89wEGJ5OTno72Aoj1RbIkH9UsUrpNmRLSb1pxHrJibA=", "hcCSV3+Xuw==")
    ]
)
def test_encrypt_username(username, salt_, nonce_, expected):
    salt_ = Converter.b64_to_byte(salt_)
    nonce_ = Converter.b64_to_byte(nonce_)
    en_username, nonce, *_ = Encryptor(True).encrypt_username(username, salt=salt_, nonce=nonce_)
    assert Converter.byte_to_b64(en_username) == expected
    assert nonce == nonce_

@pytest.mark.parametrize(
    "en_username,nonce_,tag,salt_,expected",
    [
        ("M7rc", "ZJjRIavpNbVg9E1wb7pe4pA5C10tvtW4DAdvyUeGQBc=", "kVVY7JxQO/sKZ6kCco4iww==", "8GIB0nWfBIpu+nwuo/Wiqg==", b"BOB"),
        ("hUbLWg==", "7hpvhw0h4WGcs0mmI7VKa9ZFTon/bZG/zPv94uajx8E=", "C4V4ii/+m/PIciVLofYq0w==", "Qbaf5hrwHGNviSKP+v71/w==", b"John"),
        ("Fg0SaOm/cqI=", "iAjDj3/vfmeDFytQA7oKa4DHU2uQsYoMvSNrbmhVgD0=", "k7YxX9I7y7AFhPXnoFTV5A==", "5LpsadjfH4SIovl6oA2hqA==", b"Marie :)"),
        ("hcCSV3+Xuw==", "89wEGJ5OTno72Aoj1RbIkH9UsUrpNmRLSb1pxHrJibA=", "vWUnMI3WZygCzaQ6xXY/nQ==", "vejTfpREG3JRPbuuw5Yuqw==", b"Valerie")
    ]
)
def test_decrypt_username(en_username, nonce_, tag, salt_, expected):
    nonce_ = Converter.b64_to_byte(nonce_)
    salt_ = Converter.b64_to_byte(salt_)
    tag = Converter.b64_to_byte(tag)
    en_username = Converter.b64_to_byte(en_username)
    user_key, _ = Encryptor(True).generate_username_key(expected, salt=salt_)
    plain = Encryptor(True).decrypt_username(en_username, nonce_, tag, user_key)
    assert plain == expected

@pytest.mark.parametrize(
    "data,nonce,expected",
    [
        (b"Alles ist super", "bTeT10RozAMaONJN/kYt9+WrZ4U1ovdEYzXHlYW+OWo=", "bTeT10RozAMaONJN/kYt9+WrZ4U1ovdEYzXHlYW+OWqGTeyS2XGMYNjxKHnFbIE6MTi5ve5kOHmKm3Oq3pQH"),
        (b"Wo ist meine Cola?", "1j27sV1JRItbxG1+d7S5llyAfTvxeD8Rh2cn0Sq8C64=", "1j27sV1JRItbxG1+d7S5llyAfTvxeD8Rh2cn0Sq8C64KgDsSbdOCikcj29MkVG22lQAfiMyXtEvHkjlUHfSa6dnq"),
        ("Meine Chicken Nuggets verbrennen 🔥🔥🔥".encode(), "y8M5okQ3jeh9NgSBXHeBgaC+V03n1UbnvPlmNYf0GPo=", "y8M5okQ3jeh9NgSBXHeBgaC+V03n1UbnvPlmNYf0GPrzfGRZrIjHkBMBqOyKhf43Uy49yT4iftzu13KgZOpeh0Xv9LXQvnNpjgFkFsJCCyw9dF7Rnhk4p573hBWq"),
        (b"Wo... wo bin ich?", "cq8Io6lz+KiokVPu7byOeoG279SNsfAx1AbEBdiKUs0=", "cq8Io6lz+KiokVPu7byOeoG279SNsfAx1AbEBdiKUs1d/Q7MEeJr/fBAUjfnLmv/rSsD/Xwwx7nooIGfU/9rEiA=")
    ]
)
def test_encrypt_system_data(data, nonce, expected):
    nonce = Converter.b64_to_byte(nonce)
    all_ = Encryptor(True).encrypt_system_data(data, nonce=nonce)
    assert all_ == Converter.b64_to_byte(expected)

@pytest.mark.parametrize(
    "en_data,expected",
    [
        ("bTeT10RozAMaONJN/kYt9+WrZ4U1ovdEYzXHlYW+OWqGTeyS2XGMYNjxKHnFbIE6MTi5ve5kOHmKm3Oq3pQH", b"Alles ist super"),
        ("1j27sV1JRItbxG1+d7S5llyAfTvxeD8Rh2cn0Sq8C64KgDsSbdOCikcj29MkVG22lQAfiMyXtEvHkjlUHfSa6dnq", b"Wo ist meine Cola?"),
        ("y8M5okQ3jeh9NgSBXHeBgaC+V03n1UbnvPlmNYf0GPrzfGRZrIjHkBMBqOyKhf43Uy49yT4iftzu13KgZOpeh0Xv9LXQvnNpjgFkFsJCCyw9dF7Rnhk4p573hBWq", "Meine Chicken Nuggets verbrennen 🔥🔥🔥".encode()),
        ("cq8Io6lz+KiokVPu7byOeoG279SNsfAx1AbEBdiKUs1d/Q7MEeJr/fBAUjfnLmv/rSsD/Xwwx7nooIGfU/9rEiA=", b"Wo... wo bin ich?")
    ]
)
def test_decrypt_system_data(en_data, expected):
    plain = Encryptor(True).decrypt_system_data(Converter.b64_to_byte(en_data))
    assert plain == expected

def test_validate_hash():
    message = b"my pants are on fire"
    hash_ = hashlib.sha512()
    hash_.update(message)
    hash_ = hash_.digest()
    assert Encryptor.validate_hash(message, hash_, HashingAlgorithm.sha512)

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
