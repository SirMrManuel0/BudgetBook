import hashlib

import pytest

from budget_book import VaultType
from budget_book.logic.database.encryptor import Encryptor, Converter, HashingAlgorithm


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
    "username,userkey_name,salt_,expected",
    [
        (b"BOB", "username", "8GIB0nWfBIpu+nwuo/Wiqg==", "Gl33KKFujdPZ/ACbPQxWXj/BCSI7N6oggIHpl0358Ek="),
        (b"John", "userkey", "Qbaf5hrwHGNviSKP+v71/w==", "fsXAX62ChBtbLzm/gsDGYlJKd0hXeLe4r+KtFxQXNbU="),
        (b"Marie :)", "usercan", "5LpsadjfH4SIovl6oA2hqA==", "XOUqVBKa8Q0trXwbXvJHBez1RU7DASnHDDIWMh3PX6M="),
        (b"Valerie", "i am not creative enough", "vejTfpREG3JRPbuuw5Yuqw==", "PLOYoRIrNYojYEqC7QVq/K8hIwAj3XBmOF4B5FwcgAE=")
    ]
)
def test_generate_username_key(username, userkey_name, salt_, expected):
    salt_ = Converter.b64_to_byte(salt_)
    e = Encryptor(True)
    salt = e.generate_username_key(username, userkey_name, salt_)
    assert e.compare_with_secret(VaultType(userkey_name), Converter.b64_to_byte(expected)) and salt == salt_

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

@pytest.mark.parametrize(
    "pw,salt,expected",
    [
        ("Ich backe Kuchen", "yusVp7tFoOpVrvzkTSp87A", "$argon2id$v=19$m=65536,t=3,p=3$yusVp7tFoOpVrvzkTSp87A$s+6PxfRMTcu9FRVYpWxtYb8zGkI9rSHexepWc2QOuMQOHo60bK2UzhcAB6CbtKfbjHxe6Irdh2TBKXrZ87AVeQ"),
        ("Meine Chickennuggets verbrennen", "Xklcdb7DNVfCSSUO98Jbvw", "$argon2id$v=19$m=65536,t=3,p=3$Xklcdb7DNVfCSSUO98Jbvw$DuzJfxDAeg9ZdlB8ji1ibo6kZoETKLQetb1ToskP1ZPvUzeXsmc0NM+T02WVypYGyMKHmYmi1QpI/Zl1C2duoA"),
        ("Peterle ist ein Dorfkind", "uA9pEOcaEVX3Qh1gXWHW/g", "$argon2id$v=19$m=65536,t=3,p=3$uA9pEOcaEVX3Qh1gXWHW/g$qnnLqSwuIN4OyED1ey76UrJJSnyFgH/+tixZFP1n+41nDd4hGttr9AFxYLGQk+oET0q+3rcExfEoMHG8dx7LSQ"),
        ("superSecure1234567899897984198/463841+-968496932q543", "9UKOlbehTTisGNyEL2LDqw", "$argon2id$v=19$m=65536,t=3,p=3$9UKOlbehTTisGNyEL2LDqw$2gIfYGpMoIKbB7XPVkfWKGfGJ8M3syOkVbOfMrXsuL8wMzJ2WhL5ud+cAvMfQYnggqU/gzr1SHo2mPiuLVFfDg"),
        ("Wo ist die erde?", "2M6nAWvPaXkSjeaBiK/GOQ", "$argon2id$v=19$m=65536,t=3,p=3$2M6nAWvPaXkSjeaBiK/GOQ$Ff0ZeE3zMQkOTjvo6hh2bb3eSESGb5vdXRxDd2tSzGxgt+y4YXJ0AMH6OGamlVuDAB2jXWa8AwGPUK+kW6tokA")
    ]
)
def test_recreate_hash(pw, salt, expected):
    assert Encryptor.recreate_hash(Converter.utf_to_byte(pw), Converter.b64_to_byte(salt)) == expected

def test_private_key():
    e = Encryptor(True)
    key = e.create_private_key()
    serialized = e.serialize_private_key(key)
    deserialized = e.deserialize_private_key(serialized)
    assert key.private_numbers() == deserialized.private_numbers()

@pytest.mark.parametrize(
    "pw,a",
    [
        (b"Ich backe Kuchen", ""),
        (b"Meine Chickennuggets verbrennen", ""),
        (b"Peterle ist ein Dorfkind", ""),
        (b"superSecure1234567899897984198/463841+-968496932q543", ""),
        (b"Wo ist die erde?", "")

    ]
)
def test_encrypt_and_decrypt_private_key(pw, a):
    e = Encryptor(True)
    private_key = e.create_private_key()
    enc, salt, nonce = e.encrypt_private_key(bytearray(pw), private_key)
    dec = e.decrypt_private_key(bytearray(pw), enc, nonce, salt)
    des = e.deserialize_private_key(dec)
    assert private_key.private_numbers() == des.private_numbers()

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
