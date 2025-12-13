import hashlib
import json
import secrets
import pandas
import pytest

from io import StringIO

from backend.budget_book import VaultType
from backend.budget_book.logic.encryptor import Encryptor, converter, HashingAlgorithm

@pytest.mark.parametrize(
    "username,userkey_name,salt_,expected",
    [
        (b"BOB", "username", "gH/hjB59ZDcQgyIhkbqDC4/R/HRW5kggddUKYsKwTNg=", "LMqaKLroocfAGa/ORio0vbdiS2veNNza/qqeJcE3dhI="),
        (b"John", "userkey", "dbdWfcK3kyxL5avx5JIDsYVTPQkqXH00KeoGn1v5oqs=", "ZWLDCpOdrM0zZ++/tJDuf9NVtX4RKayhyonFuFAUqv0="),
        (b"Marie :)", "usercan", "cDCfpk/s5oUsG3EAsaS74sguudHz3O1OwPD5vJLHip8=", "/RPH98D76ZaWDnN490HojPsBxRSCGs8KXB5YeEaQPu8="),
        (b"Valerie", "i am not creative enough", "lWokscBf1/FJ3622WVu8/UPUPQTpae8xVaIDJh4/5PU=", "uCoHlRUWfKnJUSRmb05vM8jMJika9LvA3ZkgeiZem/E=")
    ]
)
def test_generate_username_key(username, userkey_name, salt_, expected):
    salt_ = Converter.b64_to_byte(salt_)
    e = Encryptor(True, test=True)
    salt = e.generate_username_key(userkey_name, salt_)
    #a = e._access_encryptor()
    #print(Converter.byte_to_b64(a.get_secret(VaultType(userkey_name), True)))
    assert e.compare_with_secret(VaultType(userkey_name), Converter.b64_to_byte(expected))
    assert salt == salt_

@pytest.mark.parametrize(
    "username,salt_,nonce_,expected",
    [
        (b"BOB", "GXbQzmplolDL4ljQ00nhzcfa8oTnDDA2/44ziFCF2K0=", "5ud1YOfGmSBfNiACD53Yd6GRoFEBlY4j", "cxsqj9hmtKsSaHlplvf22M5rPA=="),
        (b"John", "UHx6ilJKfTSFiJu4nPDA6X0GLq2/37L4WhQqbSxxkjg=", "LgDHXTaWsM4BPHlzrXYO6G/uGz8Jua8s", "X6Ax4PmKQKwo9TJgcDN6RcrpBYE="),
        (b"Marie :)", "mjLO6K1jOKWewTV+JG5Pk98PRk47vs9DwZi+Eh8N15U=", "pptveTpkE0zBePbt1dafbxT8KOvHrYN6", "Qbj+FEp1owdX8DdZlscicbNKGJYJVwkC"),
        (b"Valerie", "o0iC2Qh21rMc0tWrs5uI7a1xsgGmgQ2Eb5+529VmKAo=", "idTZcmnxBNhpVPOHLyHNIdK0VYLScJxE", "WeR1Qu5bS7+mt3XVuXFJOP3iIfzV4FY=")
    ]
)
def test_encrypt_username(username, salt_, nonce_, expected):
    salt_ = Converter.b64_to_byte(salt_)
    nonce_ = Converter.b64_to_byte(nonce_)
    encryptor = Encryptor(True, test=True)
    ciphertext, nonce, _ = encryptor.encrypt_username(username, salt_, nonce_)
    #print(Converter.byte_to_b64(ciphertext))
    assert Converter.byte_to_b64(ciphertext) == expected
    assert nonce == nonce_

@pytest.mark.parametrize(
    "en_username,nonce_,salt_,expected",
    [
        ("cxsqj9hmtKsSaHlplvf22M5rPA==", "5ud1YOfGmSBfNiACD53Yd6GRoFEBlY4j", "GXbQzmplolDL4ljQ00nhzcfa8oTnDDA2/44ziFCF2K0=", b"BOB"),
        ("X6Ax4PmKQKwo9TJgcDN6RcrpBYE=", "LgDHXTaWsM4BPHlzrXYO6G/uGz8Jua8s", "UHx6ilJKfTSFiJu4nPDA6X0GLq2/37L4WhQqbSxxkjg=", b"John"),
        ("Qbj+FEp1owdX8DdZlscicbNKGJYJVwkC", "pptveTpkE0zBePbt1dafbxT8KOvHrYN6", "mjLO6K1jOKWewTV+JG5Pk98PRk47vs9DwZi+Eh8N15U=", b"Marie :)"),
        ("WeR1Qu5bS7+mt3XVuXFJOP3iIfzV4FY=", "idTZcmnxBNhpVPOHLyHNIdK0VYLScJxE", "o0iC2Qh21rMc0tWrs5uI7a1xsgGmgQ2Eb5+529VmKAo=", b"Valerie")
    ]
)
def test_decrypt_username(en_username, nonce_, salt_, expected):
    nonce_ = Converter.b64_to_byte(nonce_)
    salt_ = Converter.b64_to_byte(salt_)
    en_username = Converter.b64_to_byte(en_username)
    encryptor = Encryptor(True, test=True)
    plain = encryptor.decrypt_username(en_username, salt_, nonce_)
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
    e = Encryptor(True, test=True)
    e.add_secret(VaultType("cool"), Converter.utf_to_byte(pw))
    assert e.recreate_hash("cool", Converter.b64_to_byte(salt)) == expected

def test_key_file():
    encryptor: Encryptor = Encryptor(is_system=False, test=True)
    encryptor.generate_key_file()
    assumed_file_id: str = Converter.int_to_b64(0, False)
    id_: str = encryptor._new_entry()
    assert id_ == assumed_file_id
    id_: bytes = Converter.b64_to_byte(id_)
    id_len: bytes = Converter.int_to_bytes(len(id_), False, 5)
    file: bytes = id_len + id_ + b"This is a file."
    encryptor._add_file_verification(file)
    encryptor._encryptor.add_secret(VaultType("password"), secrets.token_bytes(32))
    key_file = encryptor.get_key_file("password")
    encryptor.set_key_file("password", key_file)
    assert len(encryptor._key_file.keys()) == 1 and assumed_file_id in encryptor._key_file.keys()
    hash_ = hashlib.sha512(file)
    hashed = hash_.digest()
    assert encryptor._key_file[assumed_file_id]["hash"] == Converter.byte_to_b64(hashed)
    encryptor.remove_secret(VaultType("password"))

@pytest.mark.parametrize(
    "csv",
    [
        "id,value\n1,10\n2,20\n3,30",
        "name,age,active\nAlice,30,True\nBob,25,False\nCharlie,40,True",
        "date,temperature\n2024-01-01,23.5\n2024-01-02,21.8\n2024-01-03,19.4",
        "id,description\n1,\"Hello, world\"\n2,\"Value, with comma\"\n3,\"Another, test\"",
        "id,a,b,c\n1,10,,30\n2,,20,\n3,5,6,7",
        "flag,count\nTrue,5\nFalse,10\nTrue,0",
        "user_id,username,email\n1,jdoe,jdoe@example.com\n2,asmith,asmith@example.com\n3,mbrown,mbrown@example.com",
        "id,text\n1,\"Emoji 😀\"\n2,\"Symbols #$%^&*\"\n3,\"Unicode ✓\"",
        "id,notes\n1,\"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\"\n2,\"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\"\n3,\"Ut enim ad minim veniam.\"",
        "a,b,c,d\n10,20,30,40\n5,15,25,35\n7,14,21,28"
    ]
)
def test_en_decrypt_et(csv):
    encryptor = Encryptor(test=True, is_system=False)
    encryptor.generate_key_file()
    df = pandas.read_csv(StringIO(csv))
    encrypted = encryptor.encrypt_et(df)
    decrypted = encryptor.decrypt_et(encrypted)
    assert df.equals(decrypted)

@pytest.mark.parametrize(
    "js",
    [
        "{\"a\": 1, \"b\": 2}",
        "{\"name\": \"Alice\", \"age\": 30}",
        "{\"x\": 10, \"y\": 20, \"z\": 30}",
        "{\"id\": 1, \"tags\": [\"red\", \"blue\"]}",
        "{\"active\": true, \"count\": 5}",
        "{\"pi\": 3.14, \"e\": 2.718}",
        "{\"user\": {\"id\": 1, \"name\": \"Bob\"}}",
        "{\"items\": [1, 2, 3, 4]}",
        "{\"status\": \"ok\", \"error\": null}",
        "{\"key\": \"value\", \"numbers\": [10, 20, 30]}"
    ]
)
def test_en_decrypt_ej(js):
    encryptor = Encryptor(test=True, is_system=False)
    encryptor.generate_key_file()
    js = json.loads(js)
    encrypted = encryptor.encrypt_ej(js)
    decrypted = encryptor.decrypt_ej(encrypted)
    assert decrypted == js

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
