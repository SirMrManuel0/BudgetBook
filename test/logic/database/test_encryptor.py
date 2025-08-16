import hashlib

import pytest

from budget_book import VaultType
from budget_book.logic.database.encryptor import Encryptor, Converter, HashingAlgorithm

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

@pytest.mark.parametrize(
    "data,nonce,aad,enc_header",
    [
        (b"Alles ist super", "nFnaoZaf2M3MGA5Dx0g1K9f1M3qOFndN", b"This is an informatial header", b"Some sort of header ig"),
        (b"Wo ist meine Cola?", "jqDO/Di4zq2ogvX6rZJKt2Z/+89AXIgF", b"Headers can be important", b"a header can only save non-secrets"),
        ("Meine Chicken Nuggets verbrennen 🔥🔥🔥".encode(), "HmqKb9eq4jFAYybFywrW+2lmUA6P96eI", b"ups, forgot the aad", b"a header has mostly genereic info"),
        (b"Wo... wo bin ich?", "ZIuaPfgsMAIl5IN46ynWbj0TP+qNKPpl", b"hmmm, this could be useful", b"i am not wise enough for another")
    ]
)
def test_de_encrypt_system_data(data, nonce, aad, enc_header):
    encryptor = Encryptor(True, test=True)
    nonce = Converter.b64_to_byte(nonce)
    en_data = encryptor.encrypt_system_data(data, nonce, aad, encryption_header=enc_header)
    _, plain, encryption_header, aad_ = encryptor.decrypt_system_data(en_data)
    assert plain == data
    assert encryption_header == enc_header
    assert aad == aad_

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

@pytest.mark.parametrize(
    "data,aad_opt,encryption_header",
    [
        (b"some data ig", b"whatever an aad is", b"an ... encryptin header? whats that lol"),
        (b"some data ig", b"whatever an aad is", None),
        (b"some data ig", None, b"an ... encryptin header? whats that lol"),
        (b"some data ig", None, None),
        (Converter.b64_to_byte("gUxW+lp9rH9lEAOWg5/qEdhIcy6lF0j9s28N6xE7JNwm+Ro6dwi9nd6magB0OubtqrkGkMjq8wu2MrR0ohprkriSBMt7LO17b9ibYPqM26NAGgsfYCEufNL3XTmP43bq9zLONZ8dAs2DcjJTIkrtmgrq+Ffk1p2WF7fezdOKownsQ+CGURQT1EQ3mqUt/4LEM9PRsYrMhdJCgGbikhODrz+pYbKrpOuDG2J/r4RAPgkcDw20copvm6/1rWSXJxXkid79Or1yJZNY6pQzdcYaHeFzFi2YBiFPDkEU9qjD09G9dVNPffFva5eXUC3Jhwp7OZXf9qpyDVjHpNQ+EiOuSU+QxsK/pYwaS0svTnipXzFjQS4S464Q+xf4If8jP9Cnr8MUtm146Yg0VqhkIYHS6bb+ACYMJsIUivcBN/wponMXfJRrFmEOIYyfz9nMmjFixg9Q+MWhhAbkPcho7kYG+p5FQHLD7LBq4I6nAKzaqPbci6mGLkbL30QHFzBEi5R5Dt1p/nkO3fOUjDbi/ROxuYjRQ6aMe3Lbvr6YutHH3RdAcGTxcG4Wod8ONpmd7y8HyK+3pUSQN/DVnr7nO5+OvYK5BUr8z45NfxbwZVnoDi8BAFSc4xHniVjLWUtZjjv6D2xzGh6luAmS0tC64DQ2rm5AQpdyHhMDf2cRc+FvgiY="),
         None, None),
        (Converter.b64_to_byte("gUxW+lp9rH9lEAOWg5/qEdhIcy6lF0j9s28N6xE7JNwm+Ro6dwi9nd6magB0OubtqrkGkMjq8wu2MrR0ohprkriSBMt7LO17b9ibYPqM26NAGgsfYCEufNL3XTmP43bq9zLONZ8dAs2DcjJTIkrtmgrq+Ffk1p2WF7fezdOKownsQ+CGURQT1EQ3mqUt/4LEM9PRsYrMhdJCgGbikhODrz+pYbKrpOuDG2J/r4RAPgkcDw20copvm6/1rWSXJxXkid79Or1yJZNY6pQzdcYaHeFzFi2YBiFPDkEU9qjD09G9dVNPffFva5eXUC3Jhwp7OZXf9qpyDVjHpNQ+EiOuSU+QxsK/pYwaS0svTnipXzFjQS4S464Q+xf4If8jP9Cnr8MUtm146Yg0VqhkIYHS6bb+ACYMJsIUivcBN/wponMXfJRrFmEOIYyfz9nMmjFixg9Q+MWhhAbkPcho7kYG+p5FQHLD7LBq4I6nAKzaqPbci6mGLkbL30QHFzBEi5R5Dt1p/nkO3fOUjDbi/ROxuYjRQ6aMe3Lbvr6YutHH3RdAcGTxcG4Wod8ONpmd7y8HyK+3pUSQN/DVnr7nO5+OvYK5BUr8z45NfxbwZVnoDi8BAFSc4xHniVjLWUtZjjv6D2xzGh6luAmS0tC64DQ2rm5AQpdyHhMDf2cRc+FvgiY="),
         b"Some extreeeemly", b"loooong data"),
    ]
)
def test_en_decrypt_file(data: bytes, aad_opt: bytes, encryption_header: bytes):
    encryptor = Encryptor(True, test=True)
    encryptor.gen_ecc_private_key(VaultType("private"))
    en = encryptor.encrypt_file(data, VaultType("private"), aad_opt=aad_opt, encryption_header=encryption_header)
    _, de, de_enc, de_aad = encryptor.decrypt_file(en, VaultType("private"))
    assert data == de
    if encryption_header is not None:
        assert encryption_header == de_enc
    if aad_opt is not None:
        assert aad_opt == de_aad

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
