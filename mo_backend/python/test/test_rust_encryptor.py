import pytest
import secrets

from backend.budget_book import RustEncryptor, VaultType
from backend.budget_book.logic.database import Converter


@pytest.mark.parametrize(
    "vt,plain,key,nonce,aad_opt,expected",
    [
        (VaultType.chacha_key(), b"Hello", None, None, None, None),
        (VaultType.password(), b"Hello",
         Converter.b64_to_byte("wc9mYoi1UUA0wG69TuXTQg1Gb6RTrWBxun3Ihqkvp3g="),
         Converter.b64_to_byte("+SaGQ5UEjeTC1I97XA3FaH5c0bht+nMq"), None,
         Converter.b64_to_byte("vjbfJ0g3I3qY6lmt7ddS8KLMyL3V")),
        (VaultType("Tarot"), b"Praise the Fool", None, None, b"Justice", None),
        (VaultType("Tarot"), b"Praise the Fool",
         Converter.b64_to_byte("cOyHT2v5R+E+GPCfcD6iWZQGstfQXcNoQphwmCFr7zw="),
         Converter.b64_to_byte("LFBuobpPAV3qshOVWgifx+Op8c+xAgVu"), b"Justice",
         Converter.b64_to_byte("fe3Z7dHN4I3gxEBrdNInNKqwWQ2m0z1ttTCQhYq9zA=="))
    ]
)
def test_de_encrypt(vt: VaultType, plain: bytes, key: bytes, nonce: bytes, aad_opt: bytes, expected: bytes):
    encryptor = RustEncryptor(True)
    key = key if key is not None else secrets.token_bytes(32)
    if key is not None:
        encryptor.add_secret(vt, key)
    no, ciphertext = encryptor.encrypt_chacha(plain, nonce, aad_opt, vt)
    if expected is not None and nonce is not None:
        assert ciphertext == expected
    with pytest.raises(Exception):
        encryptor.decrypt_chacha(
            ciphertext, no, vt,
            b"Hello" if aad_opt is None else None
        )
    vt = vt if vt is not None else VaultType.chacha_key()
    decrypted = encryptor.decrypt_chacha(ciphertext, no, vt, aad_opt)
    assert plain == decrypted

@pytest.mark.parametrize(
    "vt,plain,hash_len,salt_len,salt,expected",
    [
        (VaultType.chacha_key(), b"Hello", None, None, None, None),
        (VaultType.chacha_key(), Converter.utf_to_byte("I am happy 😁"), 32, None, None, None),
        (VaultType.chacha_key(), b"God is dead - a certain philosopher", 128, None, None, None),
        (VaultType.chacha_key(), b"Hello", None, None, Converter.b64_to_byte("PCuYR/1fmT9ASqxczoIjug"),
         "$argon2id$v=19$m=65536,t=3,p=3$PCuYR/1fmT9ASqxczoIjug$lkKmdIxl0KXoDHuwXmw+7bgbHJeuqbkTj5LuOKKFbuCaQgYMz/kFwzUeRW9mS24pxpWSO7Z6e/h4xzJqww/J0g"),
        (VaultType.chacha_key(), Converter.utf_to_byte("I am happy 😁"), 32, None,
         Converter.b64_to_byte("QAutChBCw139gH3Xqzvlow"), "$argon2id$v=19$m=65536,t=3,p=3$QAutChBCw139gH3Xqzvlow$vyd6s6mknCSRsiW58Aah775EoS4svPzmf0WOyaz8HSs"),
        (VaultType.chacha_key(), b"God is dead - a certain philosopher", 128, None,
         Converter.b64_to_byte("zqDHCHA+uSCAQrJwmgX1TQ"), "$argon2id$v=19$m=65536,t=3,p=3$zqDHCHA+uSCAQrJwmgX1TQ$qIWLmOYIKqElI2IYSWMjcofl3nLblfjxyqP/n1bgPJNzpcIamOfqQPjUmD2nTlpF5DfYAV5EV1PykPf1zZaGEz2ukrtQPvuSwgRjgMAuUQcl2VWim1E33pa0WNu3XofDssJk+htEFyupYbk4GixiLjh2IihIscGhRAg6CyxdGgI"),
        (VaultType.chacha_key(), b"Hello", None, 32, None, None),
        (VaultType.chacha_key(), Converter.utf_to_byte("I am happy 😁"), 32, 48, None, None),
        (VaultType.chacha_key(), b"God is dead - a certain philosopher", 128, 64, None, None),
        (VaultType.chacha_key(), b"Hello", None, 32, Converter.b64_to_byte("pQpvAlS+R6ikyoODTER+fRyn5gParfYUGAG3Isk/udg"), "$argon2id$v=19$m=65536,t=3,p=3$pQpvAlS+R6ikyoODTER+fRyn5gParfYUGAG3Isk/udg$KRk/D4BGwu1kiJoDl3EF2vcDakcEH3bzILXFZ62hN/ut8jO6ymneBYlh7YAOoqpBvxO/7a2uAGU+XMayZ4fU9A"),
        (VaultType.chacha_key(), Converter.utf_to_byte("I am happy 😁"), 32, 48, Converter.b64_to_byte("fLMDqYv8h4q9+SYPd9Z7M5QxvAQTNFTl/BBAA+feYa1WUL4idSq+QetsbBBkNPVC"), "$argon2id$v=19$m=65536,t=3,p=3$fLMDqYv8h4q9+SYPd9Z7M5QxvAQTNFTl/BBAA+feYa1WUL4idSq+QetsbBBkNPVC$YsvTb30/Hk2uZHLRIGiyn61adCKF6xY6lqn2MfrHopc"),
        (VaultType.chacha_key(), b"God is dead - a certain philosopher", 128, 64, Converter.b64_to_byte("utUtW+I7tqSIU3T+vZDQzOazFe+xvEJ1jihtLSOyTH3ghazFx+wiMhwa7LaEaelayHvrt3gkOssGyjXsJ7ZPlg"), "$argon2id$v=19$m=65536,t=3,p=3$utUtW+I7tqSIU3T+vZDQzOazFe+xvEJ1jihtLSOyTH3ghazFx+wiMhwa7LaEaelayHvrt3gkOssGyjXsJ7ZPlg$hJVVUewd1H/5LZaQRcFRuAfbWVxYf3MeK4BPha5C9CQ+qOcf30soU5eSfRTH2Tu3scOwZf/lLay0m78bxDwpXikMXVTmk3FgX4yru+8Lha35Ra/89G/PxgRhXUaFl69d7H8sGs8/r7SPFQHY9xLkhfHM9dOgx358cXFZ38uQ0AA"),
    ]
)
def test_hash(vt: VaultType, plain: bytes, hash_len: int, salt_len: int, salt: bytes, expected: str):
    encryptor = RustEncryptor(True)
    encryptor.add_secret(vt, plain)
    hashed = encryptor.hash_pw(vt, hash_len, salt_len, salt)
    if expected is not None:
        assert hashed == expected
    assert encryptor.is_eq_argon(vt, hashed)

@pytest.mark.parametrize(
    "vt,enc_key,secret_,from_key,store_key,nonce,aad_opt,expected",
    [
        (VaultType.chacha_key(), Converter.b64_to_byte("QRWU1UYE8jJXsqGhgvBoAobEo/MllnsoCqw/fmJbM+4="),
         Converter.b64_to_byte("IfcPgqx6TicPWC2ftNO2U/S/PiMCputNrLc1OJNfbv8="), VaultType.password(), VaultType("StoreHere"), None, None, None),
        (VaultType.chacha_key(), Converter.b64_to_byte("I/T9LRX44q2keYiLqQHUB9SrolyO/quA1QQDmOVlGfk="),
         Converter.b64_to_byte("4sgOgWitt6//lkmHcXs2V/1ip1GmxGJHoVR5ho8DHns="), VaultType.password(), VaultType("StoreHere"),
         Converter.b64_to_byte("sJCysVfSAGrh1DNOv2WhKnGAwP2PEWfp"), b"PRAISE THE FOOL!!!", Converter.b64_to_byte("uxTWMZ9RzAex6WrSCyR3YtkRA9/tZkbRn69YVDr4DxBqed5gxfX/aXUnuanc8D8u")),
    ]
)
def test_vault(vt: VaultType, enc_key: bytes, secret_: bytes, from_key: VaultType, store_key: VaultType, nonce: bytes, aad_opt: bytes, expected: bytes):
    encryptor = RustEncryptor(True)
    vt = vt if vt is not None else VaultType.chacha_key()
    encryptor.add_secret(vt, enc_key)
    encryptor.add_secret(from_key, secret_)
    no, ciphertext = encryptor.encrypt_key_chacha(from_key, store_key, None if vt == VaultType.chacha_key() else vt, nonce, aad_opt)
    if expected is not None:
        assert ciphertext == expected
    plain = encryptor.decrypt_chacha(ciphertext, no, vt, aad_opt)
    assert plain == secret_
    ciph = encryptor.get_secret(store_key)
    assert ciph == no + ciphertext
    enc = encryptor.get_secret(vt, True)
    assert enc == enc_key
    encryptor.remove_secret(vt)
    encryptor.clear_secrets()

@pytest.mark.parametrize(
    "a,b,vt_a,vt_b,store_secret,store_key,store_secret_2,store_key_2,expected,is_b_pub",
    [
        (None, None, VaultType.static_private_key(), VaultType.eph_private_key(), VaultType.shared_secret(), VaultType.chacha_key(), VaultType.private_key(), VaultType.public_key(), None, False),
        (Converter.b64_to_byte("m/wEF8O3fV0cHsVJ3qHa48iePi3jEvaWQVS81HeQ/Gw="), Converter.b64_to_byte("sGOh5lbcKsEdZb3ValU7HJcKrPt0D2ftEn6O29meysk="), VaultType.static_private_key(), VaultType.eph_private_key(), VaultType.shared_secret(), VaultType.chacha_key(), VaultType.private_key(), VaultType.public_key(), Converter.b64_to_byte("DRa8YtgF16g0sJxmIH/6K7tT/Y/te8kTM17TDEkWM2k="), False)
    ]
)
def test_ecdhe(a: bytes, b: bytes, vt_a: VaultType, vt_b: VaultType,
               store_secret: VaultType, store_key: VaultType, store_secret_2: VaultType, store_key_2: VaultType,
               expected: bytes, is_b_pub: bool):
    encryptor = RustEncryptor(True)
    if a is None:
        encryptor.gen_static_private_key(vt_a)
    else:
        encryptor.add_secret(vt_a, a)
    if b is None:
        encryptor.gen_eph_private_key(vt_b)
    else:
        encryptor.add_secret(vt_b, b)
    encryptor.find_shared_secret(store_secret, vt_a, vt_b, is_b_pub)
    encryptor.derive_key(store_key, store_secret)

    encryptor.find_shared_secret(store_secret_2, vt_a, vt_b, is_b_pub)
    encryptor.derive_key(store_key_2, store_secret_2)

    assert encryptor.compare_secrets(store_key, store_key_2)

    if expected is not None:
        generated = encryptor.get_secret(store_key, True)
        assert generated == expected

@pytest.mark.parametrize(
    "b,salt,expected",
    [
        (b"Here is somthing to derive a key from", b"this is a salt", Converter.b64_to_byte("iBq/XjJYYDqDfjHsdRIJtOIioIdErBO7hnFws62J9I8=")),
        (b"Here is somthing to derive a key from", secrets.token_bytes(32), None),
        (secrets.token_bytes(64), secrets.token_bytes(32), None),
    ]
)
def test_derive_key(b: bytes, salt: bytes, expected: bytes):
    encryptor = RustEncryptor(True)
    encryptor.add_secret(VaultType("from"), b)
    encryptor.derive_key(VaultType("store"), VaultType("from"), salt)
    encryptor.derive_key(VaultType("store2"), VaultType("from"), salt)
    if expected is not None:
        encryptor.add_secret(VaultType("expected"), expected)
        assert encryptor.compare_secrets(VaultType("store"), VaultType("expected"))
    assert encryptor.compare_secrets(VaultType("store"), VaultType("store2"))

@pytest.mark.parametrize(
    "a,b,expected",
    [
        (Converter.b64_to_byte("aHdsLugMgiSHdAosJhg0jBq3yEnDJHfXpoELFp6mn2A="), Converter.b64_to_byte("BL0DVT5e2j1uRN4Wkfa613xdw4nXbr8mzf/4ot9wkbInCjERLvW3AnR5Q1Nhw0CrFPjo6wccbPtlvob6mg0MqHjMhNqR2pLRltEVYSQ9tVC6CKXCMfimC1elJ3Jboaf5axZdqM+Ae1SD8Bhl+ZCzWc4rU5lbGgTXIEDDxKernU8="), Converter.b64_to_byte("bDRvgyZqXGH1uOhCtw7uY5YUi9Kakjb9c4ADuH0WMBInCjERLvW3AnR5Q1Nhw0CrFPjo6wccbPtlvob6mg0MEO84ssKdXLZYCttBhzxxQWpx0O6FVW99sdiwPRABQAf5axZdqM+Ae1SD8Bhl+ZCzWc4rU5lbGgTXIEDDxKernbc=")),
        (Converter.b64_to_byte("h3OooivySKsWcN7unIEMe9vfDH+qR1ZCsEp91w/ZfUE="), Converter.b64_to_byte("h3OooivySKsWcN7unIEMe9vfDH+qR1ZCsEp91w/ZfUE="), Converter.b64_to_byte("DuZQRFbkkFYs4LzcOAIY9ra+GP5UjqyEYJT6rh6y+oI=")),
        (Converter.b64_to_byte("5Dh3+fMurkxGzaKBnBXP6w=="), Converter.b64_to_byte("i8Wm870inbcpKgieTsbvoTsM+aoIDUMvK6y4xS/MXBU="), Converter.b64_to_byte("b/0d7LBQSwNv96of6tu+jDsM+aoIDUMvK6y4xS/MXPk=")),
        (Converter.b64_to_byte("MhsLDIWTYPmnflW6ieQCIw=="), Converter.b64_to_byte("34IioWPQ67g+/p5hMSiIn77WYlp7pNyoJgBz/B4rInBxmbq3PWLRMb4PQrNO6r3saPoLzTXjiqQgG64hrG3r+g=="), Converter.b64_to_byte("EZ0trehjS7HlfPMbugyKwr7WYlp7pNyoJgBz/B4rIqKMpMY80MLK2Dxk/Dwy7ODsaPoLzTXjiqQgG64hrG3rLA==")),
    ]
)
def test_ascii_add(a: bytes, b: bytes, expected: bytes):
    encryptor = RustEncryptor(True)
    encryptor.add_secret(VaultType("A"), a)
    encryptor.add_secret(VaultType("B"), b)
    encryptor.ascii_add_secrets(VaultType("A"), VaultType("B"), VaultType("Store"))
    encryptor.ascii_add_secrets(VaultType("A"), VaultType("B"), VaultType("Store2"))
    result = encryptor.get_secret(VaultType("Store"), True)
    result2 = encryptor.get_secret(VaultType("Store2"), True)
    assert result == result2
    if expected is not None:
        assert result == expected

@pytest.mark.parametrize(
    "key,nonce,ciphertext,aad,expected_key,expected_nonce",
    [
        (Converter.b64_to_byte("YWXcYFmd08hl+STfBb6ghzWQu9ldkiQmD+BKYWUShEs="), Converter.b64_to_byte("FSPSBR3e68Fk/mAT/Koy93oOIg6oQWxO"),
         Converter.b64_to_byte("A5o/YF9yNkqHUDkGssJAXwaXiH45xRnimhiUwHpK3OH4Nc9V23p7rY2/B0mezs093haRn2EcdgSFloTQaSMaCr2VFfxXr9cq"),
         None, Converter.b64_to_byte("+68cMi1ZqsgU2mJYJPpzG3U5qGslHnYfJdP59abud8E="), Converter.b64_to_byte("zIA6l+vfFFhMF4W0HallXscvQe6WLucS")),
        (Converter.b64_to_byte("h6Y+SB7fbToP4Ylgo460XGuHpktUgU85c0YstOKiVsE="), Converter.b64_to_byte("i03cMkLwtUTZU4QkHvlykFWnV7i3WgZ4"),
         Converter.b64_to_byte("+Ce2qNiYNZG6k9U7Yq/Feh6U7wn+AE/NcOZ+goa4RUGKoZLkAqgrPRbY0ALYZB2zPaQHR9I9ed3NhF2zdC6MfM8x17xWqdzK"),
         None, Converter.b64_to_byte("vW5rRJt63Ie9m15FehlqCfyc3m5Z8Ggg1z4IsDxd0Mw="), Converter.b64_to_byte("RywIjTnbEwqcE67hxA5n4IToyTGLgR8p")),
         (Converter.b64_to_byte("CDGM2k/gHhRMz5aE1eUcmkRK5eMTOWROUd+PrJBcvt4="), Converter.b64_to_byte("X6rjaHDDOsE3o9jvTSrpXmpeB4fWmI8o"),
          Converter.b64_to_byte("K2k5CQtER+93ZVkECa2CtUygDU4+e8p0BgiXgEyf9o9b+vmhKzIkggT7coZu7OYaK8BRVMjxPIzVjp/64wWuU1qBVoiscTuB"),
          None, Converter.b64_to_byte("svTnEmrONzEn1NVLcOZUZc8135twhCWuE0rP4qBFiNM="), Converter.b64_to_byte("7hv7sG8wl6Ic8qiEITRwKY8vkapBsIX1")),
        (Converter.b64_to_byte("ueNnLTls8NQ7uUmJAD6j1bc4kmE0xKQOrvZ8lQidMmE="), Converter.b64_to_byte("J0/ZDsj9ntUEn0xTqdqTVxDR8M+JNFL7"),
         Converter.b64_to_byte("kSA3LKjdcf0G5kZ5aonhYwTdbR1SxXenk+/mXwW4vXcsAaaxOesOAeCnwOPdOl3mw6E17fi4JjzxAz1SLa2ltFaSYPMwoJFy"),
         b"some aad", Converter.b64_to_byte("37lqUi3ClOipLcVQZgqgTHmeHk1NUeXg6/hsmUjxfQM="), Converter.b64_to_byte("NV2RyXxWqmdOScVGfekoDiNjLXg2TjEF")),
        (Converter.b64_to_byte("0wAh1nkhtVTFypWBE2b7uPrN3ZqErah8+V/ivPvbzxg="), Converter.b64_to_byte("mEXc/JdAElGTv5yrbSyhRZ9xgDJMXlHp"),
         Converter.b64_to_byte("MUFUgY+4h8WMcdRg59p/jYbBjUWZVaYtoiU32jhN3ek89nWKq/ZGmWK3FSrSsdxZGgElknUwQ8hQNI88VW9islAHga5wwRzB"),
         b"What would you put in here?", Converter.b64_to_byte("hWsjoM+rk8CdluHUhzvwqXoAr/llB3r4BC9E6au1JBk="), Converter.b64_to_byte("Sp0aPXY4jK7sZdCl/33yzXCoC4/v7oAj"))
    ]
)
def test_decrypt_into_key(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, expected_key: bytes, expected_nonce: bytes):
    encryptor = RustEncryptor(True)
    encryptor.add_secret(VaultType("from here"), key)
    expected = (expected_key, expected_nonce)
    #to_enc = expected[0] + expected[1]
    #_, ciph = encryptor.encrypt_chacha(to_enc, nonce, aad, VaultType("from here"))
    #print(Converter.byte_to_b64(ciph))
    #assert 0 == 0
    nonce = encryptor.decrypt_into_key(ciphertext, nonce, VaultType("store_here"), VaultType("from here"), aad)
    assert nonce == expected[1]
    sec = encryptor.get_secret(VaultType("store_here"), True)
    assert sec == expected[0]

@pytest.mark.parametrize(
    "key_to_enc,key,nonce,extra,aad,expected",
    [
        (Converter.b64_to_byte("VaKFShOomVPGLYVuIZ15xRCgEy7fFNMoZMbufzVjqGQ="), Converter.b64_to_byte("Viv/0pjTu2bL7MGg7VcGjV0+WhLLgL0imVsmoFhGSnM="),
         Converter.b64_to_byte("zfttLK9Liw9nJHyh3OK4c9pq9JfBUCbI"),
         Converter.b64_to_byte("UfbOfwwT+7F07ayZxAk1S6z9GXzBgk7eJQPcdWZz7mcrz6w24+/0dcixXsPd7Tik0S+1pO2L8KjsvoY6YNGPNw=="),
         b"This is an aad",
         Converter.b64_to_byte("nXkurMVDHvzqAW/p1lucQAgbJ5/jUf3gkvYy9WU4ps6drewaCDYr7JmclPqp0JyJ3Q7KpiJYSJYC44bATSzTIe2KtsjJVlStM654QBJZl80mAkh7vrvR7KpURUjJxtGK5gGAWea6Zx/7JyDokErp6A==")),
        (Converter.b64_to_byte("7gn7mz0LDGZJYKY7DVbeYUNV/WXuXDUJ2K/rS8l1KXA="), Converter.b64_to_byte("ksNpCelVsg/Ep38NOHuoBYXZQFW/CWzSrqAVTzYNXmE="),
         Converter.b64_to_byte("89fvBnzNcxrIkbUmc9vIWUtE3tqIVstz"),
         Converter.b64_to_byte("rLl6d87YWheaVETQvHb3viVLRgZh1KZtVq/vSxoZHYLAqMj8IF7uf6UVAxs70KlE5hLddYEHQZS+KkG/eKXcQQ=="),
         None,
         Converter.b64_to_byte("2pVE8qqHBZK3+yVxP0bFKNgb0Uz51JfRBmSh8uCdTMuVL6Tsv8REqnfJjlVSyPrYDvNCl8synPTxSvcomUpItnZyutzjdcwyCPIKdYWxy9imGxlkUeZd6p3750dOem2DIs2UH6nnTA9SUGjt5VJfUA==")),
        (Converter.b64_to_byte("/3SVUd3ARI4pZOIT1y8qJO89Mc7VBOX2681rVyej/O0="), Converter.b64_to_byte("hXEKgkljZF59fvADaS/+ulk62IZ2wCzgXY1wY4YW9No="),
         Converter.b64_to_byte("HBD+LrZPfet8rWCFDOdQPMqXozuIvmAJ"),
         Converter.b64_to_byte("TLvHZCG3s4fagH279AmYhbFbAvlyLwWMZSNDPJ2dE5ul4Ck5afIET4BW7NS2AKfAXPTix4A/EkO5vVTBG2A0mw=="),
         b"Where am I?",
         Converter.b64_to_byte("ktHeFSK0J4bps9Q7fjQjP8TtD3M41EbFy5Tkyb2L+6ov0dCUl7tVbzDxppHp24uFWgA7GsYq0NsN/SxqRfwG0lmSMmrIrDvpWidHnbvXSNhncaX5o0+xH1R9uHP3CY1gHPcR6LX3LLeTnCC0ta9F+g=="))
    ]
)
def test_encrypt_key_and_more(key_to_enc: bytes, key: bytes, nonce: bytes, extra: bytes, aad: bytes, expected: bytes):
    encryptor = RustEncryptor(True)
    encryptor.add_secret(VaultType("to encrypt"), key_to_enc)
    encryptor.add_secret(VaultType("key encrypts"), key)
    nonce, ciph = encryptor.encrypt_key_and_more(extra, VaultType("to encrypt"), nonce, aad, VaultType("key encrypts"))
    dec = encryptor.decrypt_chacha(ciph, nonce, VaultType("key encrypts"), aad)
    assert key_to_enc + extra == dec
    if expected is not None:
        assert ciph == expected
@pytest.mark.parametrize(
    "others1,others2",
    [
        ("", "abcdefghijklmnopqrstuvwxyz"),
        ("abcdef", "ghijklmnopqrstuvwxyz"),
        ("abcdefghijklmno", "pqrstuvwxyz"),
        ("abcdefghijklmnopqrstuv", "wxyz"),
        ("abcdefghijklmnopqrstuvwxyz", ""),
    ]
)
def test_transfer_secret(others1: str, others2: str):
    encryptor1: RustEncryptor = RustEncryptor(test=True)
    encryptor2: RustEncryptor = RustEncryptor(test=True)
    saved_ones1: dict = dict()
    for c in others1:
        t = secrets.token_bytes(32)
        encryptor1.add_secret(VaultType(c), t)
        saved_ones1[c] = t

    saved_ones2: dict = dict()
    for c in others2:
        t = secrets.token_bytes(32)
        encryptor2.add_secret(VaultType(c), t)
        saved_ones2[c] = t

    e1 = encryptor1 if len(others1) > len(others2) else encryptor2
    e2 = encryptor2 if len(others1) > len(others2) else encryptor1
    o1 = others1 if len(others1) > len(others2) else others2
    o2 = others2 if len(others1) > len(others2) else others1
    s1 = saved_ones1 if len(others1) > len(others2) else saved_ones2
    s2 = saved_ones2 if len(others1) > len(others2) else saved_ones1

    for c in o1:
        e2.transfer_secret(e1, VaultType(c))
        s2[c] = s1[c]
        del s1[c]
        assert e2.get_secret(VaultType(c), True) == s2[c]

        with pytest.raises(Exception):
            _ = e1.get_secret(VaultType(c), True)
