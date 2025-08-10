import pytest
import secrets

from budget_book import RustEncryptor, VaultType
from budget_book.logic.database import Converter


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
