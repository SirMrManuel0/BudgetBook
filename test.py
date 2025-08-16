import secrets
from budget_book.logic.database import Converter
len_ = 32
print(Converter.byte_to_b64(secrets.token_bytes(len_)))
print(Converter.byte_to_b64(secrets.token_bytes(len_)))
print(Converter.byte_to_b64(secrets.token_bytes(len_)))
print(Converter.byte_to_b64(secrets.token_bytes(len_)))
print(Converter.byte_to_b64(secrets.token_bytes(len_)))
print(Converter.byte_to_b64(secrets.token_bytes(len_)))


#from budget_book import RustEncryptor, VaultType

#encryptor = RustEncryptor(True)
#encryptor.gen_static_private_key(VaultType("a"))
#print(Converter.byte_to_b64(encryptor.get_secret(VaultType("a"), True)))


