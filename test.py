import secrets
from budget_book.logic.database import Converter

print(Converter.byte_to_b64(secrets.token_bytes(24)))
