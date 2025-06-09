import secrets
import keyring

def first_boot():
    system_key = key = secrets.token_bytes(256)
    keyring.set_password("BudgetBook", "system_key", system_key.hex())
    del system_key
