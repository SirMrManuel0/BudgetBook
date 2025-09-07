import os

from budget_book.path_manager import get_path_abs

KEY_NAME: str = "key.pem"
CERT_NAME: str = "BudgetBook-Cert.pem"
CERT_PRIV_DIR: str = get_path_abs("../cert_priv/")
CERT_PUB_DIR: str = get_path_abs("../cert/")
CERT_NEXT_DIR: str = get_path_abs("../cert_next/")
COMMON_NAME: str = "budgetbook.local"
DAYS: int = 365

def init():
    if not os.path.isdir(CERT_NEXT_DIR):
        os.mkdir(CERT_NEXT_DIR)
    if not os.path.isdir(CERT_PRIV_DIR):
        os.mkdir(CERT_PRIV_DIR)
    if not os.path.isdir(CERT_PUB_DIR):
        os.mkdir(CERT_PUB_DIR)
