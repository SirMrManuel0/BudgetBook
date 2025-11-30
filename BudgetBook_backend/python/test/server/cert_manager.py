import os

from backend.budget_book.server.cert_manager import gen_certs
from backend.budget_book.server.server_env import CERT_NAME, CERT_PRIV_DIR, CERT_PUB_DIR, KEY_NAME


def test_gen_certs():
    gen_certs()
    assert os.path.exists(CERT_PRIV_DIR)
    assert os.path.exists(CERT_PUB_DIR)
    assert os.path.isfile(os.path.join(CERT_PRIV_DIR, f"{CERT_NAME}.crt"))
    assert os.path.isfile(os.path.join(CERT_PUB_DIR, f"{CERT_NAME}.crt"))
    assert os.path.isfile(os.path.join(CERT_PRIV_DIR, f"{KEY_NAME}.key"))
    assert not os.path.isfile(os.path.join(CERT_PUB_DIR, f"{KEY_NAME}.key"))
