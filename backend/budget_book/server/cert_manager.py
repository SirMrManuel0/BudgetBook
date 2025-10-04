import os

from OpenSSL import crypto

from backend.budget_book.server.server_env import CERT_NAME, CERT_PRIV_DIR, CERT_PUB_DIR, KEY_NAME, DAYS, COMMON_NAME

def gen_certs():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_EC, 384)

    cert = crypto.X509()
    cert.get_subject().CN = COMMON_NAME
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(DAYS * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    with open(os.path.join(CERT_PRIV_DIR, f"{CERT_NAME}.crt"), "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(os.path.join(CERT_PUB_DIR, f"{CERT_NAME}.crt"), "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    with open(os.path.join(CERT_PRIV_DIR, f"{KEY_NAME}.key"), "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
