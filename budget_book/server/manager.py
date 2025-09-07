import ssl
import os

from flask import Flask

from budget_book.server import server_env

app = Flask(__name__)


@app.route("/")
def index():
    return "Secure ECDHE + ChaCha20-Poly1305 only!"

def start_server(ip: str, port: int = 443):
    server_env.init()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Only allow TLS 1.2 and 1.3
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # TLS 1.2 cipher restriction (only ECDHE + ChaCha20-Poly1305)
    context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305")

    # TLS 1.3 cipher restriction (ChaCha20-Poly1305 only)
    try:
        context.set_ciphers("TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256")
    except AttributeError:
        print("Warning: TLS 1.3 cipher restriction not supported on this Python/OpenSSL version")

    # Load your certificate
    context.load_cert_chain(
        certfile=os.path.join(server_env.CERT_PRIV_DIR, f"{server_env.CERT_NAME}.crt"),
        keyfile=os.path.join(server_env.CERT_PRIV_DIR, f"{server_env.KEY_NAME}.key")
    )

    app.run(host=ip, port=port, ssl_context=context)
