class Protocols:
    def new_device(self):
        """
        Because there are no CAs in a local network; SSL/TLS can not be used. Thus, to prevent MITM attacks (in theory)
        new devices need to be registered physically and receive a secret at this step. This is a protocol which needs
        to only be done once in a while.

        This protocol can only be executed by an admin.

        This protocol gives the new device an RSA public key A and an unrelated RSA private key B
        as well as a verification code and a welcome code.

        The Server saves the RSA public key A, RSA private key A, RSA public key B, RSA private key B,
        verification code, welcome code.

        The Server also gives the new device the new device register page.

        The new device now starts the new device register page and first sends the server the welcome code encrypted
        with public key A and signs the message with private key B.

        The Sever verifies the welcome code and encrypts the verification code with public key B and signs it with
        private key A.

        The new device verifies the verification code and sends and ok message encrypted with public key A and signed
        with private key B.

        The Server now sends the secret which holds for one month to the device; encrypted with the RSA public key B and
        signed with the RSA private key A.

        Now the new device is verified.

        This should make MITM attacks basically impossible.

        :return:
        """
        ...

    def send_static(self):
        ...

    def send_secrets(self):
        ...

    def validate(self):
        ...
 