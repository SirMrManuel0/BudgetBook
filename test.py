import secrets
from budget_book.logic.database import Converter

print(Converter.hex_to_b64("f291edbb67f5bdb73814452098436b30f8615ee01b1e086d4f747748b672355ef33481c6b4a"
                                         "c812f837128085ef667f00bae190c1be2b8506a2a5590a743d0ff4760d8216b4b8c0f1252fd"
                                         "8ad1e1332f6557874c36872b410e29a764458c12b8bd0cfe10ddc99db05b539eb4fd31880cd"
                                         "9704899d6a5bd69a6a3413f188f43c4d374c8c042c163074a45f987acdd69bea59beabe9424"
                                         "68f5a5d0fcdfbbff9d4fef1a60f51247e9212da9c9b5232caa38f06e386f318e10d4b94016a"
                                         "a3270ad18dd68540100819bd8a0ba8e176aa601109678a4969159f767ae04d24cbd404e7b1b8"
                                         "7721831a5af291ae257e7419200b602d9348399623e0c5380590739f83c28"))
print(Converter.byte_to_b64(secrets.token_bytes(64)))
