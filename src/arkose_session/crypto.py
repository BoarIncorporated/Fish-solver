import base64
import hashlib
import json, time
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class EncryptionData:
    def __init__(self, ct: str, iv: str, s: str) -> None:
        self.ct = ct
        self.iv = iv
        self.s = s


def aes_encrypt(content: str, password: str) -> str:
    salt: bytes = os.urandom(8)
    key, iv = default_evp_kdf(password.encode(), salt)

    padder = padding.PKCS7(128).padder()
    padded_data: bytes = padder.update(content.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text: bytes = encryptor.update(padded_data) + encryptor.finalize()

    ciphertext_encoded: str = base64.b64encode(cipher_text).decode("utf-8")

    iv_hex: str = iv.hex()
    salt_hex: str = salt.hex()

    enc_data = EncryptionData(ciphertext_encoded, iv_hex, salt_hex)

    return json.dumps(enc_data.__dict__)


def aes_decrypt(encrypted_content: str, password: str) -> str:
    enc_data: dict = json.loads(encrypted_content)
    ciphertext: bytes = base64.b64decode(enc_data["ct"])
    iv: bytes = bytes.fromhex(enc_data["iv"])
    salt: bytes = bytes.fromhex(enc_data["s"])

    key, _ = default_evp_kdf(password.encode(), salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded: bytes = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data: bytes = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted_data.decode("utf-8")


def evp_kdf(
    password: bytes,
    salt: bytes,
    key_size: int = 32,
    iv_size: int = 16,
    iterations: int = 1,
    hash_algorithm: str = "md5",
) -> Tuple[bytes, bytes]:
    if hash_algorithm.lower() != "md5":
        raise ValueError("Unsupported hash algorithm")

    derived_key_bytes: bytes = b""
    block: bytes = b""

    while len(derived_key_bytes) < (key_size + iv_size):
        hasher = hashlib.md5()
        hasher.update(block + password + salt)
        block = hasher.digest()

        for _ in range(1, iterations):
            hasher = hashlib.md5()
            hasher.update(block)
            block = hasher.digest()

        derived_key_bytes += block

    return (
        derived_key_bytes[:key_size],
        derived_key_bytes[key_size : key_size + iv_size],
    )


def default_evp_kdf(password: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    return evp_kdf(password, salt)


if __name__ == "__main__":
    timestamp = int(time.time())
    bda: str = (
        '{"ct":"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","s":"0dc02fd004c99d5b","iv":"d23b39d9156b804021108564b2a7694d"}'
        )
    timeframe = int(timestamp - (timestamp % 21600))
    encryption_key = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/131.0.0.0"
        + str(timeframe)
    )
    enckey = "711180924aa280dd8.9631261505"
    bdadecrypted = aes_decrypt(bda, encryption_key)
    print(bdadecrypted)
