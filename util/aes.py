""" AES-related utility functions """

import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from util import misc, xor

BLOCK_SIZE = 16

def pad_pkcs7(data: bytearray, block_size: int = 16) -> bytearray:
    """ Adds PKCS#7 padding to data """
    pad_value = block_size - (len(data) % block_size)
    padding = pad_value * pad_value.to_bytes(1, sys.byteorder)
    return data + padding


def unpad_pkcs7(data: bytearray) -> bytearray:
    """
    Strips PKCS#7 padding from data.
    Raises ValueError if padding is invalid.
    """
    if len(data) == 0:
        raise ValueError("Error: Empty input.")
    pad_value = data[-1]
    if pad_value == 0 or pad_value > 16:
        raise ValueError("Error: Invalid padding.")
    for i in range(1, pad_value + 1):
        if data[-i] != pad_value:
            raise ValueError("Error: Invalid padding.")
    unpadded = data[: (len(data) - pad_value)]
    return unpadded


def aes_128_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """ AES-128 encryption in ECB mode with PKCS-7 padding """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encrypt = cipher.encryptor()
    plaintext_padded = pad_pkcs7(plaintext)
    ciphertext = encrypt.update(plaintext_padded) + encrypt.finalize()
    return ciphertext


def aes_128_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """ AES-128 decryption in ECB mode with PKCS-7 padding """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decrypt = cipher.decryptor()
    plaintext_padded = decrypt.update(ciphertext) + decrypt.finalize()
    plaintext = unpad_pkcs7(plaintext_padded)
    return plaintext


def aes_128_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128 encryption without padding."""
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encrypt = cipher.encryptor()
    ciphertext = encrypt.update(plaintext) + encrypt.finalize()
    return ciphertext


def aes_128_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-128 decryption without padding."""
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decrypt = cipher.decryptor()
    plaintext = decrypt.update(ciphertext) + decrypt.finalize()
    return plaintext


def aes_128_cbc_encrypt(plaintext: bytes, key: bytes, initial_vector: bytes) -> bytearray:
    """ AES-128 encryption in CBC mode with PKCS-7 padding """
    ciphertext = bytearray()
    plaintext = pad_pkcs7(plaintext)
    plaintext_blocks = misc.split_into_blocks(plaintext)
    prev = initial_vector
    for block in plaintext_blocks:
        block = aes_128_encrypt(xor.xor_bytes(block, prev), key)
        prev = block
        ciphertext += block
    return ciphertext


def aes_128_cbc_decrypt(ciphertext: bytes, key: bytes, initial_vector: bytes) -> bytearray:
    """ AES-128 decryption in CBC mode with PKCS-7 padding """
    plaintext = bytearray()
    prev = initial_vector
    ciphertext_blocks = misc.split_into_blocks(ciphertext)
    for block in ciphertext_blocks:
        intermediate_block = aes_128_decrypt(block, key)
        plaintext_block = xor.xor_bytes(intermediate_block, prev)
        plaintext += plaintext_block
        prev = block
    try:
        plaintext = unpad_pkcs7(plaintext)
    except ValueError:
        return None
    return plaintext

def is_ecb_mode(ciphertext: bytes) -> bool:
    """
    (Shall) return True if ciphertext was encrypted in ECB mode.
    Works best on longer ciphertexts with several blocks.
    """
    return misc.contains_duplicate(misc.split_into_blocks(ciphertext))
