"""
Cryptopals - Set 2 - Block crypto
"""

import base64
import os
import sys
import random
from util import aes

BLOCK_SIZE = 16
KEY = os.urandom(BLOCK_SIZE)
IV = os.urandom(BLOCK_SIZE)


def challenge9():
    """Implement PKCS#7 padding"""
    unpadded = "YELLOW SUBMARINE"
    unpadded_bytes = unpadded.encode()
    padded_bytes = aes.pad_pkcs7(unpadded_bytes)
    return padded_bytes


def challenge10():
    """Implement CBC mode"""
    with open("data\\10.txt", encoding="utf-8") as file_handle:
        ciphertext = base64.b64decode(file_handle.read())
    initial_vector = bytes(16)
    key = b"YELLOW SUBMARINE"
    plaintext = aes.aes_128_cbc_decrypt(ciphertext, key, initial_vector).decode()
    return plaintext


def encrypt_randomly(data, key, initial_vector):
    """Encrypts data with a random key using either ECB or CBC randomly."""
    coin_flip = random.randint(0, 1)
    if coin_flip == 0:
        # ECB
        ciphertext = aes.aes_128_ecb_encrypt(data, key)
    else:
        # CBC
        ciphertext = aes.aes_128_cbc_encrypt(data, key, initial_vector)
    return ciphertext, coin_flip


def encryption_oracle(data):
    """
    Prepends and appends 5-10 bytes of random bytes to data,
    before encrypting data using encrypt_randomly.
    """

    key = os.urandom(BLOCK_SIZE)
    initial_vector = os.urandom(BLOCK_SIZE)

    prefix_count = random.randint(5, 10)
    suffix_count = random.randint(5, 10)
    prefix = os.urandom(prefix_count)
    suffix = os.urandom(suffix_count)

    data = prefix + data + suffix
    data = aes.pad_pkcs7(data)
    ciphertext, coin_flip = encrypt_randomly(data, key, initial_vector)
    return ciphertext, coin_flip


def challenge11(data):
    """An ECB/CBC detection oracle"""
    ciphertext, mode = encryption_oracle(data)
    detected_mode = aes.is_ecb_mode(bytes(ciphertext))
    modes = ["ECB", "CBC"]
    print(f"Detected mode: {modes[detected_mode]}")
    print(f"Actual mode: {modes[mode]}")


def oracle(plaintext):
    """
    Appends a Base64-encoded suffix string to plaintext before
    encrypting it in ECB mode.
    Used for challenge 12.
    """
    suffix_str = """
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK"""
    suffix = base64.b64decode(suffix_str)
    plaintext += suffix
    ciphertext = aes.aes_128_ecb_encrypt(plaintext, KEY)
    return ciphertext


def find_block_size():
    """Returns the block size of the ciphertext."""
    suffix_ciphertext_length = len(oracle(b""))
    block_size = 0
    for i in range(40):
        block = oracle(b"A" * i)
        size = len(block)
        if size != suffix_ciphertext_length:
            block_size = size - suffix_ciphertext_length
            break
    return block_size


def find_block_count(block_size: int):
    """Returns the number of blocks in the ciphertext."""
    return len(oracle(b"")) // block_size


def challenge12():
    """Byte-at-a-time ECB decryption (Simple)"""
    block_size = BLOCK_SIZE
    known = bytearray()

    block_count = len(oracle(b"")) // block_size
    for block in range(block_count + 1):
        for index in range(1, block_size + 1):
            block_input = b"A" * (block_size - index)
            block_output = oracle(block_input)[
                block_size * block : block_size * (block + 1)
            ]
            block_map = {}
            for i in range(128):
                plaintext = block_input + known + i.to_bytes(1, sys.byteorder)
                ciphertext = oracle(plaintext)[
                    block_size * block : block_size * (block + 1)
                ]
                block_map[ciphertext] = i
            try:
                char = block_map[block_output]
                known.append(char)
            except KeyError:
                continue
    return known[:-1].decode()


def challenge15():
    """PKCS#7 padding validation"""
    data = b"ICE ICE BABY"
    data_padded = aes.pad_pkcs7(data)
    data_unpadded = aes.unpad_pkcs7(data_padded)
    assert data_unpadded == data
