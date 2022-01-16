from collections import defaultdict, Counter
from operator import xor
import json
import os

import util.misc as misc


def single_key_xor(data: list, key: int) -> list:
    return [ch ^ key for ch in data]


def repeating_key_xor(data: list, key: list) -> bytes:
    out = []
    for i in range(len(data)):
        out.append(data[i] ^ key[i % len(key)])
    return bytes(out)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise IndexError("a and b not of equal length.")

    return bytes([xor(m, n) for m, n in zip(a, b)])


def xor_bruteforce(data: list) -> int:
    best_key = 0
    best_score = 0
    freq_map = misc.create_english_frequency_map()
    for i in range(256):
        data_xor = single_key_xor(data, i)
        score = misc.get_data_score(data_xor, freq_map)
        if score > best_score:
            best_score = score
            best_key = i
    return best_key


def find_repeating_key_xor_key_size(data: list, min_size: int, max_size: int) -> int:
    results = []
    for key_size in range(min_size, max_size):
        # blocks = [data[i:i+key_size]
        #          for i in range(0, len(data) - key_size, key_size)]
        blocks = misc.split_into_blocks(data, key_size)
        normalised_edit_distance = 0
        for i in range(len(blocks) - 1):
            normalised_edit_distance += misc.hamming_distance(blocks[i], blocks[i + 1])
        normalised_edit_distance /= len(blocks) * key_size
        results.append((key_size, normalised_edit_distance))
    return min(results, key=lambda x: x[1])[0]


def find_best_xor_key(data: list, freq: defaultdict) -> int:
    best_score = 0
    score = 0
    best_key = 0
    for k in range(256):
        data_xor = single_key_xor(data, k)
        score = misc.get_data_score(data_xor, freq)
        if score > best_score:
            best_score = score
            best_key = k
    return best_key


def decrypt_single_char_xor(ciphertext: str) -> str:
    freq = misc.create_english_frequency_map()
    ciphertext_bytes = bytes.fromhex(ciphertext)
    best_key = find_best_xor_key(ciphertext_bytes, freq)
    plaintext_bytes = single_key_xor(ciphertext_bytes, best_key)
    plaintext = "".join([chr(x) for x in plaintext_bytes])
    return plaintext
