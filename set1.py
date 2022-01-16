"""
Cryptopals - Set 1 - Basics
"""

import base64
from util import misc, xor, aes

def challenge1():
    """ Convert hex to base64 """
    input_string = """
    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
    """
    input_bytes = bytes.fromhex(input_string)
    return input_bytes.decode()


def challenge2():
    """ Fixed XOR """
    a_str = "1c0111001f010100061a024b53535009181c"
    b_str = "686974207468652062756c6c277320657965"
    a_bytes = bytes.fromhex(a_str)
    b_bytes = bytes.fromhex(b_str)
    output = xor.xor_bytes(a_bytes, b_bytes)
    return output.decode()


def challenge3():
    """ Single-byte XOR cipher """
    ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    plaintext = xor.decrypt_single_char_xor(ciphertext)
    return plaintext


def challenge4():
    """ Detect single-character XOR """
    best_score = 0
    best_key = 0
    best_index = 0
    score = 0
    key = 0

    with open("data\\4.txt", encoding="utf-8") as file_handle:
        data = [line.rstrip() for line in file_handle.readlines()]
    freq = misc.create_english_frequency_map()

    for i, val in enumerate(data):
        decoded = bytes.fromhex(val)
        key = xor.find_best_xor_key(decoded, freq)
        decrypted = xor.single_key_xor(decoded, key)
        score = misc.get_data_score(decrypted, freq)
        if score > best_score:
            best_score = score
            best_key = key
            best_index = i

    plaintext_bytes = xor.single_key_xor(bytes.fromhex(data[best_index]), best_key)
    plaintext = "".join([chr(c) for c in plaintext_bytes]).strip()
    return plaintext


def challenge5():
    """ Implement repeating-key XOR """
    plaintext = """Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal"""
    key = "ICE"

    ciphertext = []
    plaintext_bytes = plaintext.encode()
    key_bytes = key.encode()
    ciphertext = xor.repeating_key_xor(plaintext_bytes, key_bytes)
    ciphertext = bytes.hex(ciphertext)
    return ciphertext


def challenge6():
    """ Break repeating-key XOR """
    with open("data\\6.txt", encoding="utf-8") as file_handle:
        data = file_handle.read()
    data_decoded = base64.b64decode(data)
    key_size = xor.find_repeating_key_xor_key_size(data_decoded, 2, 40)
    key_blocks = misc.split_into_blocks(data_decoded, key_size)
    transpositions = misc.transpose_blocks(key_blocks, key_size)
    key = []
    for block in transpositions:
        block_key = xor.xor_bruteforce(block)
        key.append(block_key)
    plaintext = xor.repeating_key_xor(data_decoded, key).decode()
    return plaintext


def challenge7():
    """ AES in ECB mode """
    key = b"YELLOW SUBMARINE"
    with open("data\\7.txt", encoding="utf-8") as file_handle:
        data_decoded = base64.b64decode(file_handle.read())
    plaintext = aes.aes_128_ecb_decrypt(data_decoded, key).decode()
    return plaintext


def challenge8():
    """ Detect AES in ECB mode """
    with open("data\\8.txt", encoding="utf-8") as file_handle:
        data = [bytes.fromhex(line.strip()) for line in file_handle.readlines()]
    line_number = 0
    for number, line in enumerate(data):
        ciphertext_blocks = misc.split_into_blocks(line)
        if misc.contains_duplicate(ciphertext_blocks):
            line_number = number
            break
        continue
    return line_number + 1
