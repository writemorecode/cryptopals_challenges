""" Miscellaneous utility functions """

from collections import defaultdict, Counter
import json
import os

from operator import xor

FREQUENCIES_PATH = "util\\english_letter_frequencies.json"
TEXT_PATH = "data\\sherlock_holmes.txt"

def count_set_bits(number: int) -> int:
    """ Returns the number of set bits in number """
    count = 0
    while number:
        count += number & 1
        number >>= 1
    return count


def hamming_distance(a: bytes, b: bytes) -> int:
    """
    Returns the Hamming distance (aka the edit distance)
    between a and b
    """
    if len(a) != len(b):
        raise IndexError("a and b must be of equal length.")
    dist = 0
    for m, n in zip(a, b):
        dist += count_set_bits(xor(m,n))
    return dist


def split_into_blocks(data, size: int = 16) -> list:
    """
    Splits data into equally-sized blocks of size bytes
    E.g. "ABCD" -> ["AB","CD"] for size=2.
    """
    return [data[i : i + size] for i in range(0, len(data), size)]


def contains_duplicate(items) -> bool:
    """ Returns True if items contains a duplicate (or more) element """
    counter = Counter(items)
    for freq in counter.values():
        if freq > 1:
            return True
    return False


def transpose_blocks(blocks: list, block_len: int) -> list:
    """
    Returns a transposition of the elements in items.
    E.g. ["AB","CD"] -> [["A", "C"], ["B", "D"]]
    """
    transpositions = []
    for i in range(block_len):
        transpositions.append([block[i] for block in blocks])
    return transpositions


def create_english_frequency_map():
    """
    Creates a dict that maps letters A-Z to their
    frequency in the English language.
    """
    if os.path.exists(FREQUENCIES_PATH):
        with open(FREQUENCIES_PATH, encoding="utf-8") as file_handle:
            return defaultdict(int, json.load(file_handle))

    with open(TEXT_PATH, encoding="utf-8") as reader:
        text = reader.read()
    frequencies = defaultdict(int)
    for letter in text:
        frequencies[letter] += 1
    with open(FREQUENCIES_PATH, "w", encoding="utf-8") as file_handle:
        json.dump(frequencies, file_handle)
    return frequencies


def get_data_score(data: list, freq: defaultdict) -> int:
    """
    Scores the bytes in data according the probability that it is English text.
    Used to detect correctly-decoded plaintexts
    """
    return sum([freq[chr(ch)] for ch in data])
