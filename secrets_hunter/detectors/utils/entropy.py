import math

from collections import Counter
from typing import Set

HEX_CHARS: Set[str] = set('0123456789abcdefABCDEF')
BASE64_CHARS: Set[str] = set(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
)


def calculate_shannon_entropy(string: str) -> float:
    entropy = 0.0

    if not string:
        return entropy

    counts = Counter(string)
    length = len(string)

    for count in counts.values():
        probability = count / length

        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy

def is_hex_string(string: str) -> bool:
    return all(c in HEX_CHARS for c in string)

def is_base64_string(string: str) -> bool:
    return all(c in BASE64_CHARS for c in string)
