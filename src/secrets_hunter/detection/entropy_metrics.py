import math

from collections import Counter


def calculate_shannon_entropy(input_string: str) -> float:
    entropy = 0.0

    if not input_string:
        return entropy

    counts = Counter(input_string)
    length = len(input_string)

    for count in counts.values():
        probability = count / length

        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def max_possible_entropy(input_string: str) -> float:
    if not input_string:
        return 0.0

    return math.log2(len(set(input_string)))
