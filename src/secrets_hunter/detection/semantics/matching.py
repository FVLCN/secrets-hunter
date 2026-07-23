def phrase_match_spans(
    tokens: tuple[str, ...],
    phrase: tuple[str, ...]
) -> tuple[tuple[int, int], ...]:
    if not phrase or len(phrase) > len(tokens):
        return ()

    phrase_length = len(phrase)

    return tuple(
        (index, index + phrase_length)
        for index in range(len(tokens) - phrase_length + 1)
        if tokens[index:index + phrase_length] == phrase
    )


def contains_phrase(
    tokens: tuple[str, ...],
    phrase: tuple[str, ...]
) -> bool:
    return bool(phrase_match_spans(tokens, phrase))
