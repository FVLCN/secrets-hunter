import re

from ..bigrams import BIGRAM_MODEL
from ..corpus import CORPUS
from ..tokenization import split_identifier

from .models import LexicalAnalysis, LexicalKind


class LexicalAnalyzer:
    """
    Deterministically classifies a string as English text or random using:

    1. Word match ratio — fraction of tokens found in the corpus
    2. Bigram score — how English-like the character transitions are
    """

    _RANDOM_BASELINE: float = sum(BIGRAM_MODEL.values()) / len(BIGRAM_MODEL)
    _BEST_BASELINE: float = max(BIGRAM_MODEL.values())

    def __init__(
        self,
        word_weight:   float = 0.6,
        bigram_weight: float = 0.4,
        threshold:     float = 0.43
    ) -> None:
        self.word_weight   = word_weight
        self.bigram_weight = bigram_weight
        self.threshold     = threshold

    @classmethod
    def bigram_score(cls, s: str) -> float:
        cleaned = re.sub(r"[^a-z]", "", s.lower())

        if len(cleaned) < 2:
            return 0.0

        pairs = [(cleaned[i], cleaned[i + 1]) for i in range(len(cleaned) - 1)]
        avg_log_prob = sum(BIGRAM_MODEL[pair] for pair in pairs) / len(pairs)
        score = (avg_log_prob - cls._RANDOM_BASELINE) / (cls._BEST_BASELINE - cls._RANDOM_BASELINE)

        return max(0.0, min(1.0, score))

    def analyze(self, s: str) -> LexicalAnalysis:
        tokens = split_identifier(s)
        corpus_matches = tuple(token for token in tokens if token in CORPUS)
        corpus_tokens = tuple(dict.fromkeys(corpus_matches))
        wmr = len(corpus_matches) / len(tokens) if tokens else 0.0
        bgs = self.bigram_score(s)
        combined = self.word_weight * wmr + self.bigram_weight * bgs

        return LexicalAnalysis(
            string=s,
            corpus_tokens=corpus_tokens,
            kind=(
                LexicalKind.ENGLISH_TEXT
                if combined >= self.threshold
                else LexicalKind.RANDOM
            )
        )
