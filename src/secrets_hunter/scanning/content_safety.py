from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ContentSafetyPolicy:
    max_line_length: int
    max_repeat_run: int
    binary_detection_chunk_size: int
    control_chars_ratio_threshold: float


DEFAULT_CONTENT_SAFETY_POLICY = ContentSafetyPolicy(
    max_line_length=50000,
    max_repeat_run=1000,
    binary_detection_chunk_size=2048,
    control_chars_ratio_threshold=0.05
)
