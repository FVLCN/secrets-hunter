from pathlib import Path

from secrets_hunter.scanning.content_safety import ContentSafetyPolicy


class TextContentValidator:
    def __init__(self, policy: ContentSafetyPolicy) -> None:
        self.policy = policy

    def is_text_file(self, path: Path) -> bool:
        with open(path, "rb") as source_file:
            chunk = source_file.read(
                self.policy.binary_detection_chunk_size
            )

        return self.is_text_content(chunk)

    def is_text_content(self, content: bytes) -> bool:
        chunk = content[:self.policy.binary_detection_chunk_size]

        if not chunk:
            return True

        if b"\x00" in chunk:
            return False

        bad_bytes = 0
        for byte in chunk:
            if byte == 127:
                bad_bytes += 1
            elif byte < 32 and byte not in (9, 10, 13):
                bad_bytes += 1

        return (
            bad_bytes / len(chunk)
        ) < self.policy.control_chars_ratio_threshold
