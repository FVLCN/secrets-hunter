from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    file: str
    line: int
    type: str
    match: str
    context: str
    detection_method: str
    confidence: int
    context_var: Optional[str] = None
