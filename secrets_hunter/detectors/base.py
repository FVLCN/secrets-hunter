from abc import ABC, abstractmethod
from typing import List, Dict


class BaseDetector(ABC):
    def __init__(self, config):
        self.config = config

    @abstractmethod
    def detect(self, line: str, line_num: int, filepath: str, strings: List[str]) -> List[Dict]:
        pass
