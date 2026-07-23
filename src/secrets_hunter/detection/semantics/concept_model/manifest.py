from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

from secrets_hunter.immutability import frozen_mapping
from secrets_hunter.resources import FrozenJsonValue


@dataclass(frozen=True)
class ModelManifest:
    feature_schema_version: int
    ontology_version: int
    dataset_hash: str
    source_hashes: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source_hashes",
            frozen_mapping(self.source_hashes)
        )

    @classmethod
    def from_metadata(cls, metadata: Mapping[str, FrozenJsonValue]) -> Self:
        feature_schema_version = metadata.get("feature_schema_version")
        ontology_version = metadata.get("ontology_version")
        dataset_hash = metadata.get("dataset_hash")
        source_hashes = metadata.get("source_hashes")

        if isinstance(feature_schema_version, bool) or not isinstance(
            feature_schema_version,
            int,
        ):
            raise ValueError("Model manifest feature_schema_version must be an integer")

        if isinstance(ontology_version, bool) or not isinstance(ontology_version, int):
            raise ValueError("Model manifest ontology_version must be an integer")

        if not isinstance(dataset_hash, str) or not dataset_hash:
            raise ValueError("Model manifest dataset_hash must be a non-empty string")

        if not isinstance(source_hashes, Mapping):
            raise ValueError("Model manifest source_hashes must map names to hashes")

        normalized_hashes: dict[str, str] = {}
        for name, digest in source_hashes.items():
            if not isinstance(name, str) or not isinstance(digest, str) or not digest:
                raise ValueError(
                    "Model manifest source_hashes must map names to hashes"
                )
            normalized_hashes[name] = digest

        return cls(
            feature_schema_version=feature_schema_version,
            ontology_version=ontology_version,
            dataset_hash=dataset_hash,
            source_hashes=normalized_hashes
        )
