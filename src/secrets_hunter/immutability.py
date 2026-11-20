from collections.abc import Mapping
from types import MappingProxyType


def frozen_mapping[K, V](values: Mapping[K, V]) -> Mapping[K, V]:
    return MappingProxyType(dict(values))
