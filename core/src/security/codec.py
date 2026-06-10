import json
from typing import Any, Dict

class MessageCodec:
    """Utility for canonical JSON serialization to ensure consistent
    signatures across different platforms and Python versions.
    """

    @staticmethod
    def encode(data: Any) -> bytes:
        """Encodes data to a canonical JSON byte string."""
        return json.dumps(data, sort_keys=True, separators=(',', ':')).encode()

    @staticmethod
    def decode(data: bytes) -> Any:
        """Decodes a JSON byte string back into a Python object."""
        return json.loads(data.decode('utf-8'))
