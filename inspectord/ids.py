"""UUIDv7 generation. Time-sortable UUIDs per draft-peabody-dispatch-new-uuid-format."""

from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    """Generate a UUIDv7. 48 bits of unix-ms timestamp + 4-bit version +
    12 bits of random + 2-bit variant + 62 bits of random.
    """
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_a = int.from_bytes(os.urandom(2), "big") & 0xFFF
    rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)

    value = (
        (ts_ms << 80)
        | (0x7 << 76)
        | (rand_a << 64)
        | (0b10 << 62)
        | rand_b
    )
    return uuid.UUID(int=value)
