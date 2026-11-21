"""Validate the CPU worker's permitted per-model inference options."""

SAMPLING_LIMITS = {
    "temperature": 2.0, "top_p": 1.0, "top_k": 256,
    "repeat_penalty": 2.0, "num_ctx": 131072,
}
INTEGER_OPTIONS = {"top_k", "num_ctx"}


def valid_sampling(options):
    """Reject unsupported, nonnumeric or out-of-range model options."""
    return (isinstance(options, dict) and options.keys() <= SAMPLING_LIMITS.keys()
            and all(type(value) in (int, float) and 0 <= value <= SAMPLING_LIMITS[key]
                    and (key not in INTEGER_OPTIONS or type(value) is int)
                    and (key not in ("num_ctx", "repeat_penalty") or value > 0)
                    for key, value in options.items()))
