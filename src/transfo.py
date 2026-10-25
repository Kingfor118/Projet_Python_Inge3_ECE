from asyncio import log
from collections.abc import Iterator


def filtrage_logs(logs) -> Iterator:
    yield from filter(
        lambda log: log is not None and log != {}, logs)

def normalize_logs(log: dict) -> dict:

    normalized = {}

    for key, value in log.items():
        new_key = key.strip().upper()

        match value:
            case str():
                value = value.strip().upper()

            case dict():
                value = {
                    k: v.strip().upper() if isinstance(v, str) else v
                    for k, v in value.items()
                }

            case tuple():
                value = tuple(
                    map(
                        lambda x: x.strip().upper() if isinstance(x, str) else x,
                        filter(lambda x: x is not None, value)
                    )
                )

            case _:
                pass

        normalized[new_key] = value

    return normalized
