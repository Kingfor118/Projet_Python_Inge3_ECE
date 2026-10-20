from typing_extensions import Iterator


def lire_logs(path: str) -> Iterator[str]:
    with open(path, 'r', encoding='UTF-8') as file_obj:
        for line in file_obj:
            yield line.strip()


def lire_all_logs(path: list) -> Iterator[str]:
    for p in path:
        yield from lire_logs(p)

def parse_logs(logs: Iterator[str]) -> Iterator[dict]:
