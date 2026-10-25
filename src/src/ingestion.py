import json
from collections.abc import Iterator



def lire_logs(path: str) -> Iterator[str]:
    with open(path, 'r', encoding='UTF-8') as file_obj:
        for line in file_obj:
            yield line.strip()


def lire_all_logs(path) -> Iterator[str]:
    for p in path:
        yield from lire_logs(p)

def parse_logs(logs):
    ### utilisé du regex après pour faire le parsing

    try:
        parts = logs.split(maxsplit=4)
        time = parts[0].split('T')
        level = parts[1].split('=',1)
        ip = parts[2].split('=',1)
        user = parts[3].split('=',1)
        payload_string = parts[4].split('=',1)
        payload = json.loads(payload_string[1])


        metadata_tuple = (
            payload.get("port"),
            payload.get("protocol")
        )

        logs_dict = {
            "time": f'{time[0]} {time[1]}',
            "level": level[1],
            "ip": ip[1],
            "user": user[1],
            "payload": payload,
            "metadata": metadata_tulpe
        }
        return logs_dict
    except Exception as e:
        print(f"Error parsing log: {e}")
        return None
