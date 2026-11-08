import json
from collections.abc import Iterator


# lit un fichier ligne par ligne
def lire_logs(path: str) -> Iterator[tuple[str, int, str]]:
    try:
        with open(path, 'r', encoding='UTF-8', errors='replace') as file_obj:
            for numero, line in enumerate(file_obj, start=1):
                yield line.strip(), numero, path
    except OSError as e:
        print(f"Fichier de log illisible : {path} ({e})")


# lit plusieurs fichiers a la suite
def lire_all_logs(path: list[str]) -> Iterator[tuple[str, int, str]]:
    for p in path:
        yield from lire_logs(p)


# transforme une ligne en dictionnaire, ou None si elle est invalide
# ex : 2026-10-15T08:00:00 level=ERROR ip=192.168.1.13 user=admin payload={"event":"login_failed"}
def parse_logs(logs: tuple[str, int, str]) -> dict | None:
    ligne, numero, fichier = logs

    try:
        # maxsplit=4 : le payload peut contenir des espaces
        parts = ligne.split(maxsplit=4)
        time = parts[0].split('T')
        level = parts[1].split('=', 1)
        ip = parts[2].split('=', 1)
        user = parts[3].split('=', 1)
        payload_string = parts[4].split('=', 1)

        if (
            level[0] != "level"
            or ip[0] != "ip"
            or user[0] != "user"
            or payload_string[0] != "payload"
        ):
            raise ValueError("les titres ne sont pas corrects")

        # JSON -> dictionnaire, sinon on garde le texte brut
        try:
            payload = json.loads(payload_string[1])
        except json.JSONDecodeError:
            payload = payload_string[1]

        port = None
        protocole = None
        if isinstance(payload, dict):
            if payload.get("event") is None:
                raise ValueError("le payload ne contient pas event")
            # ces valeurs servent de cles dans les compteurs
            champs = ("PORT", "PROTOCOL", "STATUS")
            if any(k.strip().upper() in champs and isinstance(v, (list, dict))
                   for k, v in payload.items()):
                raise ValueError("port, protocol ou status invalide")
            port = payload.get("port")
            protocole = payload.get("protocol")

        return {
            "time": f'{time[0]} {time[1]}',
            "level": level[1],
            "ip": ip[1],
            "user": user[1],
            "payload": payload,
            "metadata": (ip[1], port, protocole),  # tuple fixe
        }

    except (IndexError, ValueError) as e:
        print(f"ligne {numero} Erreur: {e} fichier {fichier}")
        return None


# frozenset : la blacklist ne doit pas changer
def extract_blacklist_ips(path: str) -> frozenset[str]:
    try:
        with open(path, 'r', encoding='UTF-8') as blacklist_file:
            return frozenset(line.strip() for line in blacklist_file if line.strip())
    except OSError as e:
        print(f"Fichier de blacklist illisible : {path} ({e})")
        return frozenset()
