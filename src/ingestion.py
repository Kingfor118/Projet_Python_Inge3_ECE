import json
from collections.abc import Iterator




def lire_logs(path: str) -> Iterator[tuple[str, int, str]]:
    try:
        with open(path, 'r', encoding='UTF-8') as file_obj:
            for numero, line in enumerate(file_obj, start=1):
                yield line.strip(), numero, path
    except FileNotFoundError:
        # Si le fichier n'existe pas, on previent et on passe au fichier suivant
        print(f"Fichier de log introuvable : {path}")

def lire_all_logs(path) -> Iterator[tuple[str, int]]:
    for p in path:
        yield from lire_logs(p)

def parse_logs(logs: str) -> dict:
    numero = logs[1] 
    fichier = logs[2]
    ### utilisé du regex après pour faire le parsing
    try:
        parts = logs[0].split(maxsplit=4)
        
        
        time = parts[0].split('T')
        level = parts[1].split('=',1)
        ip = parts[2].split('=',1)
        user = parts[3].split('=',1)
        payload_string = parts[4].split('=',1)
        payload = json.loads(payload_string[1])

        if payload.get("event") is None:
            raise ValueError(f"ligne le payload ne contient pas event")
        
        # Tuple (IP, Port, Protocole) : metadonnees fixes de la connexion.
        # Port et protocole valent None si la ligne n'est pas une connexion.
        metadata_tuple = (
            ip[1],
            payload.get("port"),
            payload.get("protocol"),
        )

        if (
            level[0] != "level"
            or ip[0] != "ip"
            or user[0] != "user"
            or payload_string[0] != "payload"
        ):
            raise ValueError(f"Les titre des ne sont pas corrects")

        else:
            logs_dict = {
                "time": f'{time[0]} {time[1]}',
                "level": level[1],
                "ip": ip[1],
                "user": user[1],
                "payload": payload,
                "metadata": metadata_tuple
            }
            return logs_dict

    # On n'attrape que les erreurs qu'une ligne mal formee peut provoquer :
    # - IndexError : il manque un morceau dans la ligne (ex: parts[4] n'existe pas)
    # - ValueError : le JSON est invalide, ou un des titres n'est pas le bon
    # - AttributeError : le payload n'est pas un dictionnaire (pas de .get())
    except (IndexError, ValueError, AttributeError) as e:
        print(f"ligne {numero} Erreur: {e} fichier {fichier}")
        return None


def extract_blacklist_ips(path) -> frozenset:
    try:
        with open(path, 'r', encoding='UTF-8') as f:
            return frozenset(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        # Sans fichier de blacklist, on continue avec une blacklist vide
        print(f"Fichier de blacklist introuvable : {path}")
        return frozenset()