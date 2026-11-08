import json
from collections.abc import Iterator




# lit un fichier ligne par ligne
# avec yield la fonction renvoie une ligne puis se met en pause jusqu'a ce qu'on demande la suivante
# donc on a jamais tout le fichier en memoire, juste la ligne en cours
def lire_logs(path: str) -> Iterator[tuple[str, int, str]]:
    try:
        with open(path, 'r', encoding='UTF-8') as file_obj:
            # enumerate donne le numero de la ligne en plus (on commence a 1)
            for numero, line in enumerate(file_obj, start=1):
                # on renvoie la ligne (sans le \n), son numero et le nom du fichier
                # le numero et le fichier servent juste a afficher ou est l'erreur si la ligne est mauvaise
                yield line.strip(), numero, path
    except FileNotFoundError:
        # Si le fichier n'existe pas, on previent et on passe au fichier suivant
        print(f"Fichier de log introuvable : {path}")

# lit plusieurs fichiers a la suite
# yield from = on renvoie toutes les lignes de lire_logs(p) une par une, puis on passe au fichier d'apres
def lire_all_logs(path) -> Iterator[tuple[str, int]]:
    for p in path:
        yield from lire_logs(p)

# transforme une ligne de texte en dictionnaire
# exemple de ligne :
# 2026-10-15T08:00:00 level=ERROR ip=192.168.1.13 user=admin payload={"event":"login_failed","success":false}
def parse_logs(logs: str) -> dict:
    # logs c'est le tuple (ligne, numero, fichier) qui vient de lire_logs
    numero = logs[1]
    fichier = logs[2]
    ### utilisé du regex après pour faire le parsing
    try:
        # on coupe la ligne aux espaces, maxsplit=4 pour pas couper le json du payload (il a des espaces dedans)
        parts = logs[0].split(maxsplit=4)


        # la date est collee a l'heure avec un T, on separe les deux
        time = parts[0].split('T')
        # "level=ERROR" -> ["level", "ERROR"], pareil pour les autres
        level = parts[1].split('=',1)
        ip = parts[2].split('=',1)
        user = parts[3].split('=',1)
        payload_string = parts[4].split('=',1)
        # json.loads transforme le texte du payload en vrai dictionnaire python
        payload = json.loads(payload_string[1])

        # si le payload a pas de "event" on considere que la ligne est mauvaise
        if payload.get("event") is None:
            raise ValueError(f"ligne le payload ne contient pas event")

        # Tuple (IP, Port, Protocole) : metadonnees fixes de la connexion.
        # Port et protocole valent None si la ligne n'est pas une connexion.
        metadata_tuple = (
            ip[1],
            payload.get("port"),
            payload.get("protocol"),
        )

        # on verifie que les noms avant les = sont les bons
        if (
            level[0] != "level"
            or ip[0] != "ip"
            or user[0] != "user"
            or payload_string[0] != "payload"
        ):
            raise ValueError(f"Les titre des ne sont pas corrects")

        else:
            # tout est bon, on range les morceaux dans un dictionnaire
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
        # on renvoie None, la ligne sera enlevee apres par filtrage_logs
        return None


# lit le fichier blacklist et renvoie les ip dans un frozenset
# frozenset = comme un set mais on peut plus le modifier apres (la blacklist doit pas bouger)
def extract_blacklist_ips(path) -> frozenset:
    try:
        with open(path, 'r', encoding='UTF-8') as f:
            # on prend chaque ligne sans les espaces, et on saute les lignes vides
            return frozenset(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        # Sans fichier de blacklist, on continue avec une blacklist vide
        print(f"Fichier de blacklist introuvable : {path}")
        return frozenset()
