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
                    k.strip().upper() : v.strip().upper() if isinstance(v, str) else v
                    for k, v in value.items()
                }

            case tuple():
                # On garde les None pour que le tuple reste toujours
                # (IP, Port, Protocole), avec 3 elements dans le meme ordre
                value = tuple(
                    map(
                        lambda x: x.strip().upper() if isinstance(x, str) else x,
                        value
                    )
                )

            case _:
                pass

        normalized[new_key] = value

    return normalized


def router_log(element) -> str:
    """Regarde le format de l'element recu et renvoie son type de log.

    Les case sont testes dans l'ordre : le premier qui correspond gagne.
    C'est pour ca que les cas les plus precis sont places en premier.
    """
    match element:
        # Une simple chaine de caracteres (log brut, non parse)
        case str():
            return "CHAINE BRUTE"

        # Un dictionnaire dont le niveau est ERROR ou CRITICAL.
        # On recupere au passage le code de statut HTTP s'il existe.
        case {"LEVEL": "ERROR" | "CRITICAL", "PAYLOAD": {"STATUS": code}}:
            return f"DICT ERREUR (code {code})"

        # Un dictionnaire dont le niveau est ERROR ou CRITICAL, sans code
        case {"LEVEL": "ERROR" | "CRITICAL"}:
            return "DICT ERREUR"

        # N'importe quel autre dictionnaire
        case dict():
            return "DICT"

        # Un tuple (IP, Port, Protocole) sans port ni protocole :
        # ce n'est pas une connexion reseau (ex: un login)
        case (ip, None, None):
            return "TUPLE SANS CONNEXION"

        # Un tuple (IP, Port, Protocole) complet : une connexion reseau
        case (ip, port, protocole):
            return "TUPLE CONNEXION"

        # Tout le reste
        case _:
            return "FORMAT INCONNU"
