from collections.abc import Iterator


# enleve les logs vides ou invalides
def filtrage_logs(logs: Iterator[dict | None]) -> Iterator[dict]:
    return filter(lambda log: log is not None and log != {}, logs)


def nettoyer_texte(valeur: object) -> object:
    if isinstance(valeur, str):
        return valeur.strip().upper()
    return valeur


# met les cles et les textes du log en majuscules, sans espaces
def normalize_logs(log: dict) -> dict:
    normalized = {}

    for key, value in log.items():
        match value:
            case dict():
                value = {k.strip().upper(): nettoyer_texte(v) for k, v in value.items()}
            case tuple():
                value = tuple(map(nettoyer_texte, value))
            case _:
                value = nettoyer_texte(value)

        normalized[key.strip().upper()] = value

    return normalized


# renvoie le type de log selon son format
# l'ordre compte : le premier case qui correspond gagne
def router_log(element: object) -> str:
    match element:
        case str():
            return "CHAINE BRUTE"
        case {"LEVEL": "ERROR" | "CRITICAL", "PAYLOAD": {"STATUS": code}}:
            return f"DICT ERREUR (code {code})"
        case {"LEVEL": "ERROR" | "CRITICAL"}:
            return "DICT ERREUR"
        case dict():
            return "DICT"
        case (_, None, None):
            return "TUPLE SANS CONNEXION"
        case (_, _, _):
            return "TUPLE CONNEXION"
        case _:
            return "FORMAT INCONNU"


# renvoie le payload s'il est en dictionnaire, sinon un dictionnaire vide
def recuperer_payload(log: dict) -> dict:
    payload = log.get("PAYLOAD")
    if isinstance(payload, dict):
        return payload
    return {}
