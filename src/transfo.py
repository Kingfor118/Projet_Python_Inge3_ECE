from collections.abc import Iterator


# enleve les logs vides ou invalides (ceux ou parse_logs a renvoye None)
# filter garde seulement les logs pour lesquels la lambda renvoie True
# la lambda c'est une petite fonction sans nom, ecrite sur une seule ligne
def filtrage_logs(logs) -> Iterator:
    yield from filter(
        lambda log: log is not None and log != {}, logs)

# met le log "au propre" : on enleve les espaces en trop et on met tout en majuscule
# comme ca "error", " Error" et "ERROR" deviennent pareil
def normalize_logs(log: dict) -> dict:

    # nouveau dictionnaire qu'on remplit avec les valeurs propres
    normalized = {}

    for key, value in log.items():
        # la cle aussi en majuscule (ex: "level" -> "LEVEL")
        new_key = key.strip().upper()

        # selon le type de la valeur on la nettoie pas pareil
        match value:
            # si c'est du texte
            case str():
                value = value.strip().upper()

            # si c'est un dictionnaire (le payload), on nettoie chaque cle et chaque texte dedans
            case dict():
                value = {
                    k.strip().upper() : v.strip().upper() if isinstance(v, str) else v
                    for k, v in value.items()
                }

            # si c'est un tuple (la metadata), map applique la lambda sur chaque element
            # la lambda met en majuscule si c'est du texte, sinon elle laisse comme ca (nombres, None)
            case tuple():
                # On garde les None pour que le tuple reste toujours
                # (IP, Port, Protocole), avec 3 elements dans le meme ordre
                value = tuple(
                    map(
                        lambda x: x.strip().upper() if isinstance(x, str) else x,
                        value
                    )
                )

            # autre chose (nombre, booleen...) : on touche a rien
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
        # le | veut dire "ou", et code prend direct la valeur de STATUS
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
        # python met chaque element du tuple dans ip, port et protocole
        case (ip, port, protocole):
            return "TUPLE CONNEXION"

        # Tout le reste
        case _:
            return "FORMAT INCONNU"
