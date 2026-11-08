from src.transfo import router_log, recuperer_payload

# Remarque : chaque regle recoit TOUS les parametres passes a
# apply_security_rules (log, context, seuil_brute_force...).
# Le **kwargs a la fin de chaque regle sert a "ranger" les parametres
# dont la regle n'a pas besoin, sinon Python leverait une erreur.


# ajoute l'ip dans le set des ip qui ont fait des erreurs
# comme c'est un set, si l'ip est deja dedans elle est pas ajoutee 2 fois
def extract_unique_error_ips(log, context: dict, **kwargs):
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL"):
        context['unique_ips'].add(log.get("IP"))


# compte les erreurs par niveau et par utilisateur
# grace au defaultdict on peut faire += 1 meme la premiere fois (ca part de 0)
def occurence(log: dict, context: dict, **kwargs) -> None:
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
            context['occurence_error'][log.get("LEVEL")] += 1
            context['occurence_user'][log.get("USER")] += 1


# detecte le brute force : quelqu'un qui rate son login plein de fois a la suite
def brute_force_detector(log: dict, context: dict, seuil_brute_force: int, **kwargs):
    ip = log.get('IP')
    # "or {}" : si y a pas de payload on prend un dictionnaire vide pour eviter une erreur
    payload = recuperer_payload(log)
    event = payload.get('EVENT')


    # login reussi -> on remet le compteur de cette ip a 0
    if event == 'LOGIN_SUCCESS':
        context['occurence_brute_force'][ip] = 0

    # login rate -> on ajoute 1 au compteur de cette ip
    if event == 'LOGIN_FAILED':

        context['occurence_brute_force'][ip] += 1

    # Le seuil n'est plus ecrit en dur : il arrive par les kwargs
    # si l'ip a trop d'echecs a la suite on la met dans les suspectes
    if context['occurence_brute_force'][ip] >= seuil_brute_force:
        context['ip_sus_brute_force'].add(ip)


# compte les logins reussis / rates par ip, et les ports, protocoles et codes http qu'on voit
def occurence_ip_connexion(log: dict, context: dict, **kwargs):
    payload = recuperer_payload(log)
    event = payload.get("EVENT")
    ip = log.get("IP")

    if event == "LOGIN_SUCCESS":
        context['success_par_ip'][ip] += 1

    elif event == "LOGIN_FAILED":
        context['echecs_par_ip'][ip] += 1

    # on compte seulement si l'info existe dans le payload
    if payload.get("PROTOCOL"):
        context['protocols'][payload.get("PROTOCOL")] += 1

    if payload.get("PORT"):
        context['ports'][payload.get("PORT")] += 1

    if payload.get("STATUS"):
        context['status_codes'][payload.get("STATUS")] += 1


# compte combien de logs il y a de chaque format (DICT, DICT ERREUR, TUPLE CONNEXION...)
def compter_formats(log: dict, context: dict, **kwargs):
    # On donne le log (un dictionnaire) au routeur match-case
    format_du_log = router_log(log)
    context['formats'][format_du_log] += 1

    # On donne aussi le tuple (IP, Port, Protocole) du log au routeur
    format_metadata = router_log(log.get("METADATA"))
    context['formats'][format_metadata] += 1

    format_payload = router_log(log.get("PAYLOAD"))
    context['formats']["PAYLOAD " + format_payload] += 1
