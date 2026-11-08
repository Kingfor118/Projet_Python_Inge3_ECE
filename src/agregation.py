from src.transfo import router_log

# Remarque : chaque regle recoit TOUS les parametres passes a
# apply_security_rules (log, context, seuil_brute_force...).
# Le **kwargs a la fin de chaque regle sert a "ranger" les parametres
# dont la regle n'a pas besoin, sinon Python leverait une erreur.


def extract_unique_error_ips(log, context: dict, **kwargs):
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
        context['unique_ips'].add(log.get("IP"))


def occurence(log: dict, context: dict, **kwargs):
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
            context['occurence_error'][log.get("LEVEL")] += 1
            context['occurence_user'][log.get("USER")] += 1


def brute_force_detector(log: dict, context: dict, seuil_brute_force: int, **kwargs):
    ip = log.get('IP')
    payload = log.get('PAYLOAD') or {}
    event = payload.get('EVENT')


    if event == 'LOGIN_SUCCESS':
        context['occurence_brute_force'][ip] = 0

    if event == 'LOGIN_FAILED':

        context['occurence_brute_force'][ip] += 1

    # Le seuil n'est plus ecrit en dur : il arrive par les kwargs
    if context['occurence_brute_force'][ip] >= seuil_brute_force:
        context['ip_sus_brute_force'].add(ip)


def occurence_ip_connexion(log: dict, context: dict, **kwargs):
    payload = log.get("PAYLOAD") or {}
    event = payload.get("EVENT")
    ip = log.get("IP")

    if event == "LOGIN_SUCCESS":
        context['success_par_ip'][ip] += 1

    elif event == "LOGIN_FAILED":
        context['echecs_par_ip'][ip] += 1

    if payload.get("PROTOCOL"):
        context['protocols'][payload.get("PROTOCOL")] += 1

    if payload.get("PORT"):
        context['ports'][payload.get("PORT")] += 1

    if payload.get("STATUS"):
        context['status_codes'][payload.get("STATUS")] += 1


def compter_formats(log: dict, context: dict, **kwargs):
    # On donne le log (un dictionnaire) au routeur match-case
    format_du_log = router_log(log)
    context['formats'][format_du_log] += 1

    # On donne aussi le tuple (IP, Port, Protocole) du log au routeur
    format_metadata = router_log(log.get("METADATA"))
    context['formats'][format_metadata] += 1
