from src.transfo import recuperer_payload, router_log

# chaque regle recoit tous les parametres du moteur,
# **kwargs garde ceux dont elle n'a pas besoin


# toutes les ip vues dans les logs
def extract_active_ips(log: dict, context: dict, **kwargs) -> None:
    context['ips_actives'].add(log.get("IP"))


# ip qui ont fait des erreurs
def extract_unique_error_ips(log: dict, context: dict, **kwargs) -> None:
    if log.get("LEVEL") in ("ERROR", "CRITICAL"):
        context['unique_ips'].add(log.get("IP"))


# compte les alertes par niveau et par utilisateur
def occurence(log: dict, context: dict, **kwargs) -> None:
    if log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
        context['occurence_error'][log.get("LEVEL")] += 1
        context['occurence_user'][log.get("USER")] += 1


# compte les echecs a la suite par ip, un succes remet a zero
def brute_force_detector(log: dict, context: dict, seuil_brute_force: int, **kwargs) -> None:
    ip = log.get('IP')
    event = recuperer_payload(log).get('EVENT')

    if event == 'LOGIN_SUCCESS':
        context['occurence_brute_force'][ip] = 0

    elif event == 'LOGIN_FAILED':
        context['occurence_brute_force'][ip] += 1
        if context['occurence_brute_force'][ip] >= seuil_brute_force:
            context['ip_sus_brute_force'].add(ip)


# compte les logins par ip, les ports, les protocoles et les codes http
def occurence_ip_connexion(log: dict, context: dict, **kwargs) -> None:
    payload = recuperer_payload(log)
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


# compte les formats du log, de ses metadonnees et de son payload
def compter_formats(log: dict, context: dict, **kwargs) -> None:
    context['formats'][router_log(log)] += 1
    context['formats'][router_log(log.get("METADATA"))] += 1
    context['formats']["PAYLOAD " + router_log(log.get("PAYLOAD"))] += 1
