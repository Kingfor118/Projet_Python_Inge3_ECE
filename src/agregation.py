def extract_unique_error_ips(log, context: dict):
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
        context['unique_ips'].add(log.get("IP"))


def occurence(log: dict, context: dict):
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
            context['occurence_error'][log.get("LEVEL")] += 1
            context['occurence_user'][log.get("USER")] += 1


def brute_force_detector(log: dict, context: dict):
    ip = log.get('IP')
    payload = log.get('PAYLOAD') or {}
    event = payload.get('EVENT')


    if event == 'LOGIN_SUCCESS':
        context['occurence_brute_force'][ip] = 0

    if event == 'LOGIN_FAILED':
        
        context['occurence_brute_force'][ip] += 1

    if context['occurence_brute_force'][ip] >= 5:
        context['ip_sus_brute_force'].add(ip)


def occurence_ip_connexion(log: dict, context: dict):
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