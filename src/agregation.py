def extract_unique_error_ips(log, context: dict) -> set:
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
        context['unique_ips'].add(log.get("IP"))


def comparer_ips(ip_actives: set, ip_blacklist: frozenset):
    info = f"""union: {ip_actives | ip_blacklist}
      intersection: {ip_actives & ip_blacklist}
      difference: {ip_actives - ip_blacklist}
      difference_symetrique: {ip_actives ^ ip_blacklist}
    """
    return info

def occurence(log: dict, context: dict):
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
            context['occurence_error'][log.get("LEVEL")] += 1
            context['occurence_user'][log.get("USER")] += 1


def brute_force_detector(log: dict, context: dict):
    ip = log.get('IP')
    payload = log.get('PAYLOAD')

    if payload['event'] == 'LOGIN_SUCCESS':
        context['occurence_brute_force'][ip] = []

    if payload['event'] == 'LOGIN_FAILED':
        
        context['occurence_brute_force'][ip].append(log.get('TIME'))

    if len(context['occurence_brute_force'][ip]) >= 5:
        context['ip_sus_brute_force'].add(ip)






