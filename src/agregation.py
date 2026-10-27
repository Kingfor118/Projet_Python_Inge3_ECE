from collections import defaultdict



def extract_unique_error_ips(log, unique_ips: set) -> set:
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
        unique_ips.add(log.get("IP"))

def extract_blacklist_ips(path) -> frozenset:
    with open(path, 'r') as f:
        return frozenset(line.strip() for line in f if line.strip())

def comparer_ips(ip_actives: set, ip_blacklist: frozenset):
    info = f"""union: {ip_actives | ip_blacklist}
      intersection: {ip_actives & ip_blacklist}
      difference: {ip_actives - ip_blacklist}
      difference_symetrique: {ip_actives ^ ip_blacklist}
    """
    return info

def occurence(log, occurence_dict, key):
     if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
            occurence_dict[log.get(key)] += 1
