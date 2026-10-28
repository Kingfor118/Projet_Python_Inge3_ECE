from src.ingestion import *
from src.transfo import *
from src.agregation import *
from src.rules_engine import *
from collections import defaultdict
from src.introspection import *

var_locals = {}
var_globals = {}

context = {
      'occurence_brute_force': defaultdict(list),
      'ip_sus_brute_force': set(),
      'occurence_user': defaultdict(int),
      'occurence_error': defaultdict(int),
      'unique_ips': set()
}

logs = [     
        'demo_data/auth.log',   
        'demo_data/server.log',
        'demo_data/network.log',
    ]

blacklist = [
    'demo_data/blacklist.txt'
]

# Lecture des fichiers (module 1)
raw_logs = lire_all_logs(logs)

# Parsing des logs (module 1)
parsed_logs = map(parse_logs, raw_logs)

# Filtrage des logs invalides (module 2)
filtered_logs = filtrage_logs(parsed_logs)

# log normalize du module 2 
normalized_logs = map(normalize_logs, filtered_logs)

# Agregation des logs (module 3)
blacklist_ips = extract_blacklist_ips(blacklist[0])

for line_log in normalized_logs:
    
    var_locals = apply_security_rules(
        brute_force_detector,
        occurence,
        extract_unique_error_ips,
        log=line_log,
        context=context
    )
    introspection_local(var_locals)
  
var_globals = globals()
introspection_global(var_globals)
