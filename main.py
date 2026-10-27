from src.ingestion import *
from src.transfo import *
from src.agregation import *
from collections import defaultdict

unique_ips = set()
occurence_user = defaultdict(int)
occurence_error = defaultdict(int)

logs = [
        
        'demo_data/auth.log',
        'demo_data/blacklist.txt',
        'demo_data/server.log',
        'demo_data/network.log'
    ]

blacklist = [
    'demo_data/blacklist.txt'
]

'''
test = list(lire_logs(logs[0]))
print(parse_logs(test[1]))
'''
# Lecture des fichiers (module 1)
raw_logs = lire_all_logs(logs)

# Parsing des logs (module 1)
parsed_logs = map(parse_logs, raw_logs)

# Filtrage des logs invalides (module 2)
filtered_logs = filtrage_logs(parsed_logs)

# log normalize du module 2 
normalized_logs = map(normalize_logs, filtered_logs)


blacklist_ips = extract_blacklist_ips(blacklist[0])

for line_log in normalized_logs:
    extract_unique_error_ips(line_log, unique_ips)
    occurence(line_log, occurence_user, "USER")
    occurence(line_log, occurence_error, "LEVEL")



#print(comparer_ips(unique_ips, blacklist_ips))

print(occurence_error)