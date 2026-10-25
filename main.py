from src.ingestion import *
from src.transfo import *

logs = [
        
        'demo_data/auth.log',
        'demo_data/blacklist.txt',
        'demo_data/server.log',
        'demo_data/network.log'
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

normalized_logs = map(normalize_logs, filtered_logs)

'''print(type(raw_logs))
print(type(parsed_logs))
print(filtered_logs)'''

# Affichage
for log in normalized_logs:
    print(log)

