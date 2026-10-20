from src.ingestion import *


logs = [
    'demo_data/network.log',
        'demo_data/auth.log',
        'demo_data/blacklist.txt',

        'demo_data/server.log'
    ]


test = list(lire_logs(logs[0]))
print(parse_logs(test[1]))


'''for log in lire_all_logs(logs):
    print(parse_logs(log))'''
