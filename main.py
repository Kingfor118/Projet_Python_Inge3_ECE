from src.ingestion import *


logs = [
        'demo_data/auth.log',
        'demo_data/blacklist.txt',
        'demo_data/network.log',
        'demo_data/server.log'
    ]

for log in lire_all_logs(logs):
    print(log)
