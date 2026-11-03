import os
from datetime import datetime

from src.ingestion import *
from src.transfo import *
from src.agregation import *
from src.rules_engine import *
from collections import defaultdict
from src.introspection import *


def lancer_pipeline(fichiers_logs, fichier_blacklist):
    """Lance le pipeline complet : lecture, filtrage, normalisation,
    puis application des règles de sécurité sur les logs.

    fichiers_logs : liste des chemins des fichiers de logs à analyser.
    fichier_blacklist : chemin du fichier contenant les IP blacklistées.
    """
    # "global" sert ici à ce que context/logs/blacklist_ips restent visibles
    # par globals(), utilisé plus bas par introspection_global().
    global context, logs, blacklist_ips, var_locals, var_globals

    var_locals = {}
    var_globals = {}

    context = {
        'occurence_brute_force': defaultdict(int),
        'ip_sus_brute_force': set(),
        'occurence_user': defaultdict(int),
        'occurence_error': defaultdict(int),
        'unique_ips': set(),
        'echecs_par_ip': defaultdict(int),
        'success_par_ip': defaultdict(int),
        'ports': defaultdict(int),
        'protocols': defaultdict(int),
        'status_codes': defaultdict(int)
    }

    logs = fichiers_logs

    # Dossier de rapport : un sous-dossier horodate (date + heure) est cree
    # dans report/ a chaque scan, pour ne jamais ecraser le rapport precedent.
    horodatage = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dossier_rapport = os.path.join("report", horodatage)
    os.makedirs(dossier_rapport, exist_ok=True)

    # Lecture des fichiers (module 1)
    raw_logs = lire_all_logs(logs)

    # Parsing des logs (module 1)
    parsed_logs = map(parse_logs, raw_logs)

    # Filtrage des logs invalides (module 2)
    filtered_logs = filtrage_logs(parsed_logs)

    # log normalize du module 2
    normalized_logs = map(normalize_logs, filtered_logs)

    # Agregation des logs (module 3)
    blacklist_ips = extract_blacklist_ips(fichier_blacklist)

    for line_log in normalized_logs:
        print(line_log)
        var_locals = apply_security_rules(
            brute_force_detector,
            occurence,
            extract_unique_error_ips,
            occurence_ip_connexion,
            log=line_log,
            context=context
        )

        introspection_local(var_locals, dossier_rapport)

    var_globals = globals()
    introspection_global(var_globals, dossier_rapport)

    verifier_rapport(dossier_rapport)

    return dossier_rapport


def verifier_rapport(dossier_rapport):
    """Verifie que les fichiers de rapport ont bien ete crees, et affiche
    le resultat dans le terminal pour etre sur que le scan s'est bien passe."""
    fichier_global = os.path.join(dossier_rapport, "report_global.txt")
    fichier_local = os.path.join(dossier_rapport, "report_local.txt")

    print()
    print("=== Verification du rapport ===")
    print(f"Dossier : {dossier_rapport}")

    if os.path.exists(fichier_global):
        print(f"- report_global.txt : OK ({fichier_global})")
    else:
        print(f"- report_global.txt : MANQUANT ({fichier_global})")

    if os.path.exists(fichier_local):
        print(f"- report_local.txt : OK ({fichier_local})")
    else:
        print(f"- report_local.txt : MANQUANT ({fichier_local})")


if __name__ == "__main__":
    # Si on lance main.py directement (sans passer par start.py),
    # on utilise les fichiers de démonstration par défaut.
    fichiers_demo = [
        'demo_data/auth.log',
        'demo_data/network.log',
        'demo_data/server.log',
    ]
    blacklist_demo = 'demo_data/blacklist.txt'

    lancer_pipeline(fichiers_demo, blacklist_demo)
