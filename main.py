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

    # context = un gros dictionnaire ou on range tous les resultats
    # les regles de securite vont le remplir au fur et a mesure
    # defaultdict(int) : si la cle existe pas encore elle vaut 0, donc on peut faire += 1 direct sans KeyError
    # set() : garde chaque ip une seule fois (pas de doublons)
    context = {
        'occurence_brute_force': defaultdict(int),  # nb d'echecs de login a la suite par ip
        'ip_sus_brute_force': set(),                # ip suspectes de brute force
        'occurence_user': defaultdict(int),         # nb d'erreurs par utilisateur
        'occurence_error': defaultdict(int),        # nb de logs par niveau (ERROR, WARNING...)
        'unique_ips': set(),                        # ip qui ont fait des erreurs
        'echecs_par_ip': defaultdict(int),          # nb total de login rates par ip
        'success_par_ip': defaultdict(int),         # nb total de login reussis par ip
        'ports': defaultdict(int),                  # nb de fois qu'on voit chaque port
        'protocols': defaultdict(int),              # nb de fois qu'on voit chaque protocole
        'status_codes': defaultdict(int),           # nb de fois qu'on voit chaque code http
        'formats': defaultdict(int)                 # nb de logs par format (match-case)
    }

    logs = fichiers_logs

    # Dossier de rapport : un sous-dossier horodate (date + heure) est cree
    # dans report/ a chaque scan, pour ne jamais ecraser le rapport precedent.
    horodatage = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dossier_rapport = os.path.join("report", horodatage)
    os.makedirs(dossier_rapport, exist_ok=True)

    # attention : les 4 etapes en dessous ne lisent rien tout de suite
    # elles preparent juste la "chaine", les lignes passent une par une
    # seulement quand on fait la boucle for plus bas (c'est ca qui evite de remplir la ram)

    # Lecture des fichiers (module 1)
    raw_logs = lire_all_logs(logs)

    # Parsing des logs (module 1)
    # map applique parse_logs sur chaque ligne -> chaque ligne devient un dictionnaire
    parsed_logs = map(parse_logs, raw_logs)

    # Filtrage des logs invalides (module 2)
    # on enleve les lignes qui ont pas pu etre lues (None)
    filtered_logs = filtrage_logs(parsed_logs)

    # log normalize du module 2
    # map applique normalize_logs sur chaque log (tout en majuscule, sans espaces)
    normalized_logs = map(normalize_logs, filtered_logs)

    # Agregation des logs (module 3)
    # on recupere les ip de la blacklist dans un frozenset (un set qu'on peut pas modifier)
    blacklist_ips = extract_blacklist_ips(fichier_blacklist)

    # ici on parcourt les logs un par un
    for line_log in normalized_logs:
        print(line_log)
        # on donne les fonctions de regles directement en argument (sans les () donc on les appelle pas ici)
        # elles arrivent dans *args, et tout ce qui a un nom (log=, context=...) arrive dans **kwargs
        var_locals = apply_security_rules(
            brute_force_detector,
            occurence,
            extract_unique_error_ips,
            occurence_ip_connexion,
            compter_formats,
            log=line_log,
            context=context,
            # parametre de configuration : nombre d'echecs de connexion
            # a partir duquel une IP est consideree comme suspecte
            seuil_brute_force=5
        )

        # var_locals = les variables locales de apply_security_rules (renvoyees par locals())
        # on s'en sert pour ecrire le rapport de ce log
        introspection_local(var_locals, dossier_rapport)

    # globals() donne toutes les variables globales du fichier (context, logs, blacklist_ips...)
    # on s'en sert pour faire le rapport final
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

    # os.path.exists regarde si le fichier existe vraiment sur le disque
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
