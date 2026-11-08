import os
from collections import defaultdict
from datetime import datetime

from src.agregation import (
    brute_force_detector,
    compter_formats,
    extract_active_ips,
    extract_unique_error_ips,
    occurence,
    occurence_ip_connexion,
)
from src.ingestion import extract_blacklist_ips, lire_all_logs, parse_logs
from src.introspection import introspection_audit, introspection_global, introspection_local
from src.rules_engine import apply_security_rules
from src.transfo import filtrage_logs, normalize_logs


def lancer_pipeline(fichiers_logs: list[str], fichier_blacklist: str) -> str:
    """Lance tout le pipeline et renvoie le dossier du rapport."""
    # global : pour retrouver ces variables dans globals()
    global context, logs, blacklist_ips

    context = {
        'occurence_brute_force': defaultdict(int),  # echecs a la suite par ip
        'ip_sus_brute_force': set(),                # ip suspectes
        'occurence_user': defaultdict(int),         # alertes par utilisateur
        'occurence_error': defaultdict(int),        # alertes par niveau
        'ips_actives': set(),                       # toutes les ip vues
        'unique_ips': set(),                        # ip avec des erreurs
        'echecs_par_ip': defaultdict(int),          # logins rates par ip
        'success_par_ip': defaultdict(int),         # logins reussis par ip
        'ports': defaultdict(int),
        'protocols': defaultdict(int),
        'status_codes': defaultdict(int),
        'formats': defaultdict(int),                # formats vus par match-case
    }
    logs = fichiers_logs

    # un dossier par scan pour ne pas ecraser les anciens rapports
    horodatage = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dossier_rapport = os.path.join("report", horodatage)
    os.makedirs(dossier_rapport, exist_ok=True)

    # rien n'est lu ici : les lignes passent une par une dans le for
    raw_logs = lire_all_logs(logs)
    parsed_logs = map(parse_logs, raw_logs)
    filtered_logs = filtrage_logs(parsed_logs)
    normalized_logs = map(normalize_logs, filtered_logs)

    blacklist_ips = extract_blacklist_ips(fichier_blacklist)

    for line_log in normalized_logs:
        print(line_log)
        variables = apply_security_rules(
            brute_force_detector,
            occurence,
            extract_active_ips,
            extract_unique_error_ips,
            occurence_ip_connexion,
            compter_formats,
            log=line_log,
            context=context,
            seuil_brute_force=5,
        )
        introspection_local(variables, dossier_rapport)

    introspection_global(globals(), dossier_rapport)
    introspection_audit(locals(), globals(), dossier_rapport)
    verifier_rapport(dossier_rapport)

    return dossier_rapport


def verifier_rapport(dossier_rapport: str) -> None:
    """Affiche si les fichiers du rapport existent."""
    print("\n=== Verification du rapport ===")
    print(f"Dossier : {dossier_rapport}")

    for nom in ("report_global.txt", "report_local.txt"):
        chemin = os.path.join(dossier_rapport, nom)
        etat = "OK" if os.path.exists(chemin) else "absent"
        print(f"- {nom} : {etat}")


if __name__ == "__main__":
    fichiers_demo = [
        'demo_data/auth.log',
        'demo_data/network.log',
        'demo_data/server.log',
    ]
    lancer_pipeline(fichiers_demo, 'demo_data/blacklist.txt')
