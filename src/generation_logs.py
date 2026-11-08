import json
import os
import random
from datetime import datetime, timedelta

# Valeurs possibles pour fabriquer des lignes de log réalistes.
NIVEAUX = ["INFO", "WARNING", "ERROR", "CRITICAL"]
UTILISATEURS = ["admin", "alice", "bob", "charlie", "guest", "service"]
EVENEMENTS = ["login_success", "login_failed", "http_request", "tcp_connection"]


def generer_ligne_log(moment):
    """Construit une seule ligne de log, au même format que les fichiers
    de demo_data (ex: auth.log, server.log, network.log)."""
    niveau = random.choice(NIVEAUX)
    ip = f"192.168.1.{random.randint(1, 50)}"
    utilisateur = random.choice(UTILISATEURS)
    evenement = random.choice(EVENEMENTS)

    payload = {"event": evenement}

    if evenement == "login_success":
        payload["success"] = True
    elif evenement == "login_failed":
        payload["success"] = False
    elif evenement == "http_request":
        payload["status"] = random.choice([200, 404, 429, 500])
        payload["method"] = random.choice(["GET", "POST"])
        payload["path"] = "/"
    elif evenement == "tcp_connection":
        payload["port"] = random.choice([80, 443, 22, 3306])
        payload["protocol"] = "TCP"

    horodatage = moment.strftime("%Y-%m-%dT%H:%M:%S")
    payload_json = json.dumps(payload)

    return f"{horodatage} level={niveau} ip={ip} user={utilisateur} payload={payload_json}"


def generer_fichier_exemple(nombre_lignes=200, dossier="demo_data"):
    """Génère un fichier de log d'exemple rempli de lignes aléatoires,
    et renvoie le chemin du fichier créé."""
    nom_fichier = "exemple_genere_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"
    chemin = os.path.join(dossier, nom_fichier)

    moment = datetime.now()

    with open(chemin, "w", encoding="utf-8") as fichier:
        for _ in range(nombre_lignes):
            moment += timedelta(seconds=2)
            ligne = generer_ligne_log(moment)
            fichier.write(ligne + "\n")

    return chemin
