import json
import os
import random
from datetime import datetime, timedelta

NIVEAUX = ["INFO", "WARNING", "ERROR", "CRITICAL"]
UTILISATEURS = ["admin", "alice", "bob", "charlie", "guest", "service"]
EVENEMENTS = ["login_success", "login_failed", "http_request", "tcp_connection"]


# fabrique une ligne de log au hasard
def generer_ligne_log(moment: datetime) -> str:
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
    return f"{horodatage} level={niveau} ip={ip} user={utilisateur} payload={json.dumps(payload)}"


# cree un fichier de logs et renvoie son chemin
def generer_fichier_exemple(nombre_lignes: int = 200, dossier: str = "demo_data") -> str:
    nom_fichier = "exemple_genere_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"
    chemin = os.path.join(dossier, nom_fichier)

    moment = datetime.now()

    with open(chemin, "w", encoding="utf-8") as fichier:
        for _ in range(nombre_lignes):
            moment += timedelta(seconds=2)
            fichier.write(generer_ligne_log(moment) + "\n")

    return chemin
