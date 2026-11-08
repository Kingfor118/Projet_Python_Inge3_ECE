# Projet Python ING3 - Analyse de logs

Projet Python ING3 ECE (en trinome) : un outil en ligne de commande qui lit des fichiers de logs, les filtre, les normalise et applique des regles de securite (detection de brute force, comparaison avec une blacklist d'IP...). A la fin, un rapport est genere.

## Installation

Il faut Python 3.12 ou plus pour installer le requirements.txt (les versions figees de numpy et matplotlib l'exigent).

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

(sur Linux / Mac : `source .venv/bin/activate`)

Le pipeline n'utilise que la bibliotheque standard. Le requirements.txt liste Jupyter et matplotlib, utilises uniquement par le rapport (`report/rapport.ipynb`).

## Lancement

Avec les fichiers de demo :

```
python main.py
```

Ou avec le menu, pour choisir ses propres fichiers de log ou en generer un :

```
python start.py
```

Les rapports sont crees dans `report/<date>_<heure>/` (report_global.txt et report_local.txt).

Le rapport de projet, deja execute, est `report/rapport.ipynb`. Pour le relancer :

```
jupyter notebook report/rapport.ipynb
```

## Organisation

- `main.py` : lance tout le pipeline
- `start.py` : menu pour choisir les fichiers
- `src/ingestion.py` : lecture des fichiers avec des generateurs + parsing des lignes
- `src/transfo.py` : filtrage et normalisation des logs
- `src/agregation.py` : comptages, IP uniques, detection de brute force
- `src/rules_engine.py` : moteur de regles (`apply_security_rules`)
- `src/introspection.py` : rapports a partir de globals() / locals()
- `src/generation_logs.py` : generation d'un fichier de log d'exemple
- `demo_data/` : logs de test et blacklist (`echantillon.log` : petit exemple utilise par le notebook)
- `report/rapport.ipynb` : rapport de projet (demonstration et graphiques)

Format d'une ligne de log :

```
2026-10-15T08:00:00 level=ERROR ip=192.168.1.13 user=admin payload={"event":"login_failed","success":false}
```
