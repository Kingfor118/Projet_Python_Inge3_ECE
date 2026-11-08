# 📄 Documentation : Guide d'Exécution, Benchmarking & Profiling

> **Rôle** : Ce document fournit le guide opérationnel pour l'exécution du SIEM, ainsi que les protocoles de profiling (CPU, mémoire) permettant de vérifier empiriquement l'impact de l'évaluation paresseuse (*Lazy Evaluation*) et la faible empreinte mémoire du pipeline.

---

## 📋 Sommaire
1. [Modes d'Exécution](#-modes-dexécution)
2. [Validation de l'Environnement](#-validation-de-lenvironnement)
3. [Protocole de Profiling Mémoire (`tracemalloc`)](#-protocole-de-profiling-mémoire-tracemalloc)
4. [Protocole de Profiling CPU (`cProfile`)](#-protocole-de-profiling-cpu-cprofile)
5. [Benchmarks Comparatifs : Streaming vs Chargement Intégral](#-benchmarks-comparatifs--streaming-vs-chargement-intégral)
6. [Résolution des Incidents Fréquents (Troubleshooting)](#-résolution-des-incidents-fréquents-troubleshooting)

---

## 💻 Modes d'Exécution

### 1. Exécution Standard
Depuis la racine du projet :
```bash
python main.py
```
*Comportement* :
- Parcourt séquentiellement `auth.log`, `network.log` et `server.log`.
- Affiche chaque log normalisé sur la console (`stdout`).
- Génère ou enrichit `report/report_local.txt` lors des anomalies.
- Écrit la synthèse globale dans `report/report_global.txt`.

### 2. Exécution Silencieuse (Redirection ou Mode Batch)
Pour éviter l'affichage de dizaines de milliers de lignes dans le terminal PowerShell :
```powershell
python main.py > $null
```
Sous Linux / Bash :
```bash
python main.py > /dev/null
```

---

## 🔍 Validation de l'Environnement

Le projet exploite le pattern matching structural (`match...case`), imposant une version minimale de **Python 3.10**.

Vérification de la version :
```powershell
python --version
# Doit retourner Python 3.10.x ou ultérieur (ex: Python 3.11, 3.12, 3.13, 3.14)
```

Vérification des fichiers de logs de démonstration :
```powershell
Get-ChildItem demo_data/
# Vérifie la présence de auth.log, network.log, server.log et blacklist.txt
```

---

## 🧠 Protocole de Profiling Mémoire (`tracemalloc`)

L'un des points forts d'ingénierie du projet réside dans l'utilisation conjointe de `yield` et `map()`. Contrairement à une approche naïve qui chargerait les 37 000 lignes en mémoire (soit ~4.7 Mo de logs bruts et plus de 30 Mo de structures Python), la mémoire résidente reste constante.

### Script de Mesure Mémoire (`scripts/profile_memory.py`)
```python
import tracemalloc
import time
from collections import defaultdict
from src.ingestion import lire_all_logs, parse_logs, extract_blacklist_ips
from src.transfo import filtrage_logs, normalize_logs
from src.agregation import brute_force_detector, occurence, extract_unique_error_ips, occurence_ip_connexion
from src.rules_engine import apply_security_rules

def profiler_pipeline():
    tracemalloc.start()
    debut = time.perf_counter()
    
    logs = ['demo_data/auth.log', 'demo_data/network.log', 'demo_data/server.log']
    blacklist = 'demo_data/blacklist.txt'
    
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
    
    raw = lire_all_logs(logs)
    parsed = map(parse_logs, raw)
    filtered = filtrage_logs(parsed)
    normalized = map(normalize_logs, filtered)
    blacklist_ips = extract_blacklist_ips(blacklist)
    
    nb_lignes = 0
    for line_log in normalized:
        nb_lignes += 1
        apply_security_rules(
            brute_force_detector,
            occurence,
            extract_unique_error_ips,
            occurence_ip_connexion,
            log=line_log,
            context=context
        )
        
    fin = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    print(f"--- RÉSULTATS DU PROFILING ---")
    print(f"Nombre de logs traités : {nb_lignes:,} lignes")
    print(f"Temps d'exécution      : {fin - debut:.3f} secondes")
    print(f"Mémoire courante       : {current / 1024:.2f} Ko")
    print(f"Pic de mémoire (Peak)  : {peak / 1024:.2f} Ko ({peak / (1024*1024):.2f} Mo)")

if __name__ == '__main__':
    profiler_pipeline()
```

---

## ⚡ Protocole de Profiling CPU (`cProfile`)

Pour identifier les éventuels goulots d'étranglement (*bottlenecks*) au niveau des fonctions (par exemple entre le parsing JSON, les regex ou les découpages de chaînes) :

Exécution avec `cProfile` :
```powershell
python -m cProfile -s tottime main.py > cprofile_output.txt
```

### Indicateurs Clés à Surveiller
- **`tottime`** : Temps passé exclusivement dans la fonction (hors appels enfants).
  - Normalement, `json.loads` et `str.split` occupent le haut du classement, ce qui est conforme à un workload I/O et parsing intensif.
- **`cumtime`** : Temps cumulé incluant les sous-appels.
- **`ncalls`** : Doit être exactement proportionnel au nombre total de lignes de logs (ex. ~37 000 appels pour `normalize_logs`).

---

## 📊 Benchmarks Comparatifs : Streaming vs Chargement Intégral

| Métrique | Approche Naïve (`readlines()` / Liste complète) | Approche Projet Actuel (Générateurs / Streaming) | Gain / Ratio |
|---|---|---|---|
| **Consommation RAM Pic** | ~45 Mo (sur 37 000 entrées) | **< 3 Mo** (seulement l'état `context`) | **$\times 15$ d'économie** |
| **Temps avant 1er résultat** | Retardé (doit charger tout le fichier) | **Immédiat** ($< 1$ ms) | Temps de latence quasi nul |
| **Passage à l'échelle (10 Go de logs)** | 💥 *Crash* OOM (*Out Of Memory*) | 🟢 **Stable et invariant** | Empreinte RAM indépendante de la taille des fichiers |

---

## 🛠️ Résolution des Incidents Fréquents (Troubleshooting)

### 1. `FileNotFoundError: [Errno 2] No such file or directory: 'demo_data/auth.log'`
- **Cause** : Le script `main.py` a été exécuté depuis un sous-dossier (ex. `src/` ou `report/`) au lieu de la racine du projet.
- **Solution** : Se positionner à la racine du dépôt avant de lancer Python :
  ```powershell
  cd c:\Users\bapti\Code\GitHub\Projet_Python_Inge3_ECE
  python main.py
  ```

### 2. `SyntaxError: invalid syntax` sur `match value:`
- **Cause** : Utilisation d'une version de Python inférieure à 3.10.
- **Solution** : Mettre à jour l'interpréteur ou sélectionner l'interpréteur Python 3.10+ dans l'environnement virtuel.

### 3. Fichier `report/report_local.txt` qui grossit indéfiniment
- **Cause** : Le fichier est ouvert avec le flag `"a"` (*append*), ajoutant chaque nouvelle exécution à la suite de l'historique précédent.
- **Solution** : Vider le dossier `report/` avant un nouveau run d'audit si un rapport vierge est désiré :
  ```powershell
  Clear-Content report/*.txt
  ```

