# 📄 Documentation : `main.py` (Orchestration du Pipeline)

> **Rôle** : Point d'entrée principal (orchestrateur) du pipeline SIEM. Il configure le contexte d'état global, initialise la liste des sources de données, assemble la chaîne de traitement paresseuse (ingestion, parsing, filtrage, normalisation) et déclenche l'exécution des règles de sécurité et les phases d'audit par introspection.

---

## 📋 Sommaire
1. [Imports et Dépendances](#-imports-et-dépendances)
2. [Structure de Données : Le Contexte d'État Partagé](#-structure-de-données--le-contexte-détat-partagé)
3. [Configuration des Sources](#-configuration-des-sources)
4. [Étapes Chronologiques du Pipeline](#-étapes-chronologiques-du-pipeline)
5. [Complexité Globale](#-complexité-globale)
6. [Analyse Senior Dev : Points Forts & Recommandations](#-analyse-senior-dev--points-forts--recommandations)

---

## 📦 Imports et Dépendances

```python
from src.ingestion import *
from src.transfo import *
from src.agregation import *
from src.rules_engine import *
from collections import defaultdict
from src.introspection import *
```

- **`src.ingestion`** : Fournit `lire_all_logs`, `parse_logs` et `extract_blacklist_ips`.
- **`src.transfo`** : Fournit `filtrage_logs` et `normalize_logs`.
- **`src.agregation`** : Fournit les règles de sécurité (`brute_force_detector`, `occurence`, `extract_unique_error_ips`, `occurence_ip_connexion`).
- **`src.rules_engine`** : Fournit le moteur générique `apply_security_rules`.
- **`src.introspection`** : Fournit `introspection_local` et `introspection_global`.
- **`collections.defaultdict`** : Structure de dictionnaire auto-initialisant les clés inexistantes avec une valeur par défaut (`0` pour `int`).

---

## 🧠 Structure de Données : Le Contexte d'État Partagé

Le dictionnaire `context` (lignes 11 à 22) sert de référentiel d'état en mémoire partagé entre toutes les règles d'agrégation au cours du passage de chaque log normalisé :

| Clé du Contexte | Type | Initialisation | Rôle dans le Pipeline |
|---|---|---|---|
| `occurence_brute_force` | `defaultdict(int)` | `defaultdict(int)` | Compteur d'échecs d'authentification consécutifs par adresse IP. Remis à 0 en cas de succès. |
| `ip_sus_brute_force` | `set` | `set()` | Ensemble des adresses IP ayant atteint ou dépassé le seuil critique (5 échecs consécutifs). |
| `occurence_user` | `defaultdict(int)` | `defaultdict(int)` | Nombre d'erreurs (`ERROR`, `WARNING`, `CRITICAL`) associées à chaque nom d'utilisateur. |
| `occurence_error` | `defaultdict(int)` | `defaultdict(int)` | Décompte du nombre total d'événements par niveau de criticité anormal. |
| `unique_ips` | `set` | `set()` | Ensemble des adresses IP uniques ayant généré au moins un log d'erreur/avertissement. |
| `echecs_par_ip` | `defaultdict(int)` | `defaultdict(int)` | Nombre total de connexions échouées (`LOGIN_FAILED`) par IP (historique absolu). |
| `success_par_ip` | `defaultdict(int)` | `defaultdict(int)` | Nombre total de connexions réussies (`LOGIN_SUCCESS`) par IP (historique absolu). |
| `ports` | `defaultdict(int)` | `defaultdict(int)` | Fréquence d'utilisation de chaque port réseau (ex. 80, 443, 22). |
| `protocols` | `defaultdict(int)` | `defaultdict(int)` | Fréquence d'utilisation de chaque protocole réseau (ex. TCP, UDP, HTTPS). |
| `status_codes` | `defaultdict(int)` | `defaultdict(int)` | Distribution des statuts retournés (ex. 200, 401, 404, 500). |

---

## ⚙️ Configuration des Sources

```python
logs = [     
    'demo_data/auth.log',   
    'demo_data/network.log',
    'demo_data/server.log',
]

blacklist = [
    'demo_data/blacklist.txt'
]
```

- **`logs`** : Liste ordonnée des chemins relatifs vers les fichiers journaux à ingérer.
- **`blacklist`** : Chemin vers le fichier texte listant les adresses IP considérées comme malveillantes ou interdites.

---

## 🚀 Étapes Chronologiques du Pipeline

### Étape 1 : Lecture en streaming (Module 1)
```python
raw_logs = lire_all_logs(logs)
```
- **Type retourné** : Générateur Python (`Iterator[tuple[str, int, str]]`).
- **Comportement** : Ouvre séquentiellement chaque fichier sans le charger entièrement en RAM. Chaque élément produit est un triplet : `(ligne_brute_sans_retour, numero_ligne, chemin_fichier)`.

### Étape 2 : Parsing et désérialisation JSON (Module 1)
```python
parsed_logs = map(parse_logs, raw_logs)
```
- **Type retourné** : Itérateur d'évaluation paresseuse (`map`).
- **Comportement** : Découpe la ligne de log, sépare les paires `clé=valeur`, décode le payload JSON et renvoie un dictionnaire structuré ou `None` en cas d'erreur de syntaxe.

### Étape 3 : Filtrage des enregistrements invalides (Module 2)
```python
filtered_logs = filtrage_logs(parsed_logs)
```
- **Type retourné** : Générateur Python filtré.
- **Comportement** : Écarte tous les enregistrements `None` ou les dictionnaires vides `{}` issus de lignes corrompues.

### Étape 4 : Normalisation typographique (Module 2)
```python
normalized_logs = map(normalize_logs, filtered_logs)
```
- **Type retourné** : Itérateur d'évaluation paresseuse (`map`).
- **Comportement** : Transforme les clés et valeurs textuelles en majuscules uniformes pour garantir l'insensibilité à la casse.

### Étape 5 : Extraction de la Blacklist (Module 3 / Ingestion)
```python
blacklist_ips = extract_blacklist_ips(blacklist[0])
```
- **Type retourné** : `frozenset[str]`.
- **Comportement** : Lit le fichier `blacklist.txt` et charge les IP dans une collection immuable à accès en temps constant $\mathcal{O}(1)$.

### Étape 6 : Boucle d'Évaluation & Traitement Événementiel
```python
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

    introspection_local(var_locals)
```
- **Consommation du flux** : La boucle `for` est le moteur d'évaluation qui "tire" chaque log à travers la chaîne de générateurs (`normalized_logs` $\leftarrow$ `filtered_logs` $\leftarrow$ `parsed_logs` $\leftarrow$ `raw_logs`). Un seul log réside en mémoire à un instant donné.
- **Exécution des règles** : Appel de `apply_security_rules` qui applique les 4 règles de sécurité passées en paramètres positionnels (`*args`) sur le log et le contexte (`**kwargs`).
- **Audit local** : `var_locals` capture le dictionnaire `locals()` renvoyé par le moteur de règles et le transmet à `introspection_local` pour écrire dans `report/report_local.txt` si une anomalie ou alerte est identifiée.

### Étape 7 : Audit Global et Synthèse en Fin de Flux
```python
var_globals = globals()
introspection_global(var_globals)
```
- Récupère le dictionnaire de l'espace des noms global `globals()`.
- Exécute `introspection_global` qui corrèle les IP actives avec la blacklist et écrit la synthèse consolidée dans `report/report_global.txt`.

---

## 📈 Complexité Globale

- **Complexité Temporelle** : $\mathcal{O}(N)$ où $N$ est le nombre total de lignes de logs dans l'ensemble des fichiers. Chaque ligne traverse le pipeline en temps moyen constant $\mathcal{O}(1)$ grâce aux tables de hachage (`dict`, `set`, `defaultdict`). Le tri final dans le rapport global s'exécute en $\mathcal{O}(U \log U)$ où $U \ll N$ est le nombre d'IP uniques.
- **Complexité Spatiale** : $\mathcal{O}(U + C)$ où $U$ est le nombre d'IP uniques et $C$ la taille des contextes/dictionnaires d'occurrences. La mémoire vive ne dépend pas du nombre de lignes $N$ mais uniquement du nombre d'entités uniques observées.

---

## 💡 Analyse Senior Dev : Points Forts & Recommandations

### ✅ Points Forts
1. **Streaming méconnu mais élégant** : La composition de `map()` et de générateurs (`yield`) évite les dépassements de mémoire vive (*Out of Memory*).
2. **Découplage règles / orchestration** : La liste des règles appliquées dans `apply_security_rules` est totalement paramétrable sans modifier la boucle de consommation.

### ⚠️ Recommandations d'Amélioration & Bonnes Pratiques
1. **Éviter les imports wildcard (`from module import *`)** :
   - *Problème* : Pollue le namespace global, rend l'analyse statique difficile et peut masquer des écrasements de variables involontaires.
   - *Solution* : Expliciter les imports : `from src.ingestion import lire_all_logs, parse_logs, extract_blacklist_ips`.
2. **Introduire la clause guard standard `if __name__ == '__main__':`** :
   - *Problème* : Actuellement, importer `main.py` déclenche immédiatement l'analyse et la lecture des fichiers sur le disque.
   - *Solution* : Encapsuler l'orchestration dans une fonction `def main():` protégée par `if __name__ == '__main__':`.
3. **Usage de `pathlib.Path`** :
   - *Problème* : Chemins écrits sous forme de chaînes de caractères relatives avec des séparateurs slash `/`.
   - *Solution* : Utiliser `pathlib.Path(__file__).resolve().parent / "demo_data" / "auth.log"` pour une compatibilité multiplateforme native (Windows/Linux/macOS).
4. **Typage de `context` via un `dataclass` ou `TypedDict`** :
   - Remplacer le dictionnaire brut par une classe typée apporte l'autocomplétion et évite les erreurs d'inattention sur les noms de clés (`occurence_brute_force` vs `echecs_par_ip`).

