# 📄 Documentation : `src/ingestion.py` (Module 1 : Ingestion des Données)

> **Rôle** : Ce module assure l'accès aux données sources sur disque. Il implémente la lecture en streaming (générateurs paresseux), la désérialisation du format hybride texte/JSON des journaux d'événements et le chargement immuable de la liste noire d'adresses IP.

---

## 📋 Sommaire des Fonctions

| Fonction | Signature Complète | Rôle Principal |
|---|---|---|
| [`lire_logs`](#1-lire_logs) | `(path: str) -> Iterator[tuple[str, int, str]]` | Générateur lisant un fichier ligne par ligne sans saturation mémoire. |
| [`lire_all_logs`](#2-lire_all_logs) | `(path: Iterable[str]) -> Iterator[tuple[str, int, str]]` | Générateur chaînant la lecture de plusieurs fichiers via `yield from`. |
| [`parse_logs`](#3-parse_logs) | `(logs: tuple[str, int, str]) -> dict \| None` | Parseur textuel & JSON extrayant et validant les métadonnées et payloads. |
| [`extract_blacklist_ips`](#4-extract_blacklist_ips) | `(path: str) -> frozenset[str]` | Charge les IP interdites dans un ensemble immuable pour tests en $\mathcal{O}(1)$. |

---

## 🔍 Analyse Détaillée des Fonctions

### 1. `lire_logs`

#### Code Source
```python
def lire_logs(path: str) -> Iterator[tuple[str, int, str]]:
    with open(path, 'r', encoding='UTF-8') as file_obj:
        for numero, line in enumerate(file_obj, start=1):
            yield line.strip(), numero, path
```

#### Description Fonctionnelle
Lit un fichier texte encodé en UTF-8 ligne après ligne de manière paresseuse (*lazy evaluation*). Grâce à l'instruction `yield`, le fichier n'est pas stocké en mémoire vive dans son intégralité : chaque ligne est lue, nettoyée de ses caractères d'espacement et retournée au consommateur à la demande.

#### Paramètres
- **`path`** (`str`) : Chemin absolu ou relatif vers le fichier de logs à lire.

#### Valeur de Retour
- **`Iterator[tuple[str, int, str]]`** : Générateur produisant un triplet à chaque itération :
  1. `line.strip()` (`str`) : Le texte de la ligne nettoyé des retours chariots (`\n`, `\r`) et espaces de début/fin.
  2. `numero` (`int`) : L'index de la ligne dans le fichier, indexé à partir de 1.
  3. `path` (`str`) : Le nom ou chemin du fichier source d'origine (utile pour la traçabilité des erreurs).

#### Algorithme Interne
1. Ouverture sécurisée du fichier dans un gestionnaire de contexte `with open(..., encoding='UTF-8')` garantissant la fermeture du descripteur de fichier en toute circonstance.
2. Utilisation de `enumerate(file_obj, start=1)` qui itère directement sur le descripteur de fichier par petits tampons (buffers).
3. Émission immédiate via `yield` du triplet composé de la ligne épurée, de son numéro et de son chemin.

#### Complexités
- **Temporelle** : $\mathcal{O}(L)$ où $L$ est le nombre de lignes du fichier. Chaque itération s'exécute en $\mathcal{O}(M)$ où $M$ est la longueur de la ligne lue.
- **Spatiale** : $\mathcal{O}(M)$ en mémoire résidente (la taille de la ligne courante uniquement).

---

### 2. `lire_all_logs`

#### Code Source
```python
def lire_all_logs(path) -> Iterator[tuple[str, int]]:
    for p in path:
        yield from lire_logs(p)
```

#### Description Fonctionnelle
Permet de fusionner virtuellement plusieurs fichiers de logs en un seul flux continu d'éléments, sans devoir concaténer ou copier des fichiers sur le disque ou en mémoire.

#### Paramètres
- **`path`** (`Iterable[str]`) : Collection (liste, tuple, ensemble) contenant les chemins des fichiers de logs à traiter séquentiellement.

#### Valeur de Retour
- **`Iterator[tuple[str, int, str]]`** : Générateur continu produisant les triplets issus successivement de chaque fichier. *(Remarque : le type hint `Iterator[tuple[str, int]]` dans le code omet le 3e élément `path` du tuple).*

#### Algorithme Interne
1. Parcourt chaque chemin `p` présent dans la collection `path`.
2. Délègue l'itération à la sous-fonction `lire_logs(p)` via l'instruction `yield from`. Dès qu'un fichier est entièrement parcouru, son descripteur est fermé et le fichier suivant est ouvert.

#### Complexités
- **Temporelle** : $\mathcal{O}(\sum L_i)$ où $L_i$ est le nombre de lignes de chaque fichier $i$.
- **Spatiale** : $\mathcal{O}(1)$ au-delà du buffer de lecture de la ligne en cours.

---

### 3. `parse_logs`

#### Code Source
```python
def parse_logs(logs: str) -> dict:
    numero = logs[1] 
    fichier = logs[2]
    ### utilisé du regex après pour faire le parsing
    try:
        parts = logs[0].split(maxsplit=4)
        
        time = parts[0].split('T')
        level = parts[1].split('=', 1)
        ip = parts[2].split('=', 1)
        user = parts[3].split('=', 1)
        payload_string = parts[4].split('=', 1)
        payload = json.loads(payload_string[1])

        if payload.get("event") is None:
            raise ValueError(f"ligne le payload ne contient pas event")
        
        metadata_tuple = (
            payload.get("port"),
            payload.get("protocol"),
            payload.get("status"),
            payload.get("method"),
        )

        if (
            level[0] != "level"
            or ip[0] != "ip"
            or user[0] != "user"
            or payload_string[0] != "payload"
        ):
            raise ValueError(f"Les titre des ne sont pas corrects")

        else:
            logs_dict = {
                "time": f'{time[0]} {time[1]}',
                "level": level[1],
                "ip": ip[1],
                "user": user[1],
                "payload": payload,
                "metadata": metadata_tuple
            }
            return logs_dict

    except Exception as e:
        print(f"ligne {numero} Erreur: {e} fichier {fichier}")
        return None
```

#### Description Fonctionnelle
Analyse syntaxiquement chaque entrée brute pour la convertir en un dictionnaire standardisé. Elle extrait les champs d'en-tête (`time`, `level`, `ip`, `user`), désérialise la chaîne JSON représentant le `payload`, vérifie la validité des étiquettes et isole les métadonnées réseau courantes sous forme de tuple immuable.

#### Format Attendu des Logs
Les lignes de logs sont supposées suivre le format standardisé suivant :
```text
2026-03-11T10:15:32 level=INFO ip=192.168.1.10 user=admin payload={"event":"LOGIN_SUCCESS","port":443,"protocol":"TCP"}
```

#### Paramètres
- **`logs`** (`tuple[str, int, str]`) : Le triplet généré par `lire_logs`, composé de `(raw_line, line_number, file_path)`. *(Note : le paramètre est annoté `logs: str` mais reçoit un tuple).*

#### Valeur de Retour
- **`dict`** : Si le parsing et les validations réussissent, retourne :
  ```python
  {
      "time": "2026-03-11 10:15:32",
      "level": "INFO",
      "ip": "192.168.1.10",
      "user": "admin",
      "payload": {"event": "LOGIN_SUCCESS", "port": 443, "protocol": "TCP"},
      "metadata": (443, "TCP", None, None)
  }
  ```
- **`None`** : Si une exception survient (format invalide, JSON corrompu, clé absente), un message d'avertissement est affiché sur la console et la fonction retourne `None`.

#### Algorithme Interne
1. Récupère le numéro de ligne `logs[1]` et le fichier `logs[2]`.
2. Découpe la ligne avec `logs[0].split(maxsplit=4)` :
   - Évite les découpages superflus dans le payload JSON grâce à `maxsplit=4`.
   - Index 0 : horodatage ISO (`YYYY-MM-DDTHH:MM:SS`).
   - Index 1 à 4 : `level=...`, `ip=...`, `user=...`, `payload={...}`.
3. Formate l'horodatage en remplaçant le séparateur `T` par un espace (`time[0] time[1]`).
4. Sépare chaque paire clé/valeur au premier signe égal (`.split('=', 1)`).
5. Désérialise le JSON via `json.loads(payload_string[1])`.
6. Valide la présence impérative de la clé `event` dans le payload (`payload.get("event") is None -> ValueError`).
7. Valide les étiquettes des champs obligatoires (`level[0] == "level"`, `ip[0] == "ip"`, etc.).
8. Extrait le 4-tuple de métadonnées `(port, protocol, status, method)`.

#### Gestion des Erreurs et Cas Limites
- `IndexError` : Ligne tronquée ou vide ne comportant pas 5 éléments distincts.
- `json.JSONDecodeError` : Payload JSON malformé ou tronqué.
- `ValueError` : Absence du champ `event` ou non-respect du nom des étiquettes.
- Toutes ces exceptions sont interceptées par le bloc `except Exception as e:`, consignant l'erreur sur `stdout` sans bloquer le traitement global.

---

### 4. `extract_blacklist_ips`

#### Code Source
```python
def extract_blacklist_ips(path) -> frozenset:
    with open(path, 'r') as f:
        return frozenset(line.strip() for line in f if line.strip())
```

#### Description Fonctionnelle
Lit un fichier contenant une liste d'adresses IP interdites (une adresse par ligne), élimine les lignes vides et les espaces, et les charge dans un ensemble immuable (`frozenset`).

#### Paramètres
- **`path`** (`str`) : Chemin vers le fichier de liste noire (ex. `'demo_data/blacklist.txt'`).

#### Valeur de Retour
- **`frozenset[str]`** : Ensemble immuable d'adresses IP uniques au format chaîne de caractères.

#### Algorithme Interne
1. Ouvre le fichier en lecture avec `with open(...)`.
2. Utilise une expression génératrice `(line.strip() for line in f if line.strip())` qui filtre directement les lignes blanches.
3. Transmet ce générateur au constructeur `frozenset()`.

#### Intérêt de Conception (Pourquoi un `frozenset` ?)
1. **Complexité de recherche en $\mathcal{O}(1)$** : L'appartenance `ip in blacklist_ips` est calculée en temps constant moyen via une table de hachage, contrairement à une liste en $\mathcal{O}(K)$.
2. **Immuabilité et Sécurité** : Les données de référence ne peuvent être altérées accidentellement par une fonction tierce pendant l'exécution.
3. **Opérations Ensemblistes Natives** : Permet l'utilisation directe des opérateurs Python `|` (union), `&` (intersection), `-` (différence) et `^` (différence symétrique).

---

## 💡 Analyse Senior Dev : Points Forts & Recommandations

### ✅ Points Forts
- Gestion fainéante des fichiers garantissant la scalabilité horizontale.
- Découpage optimisé grâce à `maxsplit=4` qui préserve l'intégrité de chaînes JSON contenant des espaces.
- Utilisation judicieuse du `frozenset`.

### ⚠️ Recommandations d'Amélioration & Robustesse
1. **Correction des Type Hints** :
   - `parse_logs(logs: str)` devrait être typé : `parse_logs(logs: tuple[str, int, str]) -> dict | None`.
   - `lire_all_logs(path)` devrait être annoté avec `path: Iterable[str]`.
2. **Encodage explicite sur la Blacklist** :
   - Dans `extract_blacklist_ips`, spécifier `open(path, 'r', encoding='UTF-8')` pour éviter des comportements imprévus sous Windows (qui utilise par défaut l'encodage CP1252/ANSI).
3. **Journalisation vs Print** :
   - Remplacer `print(f"ligne {numero} Erreur: {e} fichier {fichier}")` par le module standard `logging` (`logger.warning(...)`) pour diriger les flux d'erreurs vers `stderr` ou un fichier de log dédié.

