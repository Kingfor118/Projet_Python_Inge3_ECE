# 📄 Documentation : `src/agregation.py` (Module 3 : Agrégation & Règles Métier)

> **Rôle** : Ce module concentre l'intelligence analytique du SIEM. Il contient l'ensemble des règles de sécurité et de calcul statistique appliquées à chaque événement normalisé. Il maintient l'état dans le dictionnaire `context` (détection d'attaques par force brute, dénombrement des anomalies, métriques réseau).

---

## 📋 Sommaire des Fonctions

| Fonction | Signature Complète | Rôle Principal |
|---|---|---|
| [`brute_force_detector`](#1-brute_force_detector) | `(log: dict, context: dict) -> None` | Détection dynamique des attaques par force brute (seuil de 5 échecs consécutifs). |
| [`extract_unique_error_ips`](#2-extract_unique_error_ips) | `(log: dict, context: dict) -> None` | Recense les adresses IP associées à des niveaux de log critiques. |
| [`occurence`](#3-occurence) | `(log: dict, context: dict) -> None` | Dénombre les événements par niveau d'anomalie et par utilisateur incriminé. |
| [`occurence_ip_connexion`](#4-occurence_ip_connexion) | `(log: dict, context: dict) -> None` | Enregistre l'historique global des succès/échecs, protocoles, ports et statuts HTTP. |

---

## 🔍 Analyse Détaillée des Fonctions

### 1. `brute_force_detector`

#### Code Source
```python
def brute_force_detector(log: dict, context: dict):
    ip = log.get('IP')
    payload = log.get('PAYLOAD') or {}
    event = payload.get('EVENT')

    if event == 'LOGIN_SUCCESS':
        context['occurence_brute_force'][ip] = 0

    if event == 'LOGIN_FAILED':
        context['occurence_brute_force'][ip] += 1

    if context['occurence_brute_force'][ip] >= 5:
        context['ip_sus_brute_force'].add(ip)
```

#### Description Fonctionnelle
Surveille le flux des tentatives d'authentification pour chaque adresse IP. Elle modélise une **machine à états finis** pour identifier les comportements malveillants typiques des attaques par dictionnaire ou force brute :
- Une tentative infructueuse (`LOGIN_FAILED`) incrémente le compteur d'échecs consécutifs de l'IP.
- Dès que ce compteur atteint ou dépasse le seuil critique fixé à **5**, l'adresse IP est marquée comme suspecte et ajoutée à l'ensemble `ip_sus_brute_force`.
- Une connexion réussie (`LOGIN_SUCCESS`) remet le compteur d'échecs consécutifs à 0, modélisant ainsi une authentification légitime après de rares erreurs de saisie.

#### Paramètres
- **`log`** (`dict`) : Dictionnaire de log normalisé.
- **`context`** (`dict`) : Contexte global d'état. Les clés modifiées sont :
  - `context['occurence_brute_force']` (`defaultdict(int)`)
  - `context['ip_sus_brute_force']` (`set`)

#### Valeur de Retour
- **`None`** : Mutation par effet de bord (*in-place modification*) des structures de données de `context`.

#### Cas Limites & Robustesse
- Si `log.get('PAYLOAD')` vaut `None`, l'expression `or {}` garantit qu'aucune exception `AttributeError` n'est levée lors du `.get('EVENT')`.
- Si `ip` n'a jamais été rencontré, le `defaultdict(int)` initialise automatiquement le compteur à `0`.

#### Complexité
- **Temporelle** : $\mathcal{O}(1)$ (recherches et écritures par table de hachage).
- **Spatiale** : $\mathcal{O}(1)$ par appel.

---

### 2. `extract_unique_error_ips`

#### Code Source
```python
def extract_unique_error_ips(log, context: dict):
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
        context['unique_ips'].add(log.get("IP"))
```

#### Description Fonctionnelle
Isole les adresses IP ayant généré au moins un journal d'alerte ou d'erreur (`ERROR`, `CRITICAL` ou `WARNING`). L'ensemble `context['unique_ips']` ainsi constitué sert ultérieurement de pivot pour les calculs statistiques et la corrélation avec la liste noire dans le module d'introspection.

#### Paramètres
- **`log`** (`dict | None`) : Dictionnaire de log normalisé.
- **`context`** (`dict`) : Contexte global d'état. Clé modifiée : `context['unique_ips']` (`set`).

#### Valeur de Retour
- **`None`** : Insertion dans le `set` (les doublons sont automatiquement ignorés).

#### Complexité
- **Temporelle** : $\mathcal{O}(1)$ moyen (appartenance à un tuple de 3 éléments et insertion dans un `set`).
- **Spatiale** : $\mathcal{O}(1)$ par appel.

---

### 3. `occurence`

#### Code Source
```python
def occurence(log: dict, context: dict):
    if log is not None and log.get("LEVEL") in ("ERROR", "CRITICAL", "WARNING"):
        context['occurence_error'][log.get("LEVEL")] += 1
        context['occurence_user'][log.get("USER")] += 1
```

#### Description Fonctionnelle
Comptabilise la fréquence des événements anormaux selon deux dimensions d'analyse :
1. **Par niveau de sévérité** (`LEVEL`) : Permet de connaître la volumétrie relative des `WARNING`, `ERROR` et `CRITICAL`.
2. **Par compte utilisateur** (`USER`) : Identifie les comptes utilisateurs les plus exposés ou les plus actifs lors d'incidents de sécurité.

#### Paramètres
- **`log`** (`dict | None`) : Dictionnaire de log normalisé.
- **`context`** (`dict`) : Contexte global d'état. Clés modifiées :
  - `context['occurence_error']` (`defaultdict(int)`)
  - `context['occurence_user']` (`defaultdict(int)`)

#### Valeur de Retour
- **`None`** : Incrémentation sur place.

#### Complexité
- **Temporelle** : $\mathcal{O}(1)$ (deux accès par hachage et deux incrémentations).
- **Spatiale** : $\mathcal{O}(1)$.

---

### 4. `occurence_ip_connexion`

#### Code Source
```python
def occurence_ip_connexion(log: dict, context: dict):
    payload = log.get("PAYLOAD") or {}
    event = payload.get("EVENT")
    ip = log.get("IP")

    if event == "LOGIN_SUCCESS":
        context['success_par_ip'][ip] += 1

    elif event == "LOGIN_FAILED":
        context['echecs_par_ip'][ip] += 1

    if payload.get("PROTOCOL"):
        context['protocols'][payload.get("PROTOCOL")] += 1

    if payload.get("PORT"):
        context['ports'][payload.get("PORT")] += 1

    if payload.get("STATUS"):
        context['status_codes'][payload.get("STATUS")] += 1
```

#### Description Fonctionnelle
Collecte les métriques globales d'infrastructure et d'authentification :
- Compte le nombre total de réussites et d'échecs pour chaque IP sur l'ensemble de la période d'observation (contrairement à `brute_force_detector` qui ne compte que les échecs consécutifs).
- Enregistre la distribution des protocoles utilisés (ex. `SSH`, `HTTP`, `HTTPS`, `DNS`).
- Enregistre la distribution des ports de destination (ex. `22`, `80`, `443`).
- Dénombre les codes de statut HTTP ou applicatifs renvoyés (ex. `200`, `401`, `403`, `500`).

#### Paramètres
- **`log`** (`dict`) : Dictionnaire de log normalisé.
- **`context`** (`dict`) : Contexte global d'état. Clés modifiées :
  - `context['success_par_ip']` (`defaultdict(int)`)
  - `context['echecs_par_ip']` (`defaultdict(int)`)
  - `context['protocols']` (`defaultdict(int)`)
  - `context['ports']` (`defaultdict(int)`)
  - `context['status_codes']` (`defaultdict(int)`)

#### Valeur de Retour
- **`None`**.

#### Complexité
- **Temporelle** : $\mathcal{O}(1)$.
- **Spatiale** : $\mathcal{O}(1)$.

---

## 💡 Analyse Senior Dev : Points Forts & Recommandations

### ✅ Points Forts
- **Performance optimale** : Toutes les règles s'exécutent en temps constant $\mathcal{O}(1)$ strict, ce qui est indispensable pour un traitement de flux en temps réel.
- **Faible couplage** : Chaque fonction ne dépend que du format de log convenu et du dictionnaire d'état, sans dépendance circulaire.

### ⚠️ Recommandations d'Amélioration & Robustesse
1. **Seuil de Brute-Force Paramétrable** :
   - *Actuel* : La valeur `5` est codée en dur (*hardcoded magic number*).
   - *Recommandation* : Définir une constante de configuration ou passer un paramètre : `THRESHOLD_BRUTE_FORCE = 5`.
2. **Fenêtre Glissante Temporelle** :
   - *Limite actuelle* : Si une IP a 4 échecs le lundi et 1 échec le vendredi sans tentative réussie entre-temps, elle est marquée suspecte alors qu'il ne s'agit pas forcément d'une attaque automatisée.
   - *Recommandation d'évolution* : Associer les timestamps pour n'alerter que si les $N$ échecs se produisent dans un intervalle de temps resserré (ex. 5 échecs en moins de 10 minutes).
3. **Consistance du nommage** :
   - Préférer l'orthographe française correcte `occurrences` (avec deux 'r') ou un nommage standardisé en anglais (`error_counter`, `user_error_counter`).

