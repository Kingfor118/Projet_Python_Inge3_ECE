# 📄 Documentation : `src/introspection.py` (Module 5 : Introspection & Audit de Sécurité)

> **Rôle** : Ce module exploite les capacités réflexives de Python (`locals()`, `globals()`, méta-attributs `__name__`) pour auditer le système de sécurité sans intrusion dans le code métier. Il génère les rapports d'audit persistant au fil de l'eau (`report/report_local.txt`) et la synthèse analytique consolidée (`report/report_global.txt`) enrichie par la théorie des ensembles.

---

## 📋 Sommaire des Fonctions

| Fonction | Signature Complète | Rôle Principal |
|---|---|---|
| [`list_info`](#1-list_info) | `(log: dict) -> str` | Formate les métadonnées et indicateurs clés d'un log sous forme textuelle épurée. |
| [`introspection_local`](#2-introspection_local) | `(local_variables: dict) -> None` | Audite l'exécution locale des règles et consigne les événements anormaux dans `report_local.txt`. |
| [`introspection_global`](#3-introspection_global) | `(var_global: dict) -> None` | Analyse l'état global en fin de flux, corrèle avec la blacklist et consigne le bilan dans `report_global.txt`. |
| [`formate_affichages`](#4-formate_affichages) | `(item: dict \| set \| frozenset) -> str` | Met en forme de manière triée et ordonnée les dictionnaires et ensembles pour les rapports. |

---

## 🔍 Analyse Détaillée des Fonctions

### 1. `list_info`

#### Code Source
```python
def list_info(log: dict) -> str:
    payload = log.get('PAYLOAD') or {}

    champs = {
        'IP': log.get('IP'),
        'User': log.get('USER'),
        'Level': log.get('LEVEL'),
        'Event': payload.get('EVENT'),
        'Protocol': payload.get('PROTOCOL'),
        'Port': payload.get('PORT'),
        'Method': payload.get('METHOD'),
        'Status': payload.get('STATUS'),
    }

    information = ""

    for nom, valeur in champs.items():
        if valeur is not None:
            information += f"{nom}: {valeur}\n"

    return information
```

#### Description Fonctionnelle
Extrait les données pertinentes d'un dictionnaire de log normalisé et de son sous-dictionnaire `PAYLOAD`. Elle filtre automatiquement les champs dont la valeur est absente (`None`) et retourne une chaîne formatée sous forme de liste `Clé: Valeur`.

#### Paramètres
- **`log`** (`dict`) : Dictionnaire de log normalisé.

#### Valeur de Retour
- **`str`** : Bloc textuel vertical ne contenant que les attributs effectivement renseignés.  
  *Exemple :*
  ```text
  IP: 192.168.1.50
  User: ALICE
  Level: ERROR
  Event: LOGIN_FAILED
  Port: 22
  Protocol: TCP
  ```

#### Complexité
- **Temporelle** : $\mathcal{O}(1)$ (nombre fixe de 8 clés inspectées).
- **Spatiale** : $\mathcal{O}(1)$ (chaîne de caractères de quelques dizaines d'octets).

---

### 2. `introspection_local`

#### Code Source
```python
def introspection_local(local_variables: dict):

    details = ""

    function_kwargs = local_variables.get('kwargs')
    applied_rules = local_variables.get('args')
    context = function_kwargs['context']
    log = function_kwargs['log']
    ip_address = log.get('IP')
    log_level = log.get('LEVEL')
    event = log.get('PAYLOAD', {}).get('EVENT')

    log_info = list_info(log)

    if event in ('LOGIN_SUCCESS', 'LOGIN_FAILED'):
        details = f'''
[CONTEXTE]
Echecs de connexion pour cette IP : {context['occurence_brute_force'].get(ip_address, 0)}
IP suspecte de brute force : {'Oui' if ip_address in context['ip_sus_brute_force'] else 'Non'}
'''

    information = f'''
-----------------------------------------------------------------------
[LOG]
{log_info}
[MOTEUR DE REGLES]
nombre de regles appliquees: {len(applied_rules)}
regles appliquees: {[rule.__name__ for rule in applied_rules]}
{details}

'''
    if log_level == 'ERROR' or log_level == 'WARNING' or log_level == 'CRITICAL' or ip_address in context['ip_sus_brute_force']:
        with open("report/report_local.txt", "a") as f:
            f.write(information)
```

#### Description Fonctionnelle
Effectue un audit réflexif en direct lors du passage de chaque log. Elle inspecte le dictionnaire local renvoyé par `apply_security_rules`, en extrait la liste des règles passées en argument, les noms des fonctions via `rule.__name__`, et évalue la sévérité de l'événement.

#### Condition de Déclenchement de l'Alerte (Écriture sur Disque)
Un événement est consigné dans `report/report_local.txt` si et seulement si :
$$\text{log\_level} \in \{\text{'ERROR'}, \text{'WARNING'}, \text{'CRITICAL'}\} \quad \lor \quad \text{ip\_address} \in \text{context}['ip\_sus\_brute\_force']$$
Les logs normaux de type `INFO` provenant d'adresses saines sont ainsi filtrés, évitant de surcharger le rapport local avec des événements bénins.

#### Paramètres
- **`local_variables`** (`dict`) : Instantané de l'espace des noms local produit par `apply_security_rules` via l'instruction `locals()`.

#### Valeur de Retour
- **`None`** : Écriture en mode ajout (`"a"`) dans le fichier `report/report_local.txt`.

#### Algorithme Interne
1. Extraction sécurisée de `function_kwargs` et `applied_rules`.
2. Décomposition de `context`, `log`, `ip_address`, `log_level` et `event`.
3. Formatage de la fiche descriptive du log via `list_info(log)`.
4. Si l'événement est lié à l'authentification (`LOGIN_SUCCESS` ou `LOGIN_FAILED`), enrichissement d'une section `[CONTEXTE]` indiquant le compteur d'échecs consécutifs et le statut de suspicion de l'IP.
5. Introspection dynamique des règles : calcul de `len(applied_rules)` et extraction des noms de fonctions via la compréhension de liste `[rule.__name__ for rule in applied_rules]`.
6. Si la condition de sévérité ou d'IP suspecte est satisfaite, persistance sur disque.

---

### 3. `introspection_global`

#### Code Source
```python
def introspection_global(var_global: dict):
    ip_sus_brute_force = var_global.get('context').get('ip_sus_brute_force')
    occurence_user = var_global.get('context').get('occurence_user')
    occurence_error = var_global.get('context').get('occurence_error')
    unique_ips = var_global.get('context').get('unique_ips')
    echecs_par_ip = var_global.get('context').get('echecs_par_ip')
    success_par_ip = var_global.get('context').get('success_par_ip')
    blacklist_ips = var_global.get('blacklist_ips')
    port = var_global.get('context').get('ports')
    protocol = var_global.get('context').get('protocols')
    status_codes = var_global.get('context').get('status_codes')

    list_ip_string = ""

    for ip in unique_ips:
        if echecs_par_ip[ip] + success_par_ip[ip] > 0: #evite la division par zero
            list_ip_string += f"{ip} (echecs: {echecs_par_ip[ip]}, succes: {success_par_ip[ip]}, pourcentage d'echec: {echecs_par_ip[ip] / (echecs_par_ip[ip] + success_par_ip[ip]) * 100:.2f}%)\n"

    information = f'''
[VARIABLES GLOBALES]
nombre de fichier de log = {len(var_global.get('logs', []))}

-----------------------------------------------------------------------
ip suspecte de brute force: 
{formate_affichages(ip_sus_brute_force)} 
l'occurence d'utilisateur: 
{formate_affichages(dict(occurence_user))}
l'occurence d'erreur: 
{formate_affichages(dict(occurence_error))}
nombre de ip unique: 
{len(unique_ips)}
-----------------------------------------------------------------------

[COMPARAISON DES IP AVEC LA BLACKLIST]
Union des ip actives et blacklist: 
{formate_affichages(unique_ips | blacklist_ips)}
IP blacklistees actives : 
{formate_affichages(unique_ips & blacklist_ips)}
IP actives non blacklistees : 
{formate_affichages(unique_ips - blacklist_ips)}
Difference symetrique : 
{formate_affichages(unique_ips ^ blacklist_ips)}

[AUTRE]
IP suspecte qui n'est pas dans la blacklist 
{formate_affichages(ip_sus_brute_force - blacklist_ips)}
portes d'ip:
{formate_affichages(dict(port))}
Protocoles d'ip:
{formate_affichages(dict(protocol))}
Codes de statut:
{formate_affichages(dict(status_codes))}
[STATISTIQUES DES IP]
{list_ip_string}
-----------------------------------------------------------------------
[FIN DU RAPPORT]

'''
    with open("report/report_global.txt", "a") as f:
        f.write(information)
```

#### Description Fonctionnelle
Synthétise l'ensemble de l'audit de sécurité une fois le flux de journaux totalement consommé. Elle accède aux structures de données globales via le dictionnaire `globals()` de `main.py` et calcule :
1. Les ratios de succès/échec par adresse IP (avec garde contre la division par zéro).
2. Les relations ensemblistes fondamentales entre les IP actives observées et la liste noire.
3. Les adresses suspectes de brute-force constituant des **menaces émergentes** (non encore répertoriées dans la liste noire).
4. La répartition des vecteurs réseau (ports, protocoles, codes HTTP).

#### Algèbre Ensembliste Appliquée à la Sécurité

Le tableau suivant explicite la signification métier de chaque opérateur ensembliste employé :

| Opération Python | Notation Mathématique | Signification en Cybersécurité |
|---|---|---|
| `unique_ips \| blacklist_ips` | $A \cup B$ | **Périmètre complet d'intérêt** : Ensemble de toutes les adresses IP surveillées ou ayant généré des alertes. |
| `unique_ips & blacklist_ips` | $A \cap B$ | **IP Blacklistées Actives (Menace Confirmée)** : Adresses officiellement malveillantes qui ont interagi avec le système. |
| `unique_ips - blacklist_ips` | $A \setminus B$ | **IP Actives Non Blacklistées** : Adresses ayant généré des erreurs mais inconnues de la liste noire (à surveiller). |
| `unique_ips ^ blacklist_ips` | $A \triangle B$ | **Différence Symétrique** : IP actives sans être blacklistées OU IP blacklistées n'ayant pas généré d'alerte. |
| `ip_sus_brute_force - blacklist_ips` | $S \setminus B$ | **Menaces Inédites (0-Day / Nouvelles Détections)** : Attaquants par force brute détectés par le moteur heuristique mais pas encore inscrits dans la blacklist (candidats immédiats pour une mise à ban pare-feu). |

#### Paramètres
- **`var_global`** (`dict`) : Dictionnaire complet de l'espace des noms global (`globals()`) passé depuis `main.py`.

#### Valeur de Retour
- **`None`** : Écriture en mode ajout (`"a"`) dans le fichier `report/report_global.txt`.

---

### 4. `formate_affichages`

#### Code Source
```python
def formate_affichages(item):

    if type(item) is dict:
        sorted_items = sorted(item.items())
        formatted_items = ""

        for key, value in sorted_items:
            formatted_items += f"- {key}: {value}\n"

        return formatted_items

    if type(item) is set:
        sorted_ips = sorted(item)
        formatted_ips = ""

        for ip in sorted_ips:
            formatted_ips += f"- {ip}\n"

        return formatted_ips
```

#### Description Fonctionnelle
Fonction utilitaire assurant une mise en page claire et déterministe pour les rapports textuels. Elle trie les données par ordre alphabétique pour garantir que deux exécutions sur les mêmes logs produisent un rapport au contenu ordonné de manière identique.

#### Paramètres
- **`item`** (`dict | set | frozenset`) : Structure de données à formater.

#### Valeur de Retour
- **`str`** : Chaîne contenant une puce markdown (`- Clé: Valeur\n` ou `- IP\n`) par élément.

---

## 💡 Analyse Senior Dev : Points Forts & Recommandations

### ✅ Points Forts
- **Excellente exploitation de la théorie des ensembles** : Les calculs `|`, `&`, `-`, `^` sont expressifs, idiomatiques en Python et exécutés en langage C sous le capot pour une rapidité maximale.
- **Protection arithmétique** : Présence de la condition `echecs_par_ip[ip] + success_par_ip[ip] > 0` évitant un plantage sur division par zéro (`ZeroDivisionError`).
- **Découplage grâce à l'introspection** : Le module consomme l'état sans nécessiter une multitude de paramètres individuels.

### ⚠️ Recommandations d'Amélioration & Robustesse
1. **Mode d'Ouverture des Fichiers (`"a"` vs `"w"`)** :
   - *Comportement actuel* : `open(..., "a")` ajoute le contenu à la fin du fichier sans jamais le purger. Au bout de plusieurs exécutions, `report_local.txt` et `report_global.txt` grossissent indéfiniment en empilant les anciens rapports.
   - *Recommandation* : Ajouter un horodatage d'exécution en tête de rapport, ou ouvrir en mode `"w"` (écriture avec écrasement) au début d'un run complet, ou générer un nom de fichier horodaté (`report_global_YYYYMMDD_HHMMSS.txt`).
2. **Support des `frozenset` dans `formate_affichages`** :
   - *Bug latent identifié* : La fonction teste `if type(item) is set:`. Or, `blacklist_ips` est un `frozenset` ! Lors de l'opération `ip_sus_brute_force - blacklist_ips`, le résultat est bien un `set`, mais si on passait `blacklist_ips` directement, la fonction ne rentrerait dans aucun des deux `if` et renverrait implicitement `None`.
   - *Correction recommandée* : Remplacer les tests stricts par `isinstance()` :
     ```python
     if isinstance(item, dict):
         ...
     elif isinstance(item, (set, frozenset)):
         ...
     ```
3. **Création Automatique du Répertoire `report/`** :
   - Si le dossier `report/` est supprimé ou absent lors d'un clone vierge, `open("report/...", "a")` lèvera une `FileNotFoundError`. Il est recommandé d'inclure :
     ```python
     import os
     os.makedirs("report", exist_ok=True)
     ```

