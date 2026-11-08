# 📄 Documentation : `src/rules_engine.py` (Module 4 : Moteur de Règles)

> **Rôle** : Ce module fournit le moteur d'exécution générique pour l'évaluation des règles de sécurité. Il implémente le patron de conception **Dispatcher / Strategy** et permet de découpler entièrement l'orchestrateur central de la liste concrète des règles appliquées. Il fait également office de passerelle d'introspection en capturant dynamiquement l'environnement local d'exécution.

---

## 📋 Sommaire des Fonctions

| Fonction | Signature Complète | Rôle Principal |
|---|---|---|
| [`apply_security_rules`](#1-apply_security_rules) | `(*args: Callable, **kwargs: Any) -> dict` | Exécute séquentiellement un ensemble variable de règles et retourne la portée locale `locals()`. |

---

## 🔍 Analyse Détaillée de la Fonction

### 1. `apply_security_rules`

#### Code Source
```python
def apply_security_rules(*args, **kwargs) -> dict:
    for rule in args:
        rule(**kwargs)
        
    return locals()
```

#### Description Fonctionnelle
`apply_security_rules` est un exécuteur d'ordre supérieur (*higher-order executor*) :
1. Elle accepte une liste variable de fonctions de sécurité en arguments positionnels (`*args`).
2. Elle accepte des arguments nommés arbitraires (`**kwargs`) destinés à être injectés dans chaque règle (typiquement `log=line_log, context=context`).
3. Elle itère sur chaque fonction passée et l'invoque en lui transmettant l'ensemble des arguments nommés déballés (`rule(**kwargs)`).
4. Elle retourne le dictionnaire de l'espace des noms local (`locals()`), qui contient l'instantané des arguments d'appel et de l'état d'exécution.

#### Paramètres
- **`*args`** (`tuple[Callable, ...]`) : Tuple de fonctions de rappel (*callables*) représentant les règles de sécurité à appliquer (ex. `brute_force_detector`, `occurence`, `extract_unique_error_ips`, `occurence_ip_connexion`).
- **`**kwargs`** (`dict[str, Any]`) : Dictionnaire des paramètres nommés requis par les règles. Dans le pipeline SIEM :
  - `log` : Le log normalisé en cours de traitement.
  - `context` : Le dictionnaire partagé d'état global.

#### Valeur de Retour
- **`dict`** : Le dictionnaire des variables locales au moment du `return`.  
  Ce dictionnaire possède la structure suivante :
  ```python
  {
      'args': (
          <function brute_force_detector at 0x...>,
          <function occurence at 0x...>,
          <function extract_unique_error_ips at 0x...>,
          <function occurence_ip_connexion at 0x...>
      ),
      'kwargs': {
          'log': {'TIME': '...', 'LEVEL': '...', 'IP': '...', ...},
          'context': {'occurence_brute_force': ..., ...}
      },
      'rule': <function occurence_ip_connexion at 0x...>  # dernière valeur de la boucle
  }
  ```

#### Rôle Clé dans le Mécanisme d'Introspection
Dans `main.py`, le retour de cette fonction est stocké dans `var_locals` puis transmis à `introspection_local(var_locals)`.  
Cela permet à la fonction d'introspection d'extraire dynamiquement :
- La liste des règles effectivement appliquées via `[rule.__name__ for rule in var_locals['args']]`.
- Le nombre total de règles appliquées via `len(var_locals['args'])`.
- Les données métier sous-jacentes via `var_locals['kwargs']['log']` et `var_locals['kwargs']['context']`.

Ce mécanisme évite d'avoir à coder en dur la liste des règles dans le rapporteur ou à les transmettre en double.

#### Complexités
- **Temporelle** : $\mathcal{O}(R \cdot C_{rule})$ où $R$ est le nombre de règles dans `args` et $C_{rule}$ la complexité moyenne d'exécution d'une règle (ici $\mathcal{O}(1)$). La fonction s'exécute donc en $\mathcal{O}(R)$.
- **Spatiale** : $\mathcal{O}(R + K)$ où $K$ est le nombre de clés dans `kwargs`, alloué pour le dictionnaire de retour `locals()`.

---

## 💡 Analyse Senior Dev : Points Forts & Recommandations

### ✅ Points Forts
- **Extensibilité Ouverte/Fermée (Principe OCP - SOLID)** : Le moteur est "ouvert à l'extension mais fermé à la modification". Pour ajouter une 5e règle de sécurité (par exemple un détecteur d'injection SQL ou de scan de ports), il suffit de créer la fonction et de la passer dans l'appel `apply_security_rules(...)` dans `main.py` sans toucher une seule ligne de `src/rules_engine.py`.
- **Concision extrême** : 5 lignes élégantes réalisant à la fois le dispatching et la préparation de l'audit réflexif.

### ⚠️ Recommandations d'Amélioration & Robustesse
1. **Isolation des Pannes (Fault Tolerance)** :
   - *Risque* : Si l'une des règles lève une exception inattendue, la boucle `for rule in args:` s'interrompt brutalement et les règles suivantes ne sont pas évaluées pour ce log.
   - *Solution recommandée* :
     ```python
     def apply_security_rules(*args, **kwargs) -> dict:
         errors = []
         for rule in args:
             try:
                 rule(**kwargs)
             except Exception as exc:
                 errors.append((rule.__name__, str(exc)))
         return locals()
     ```
2. **Annotation de Types (PEP 484)** :
   - Préciser les types pour guider les outils d'analyse statique (Mypy) :
     ```python
     from collections.abc import Callable
     from typing import Any

     def apply_security_rules(*args: Callable[..., None], **kwargs: Any) -> dict[str, Any]:
         ...
     ```

