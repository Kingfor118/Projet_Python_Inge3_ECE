# 📄 Documentation : Stratégie de Tests Unitaires & d'Intégration (`tests/`)

> **Rôle** : Ce document définit le plan d'assurance qualité (QA) et la stratégie de tests automatisés pour l'ensemble du pipeline SIEM. En tant que système d'ingestion et de détection de menaces, la fiabilité, l'idempotence et l'absence de régression sont des critères critiques.

---

## 📋 Sommaire
1. [Pyramide de Tests & Objectifs de Couverture](#-pyramide-de-tests--objectifs-de-couverture)
2. [Matrice de Test par Module](#-matrice-de-test-par-module)
3. [Exemples de Suites de Tests Unitaires (`pytest`)](#-exemples-de-suites-de-tests-unitaires-pytest)
   - [3.1 Tests du Module Ingestion](#31-tests-du-module-ingestion)
   - [3.2 Tests du Module Transformation](#32-tests-du-module-transformation)
   - [3.3 Tests du Module Agrégation](#33-tests-du-module-agrégation)
   - [3.4 Tests du Moteur de Règles & Introspection](#34-tests-du-moteur-de-règles--introspection)
4. [Test d'Intégration Bout-en-Bout (End-to-End)](#-test-dintégration-bout-en-bout-end-to-end)
5. [Automatisation CI/CD (GitHub Actions)](#-automatisation-cicd-github-actions)

---

## 🔺 Pyramide de Tests & Objectifs de Couverture

```text
       /\
      /  \     Tests E2E / Intégration (Pipeline complet avec fichiers temporaires)
     /----\    
    /      \   Tests d'Agrégation & Règles (Simulation de scénarios d'attaque)
   /--------\  
  /          \ Tests Unitaires Purs (Ingestion, Parsing JSON, Pattern Matching)
 /------------\
```

- **Objectif de couverture de code (Code Coverage)** : $\ge 90\%$ sur l'ensemble du dossier [`src/`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src).
- **Outillage recommandé** : `pytest`, `pytest-cov`, `pytest-mock`.

---

## 📊 Matrice de Test par Module

| Module | Fonction Testée | Cas Nominaux | Cas Limites / Erreurs |
|---|---|---|---|
| **`ingestion`** | `lire_logs` | Parcours complet d'un fichier valide avec bons numéros de ligne. | Fichier vide, caractères UTF-8 spéciaux. |
| **`ingestion`** | `parse_logs` | Ligne nominale complète, payload JSON avec tous les champs. | JSON malformé, absence de la clé `"event"`, labels d'en-tête erronés, ligne tronquée. |
| **`ingestion`** | `extract_blacklist_ips` | Chargement d'IP distinctes dans un `frozenset`. | Lignes vides, espaces en début/fin, fichier inexistant. |
| **`transfo`** | `filtrage_logs` | Conservation des dictionnaires valides. | Élimination stricte des entrées `None` et `{}`. |
| **`transfo`** | `normalize_logs` | Conversion en majuscules des clés et sous-dictionnaires. | Préservation des types entiers (`int`), traitement des tuples avec `None`. |
| **`agregation`** | `brute_force_detector` | 5 échecs consécutifs $\rightarrow$ alerte suspecte. | Moins de 5 échecs, remise à zéro immédiate sur `LOGIN_SUCCESS`. |
| **`agregation`** | `extract_unique_error_ips` | Ajout des IP de logs `ERROR`, `WARNING`, `CRITICAL`. | Ignorance des logs de niveau `INFO` ou `DEBUG`. |
| **`rules_engine`** | `apply_security_rules` | Exécution séquentielle des règles passées en `*args`. | Propagation correcte des `**kwargs`, capture fidèle de `locals()`. |
| **`introspection`**| `formate_affichages` | Formatage ordonné et déterministe (`sorted`). | Dictionnaire vide, ensemble vide. |
| **`introspection`**| `introspection_global` | Calculs d'union, intersection, différence, ratios d'échecs. | IP avec 0 total (division par zéro évitée). |

---

## 🧪 Exemples de Suites de Tests Unitaires (`pytest`)

### 3.1 Tests du Module Ingestion

```python
# tests/test_ingestion.py
import pytest
from src.ingestion import parse_logs, extract_blacklist_ips

def test_parse_logs_nominal():
    raw_tuple = (
        '2026-03-11T10:00:00 level=INFO ip=192.168.1.10 user=admin payload={"event":"LOGIN_SUCCESS","port":443,"protocol":"TCP"}',
        1,
        "dummy.log"
    )
    result = parse_logs(raw_tuple)
    assert result is not None
    assert result["time"] == "2026-03-11 10:00:00"
    assert result["level"] == "INFO"
    assert result["ip"] == "192.168.1.10"
    assert result["user"] == "admin"
    assert result["payload"]["event"] == "LOGIN_SUCCESS"
    assert result["metadata"] == (443, "TCP", None, None)

def test_parse_logs_json_invalide():
    # Payload JSON corrompu (manque accolade fermante)
    raw_tuple = (
        '2026-03-11T10:00:00 level=INFO ip=192.168.1.10 user=admin payload={"event":"LOGIN_SUCCESS"',
        2,
        "dummy.log"
    )
    result = parse_logs(raw_tuple)
    assert result is None  # Doit capturer l'exception et renvoyer None

def test_parse_logs_sans_event():
    # Payload valide en JSON mais dépourvu de la clé obligatoire "event"
    raw_tuple = (
        '2026-03-11T10:00:00 level=INFO ip=192.168.1.10 user=admin payload={"port":80}',
        3,
        "dummy.log"
    )
    result = parse_logs(raw_tuple)
    assert result is None

def test_extract_blacklist_ips(tmp_path):
    # Création d'un fichier blacklist fictif temporaire
    f = tmp_path / "blacklist.txt"
    f.write_text("10.0.0.1\n\n  192.168.1.100  \n10.0.0.1\n", encoding="utf-8")
    
    ips = extract_blacklist_ips(str(f))
    assert isinstance(ips, frozenset)
    assert ips == frozenset({"10.0.0.1", "192.168.1.100"})
```

---

### 3.2 Tests du Module Transformation

```python
# tests/test_transfo.py
from src.transfo import filtrage_logs, normalize_logs

def test_filtrage_logs():
    entrees = [
        {"LEVEL": "INFO"},
        None,
        {},
        {"LEVEL": "ERROR"},
        None
    ]
    resultats = list(filtrage_logs(entrees))
    assert len(resultats) == 2
    assert resultats == [{"LEVEL": "INFO"}, {"LEVEL": "ERROR"}]

def test_normalize_logs_pattern_matching():
    log_brut = {
        "level": "warning",
        "ip": "10.0.0.5",
        "payload": {
            "event": "port_scan",
            "port": 8080,
            "protocol": "tcp"
        },
        "metadata": (8080, "tcp", None)
    }
    normalise = normalize_logs(log_brut)
    
    # Vérification des clés de premier niveau
    assert "LEVEL" in normalise and "IP" in normalise
    assert normalise["LEVEL"] == "WARNING"
    assert normalise["IP"] == "10.0.0.5"
    
    # Vérification du sous-dictionnaire normalisé
    assert normalise["PAYLOAD"]["EVENT"] == "PORT_SCAN"
    assert normalise["PAYLOAD"]["PROTOCOL"] == "TCP"
    assert normalise["PAYLOAD"]["PORT"] == 8080  # Les entiers ne doivent pas être altérés
    
    # Vérification du tuple (None éliminé, texte en majuscule)
    assert normalise["METADATA"] == (8080, "TCP")
```

---

### 3.3 Tests du Module Agrégation

```python
# tests/test_agregation.py
from collections import defaultdict
from src.agregation import brute_force_detector, extract_unique_error_ips

def test_brute_force_detector_detection():
    context = {
        'occurence_brute_force': defaultdict(int),
        'ip_sus_brute_force': set()
    }
    ip_attaquant = "198.51.100.23"
    log_echec = {"IP": ip_attaquant, "PAYLOAD": {"EVENT": "LOGIN_FAILED"}}
    
    # 4 échecs : seuil pas encore atteint
    for _ in range(4):
        brute_force_detector(log_echec, context)
    assert ip_attaquant not in context['ip_sus_brute_force']
    assert context['occurence_brute_force'][ip_attaquant] == 4
    
    # 5e échec : déclenchement immédiat de la détection
    brute_force_detector(log_echec, context)
    assert ip_attaquant in context['ip_sus_brute_force']
    assert context['occurence_brute_force'][ip_attaquant] == 5

def test_brute_force_reset_on_success():
    context = {
        'occurence_brute_force': defaultdict(int),
        'ip_sus_brute_force': set()
    }
    ip = "192.168.1.20"
    log_echec = {"IP": ip, "PAYLOAD": {"EVENT": "LOGIN_FAILED"}}
    log_succes = {"IP": ip, "PAYLOAD": {"EVENT": "LOGIN_SUCCESS"}}
    
    # 3 échecs consécutifs
    for _ in range(3):
        brute_force_detector(log_echec, context)
    assert context['occurence_brute_force'][ip] == 3
    
    # 1 succès -> réinitialisation à zéro
    brute_force_detector(log_succes, context)
    assert context['occurence_brute_force'][ip] == 0
    assert ip not in context['ip_sus_brute_force']
```

---

### 3.4 Tests du Moteur de Règles & Introspection

```python
# tests/test_rules_engine.py
from src.rules_engine import apply_security_rules

def test_apply_security_rules_locals_capture():
    # Définition de fausses règles espionnes
    calls = []
    def fake_rule_1(**kwargs):
        calls.append(("rule_1", kwargs.get("token")))
        
    def fake_rule_2(**kwargs):
        calls.append(("rule_2", kwargs.get("token")))
        
    captured = apply_security_rules(fake_rule_1, fake_rule_2, token="ECE_TEST")
    
    # Vérification que toutes les règles ont été exécutées
    assert len(calls) == 2
    assert calls[0] == ("rule_1", "ECE_TEST")
    assert calls[1] == ("rule_2", "ECE_TEST")
    
    # Vérification de l'introspection retournée
    assert "args" in captured and "kwargs" in captured
    assert [r.__name__ for r in captured["args"]] == ["fake_rule_1", "fake_rule_2"]
    assert captured["kwargs"]["token"] == "ECE_TEST"
```

---

## 🔄 Test d'Intégration Bout-en-Bout (End-to-End)

Ce test simule l'intégralité du pipeline sur un jeu de données réduit créé à la volée dans un répertoire temporaire :

```python
# tests/test_integration_e2e.py
from collections import defaultdict
from src.ingestion import lire_all_logs, parse_logs, extract_blacklist_ips
from src.transfo import filtrage_logs, normalize_logs
from src.rules_engine import apply_security_rules
from src.agregation import brute_force_detector, occurence, extract_unique_error_ips, occurence_ip_connexion

def test_pipeline_complet(tmp_path):
    # 1. Écriture d'un log et d'une blacklist de test
    log_file = tmp_path / "test_auth.log"
    log_content = (
        '2026-03-11T09:00:00 level=INFO ip=10.0.0.1 user=alice payload={"event":"LOGIN_SUCCESS","port":443}\n'
        '2026-03-11T09:01:00 level=WARNING ip=10.0.0.2 user=bob payload={"event":"LOGIN_FAILED","port":22}\n'
        'LIGNE_CORROMPUE_INVALIDE\n'
    )
    log_file.write_text(log_content, encoding="utf-8")
    
    # 2. Contexte
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
    
    # 3. Exécution de la chaîne
    raw = lire_all_logs([str(log_file)])
    parsed = map(parse_logs, raw)
    filtered = filtrage_logs(parsed)
    normalized = map(normalize_logs, filtered)
    
    for log in normalized:
        apply_security_rules(
            brute_force_detector,
            occurence,
            extract_unique_error_ips,
            occurence_ip_connexion,
            log=log,
            context=context
        )
        
    # 4. Assertions métier
    assert context['unique_ips'] == {"10.0.0.2"}
    assert context['success_par_ip']["10.0.0.1"] == 1
    assert context['echecs_par_ip']["10.0.0.2"] == 1
    assert context['occurence_error']["WARNING"] == 1
    assert context['occurence_user']["BOB"] == 1
```

---

## 🚀 Automatisation CI/CD (GitHub Actions)

Pour garantir la pérennité du code sur le dépôt GitHub [`Projet_Python_Inge3_ECE`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE), voici le workflow d'intégration continue à déposer dans `.github/workflows/python-tests.yml` :

```yaml
name: Tests SIEM & Intégration Continue

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
    - uses: actions/checkout@v4
    
    - name: Configuration de Python ${{ matrix.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}
        
    - name: Installation des dépendances de test
      run: |
        python -m pip install --upgrade pip
        pip install pytest pytest-cov flake8
        
    - name: Linting du code (PEP 8)
      run: |
        flake8 src/ main.py --count --max-line-length=127 --statistics
        
    - name: Exécution des tests avec couverture
      run: |
        pytest tests/ --cov=src --cov-report=term-missing
```

