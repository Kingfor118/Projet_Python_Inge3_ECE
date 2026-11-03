# 🛡️ Pipeline d'Ingestion & Détection de Menaces sur Logs (SIEM)

 **Projet Python — Majeure Ingénieur 3 (ECE)**  
 Analyse, normalisation, détection d'intrusions (brute force), corrélation avec liste noire et audit par introspection.

---

## 📋 Table des matières

- [Présentation](#-présentation)
- [Fonctionnalités clés](#-fonctionnalités-clés)
- [Architecture & Modules](#-architecture--modules)
- [Arborescence du projet](#-arborescence-du-projet)
- [Données de test (`demo_data`)](#-données-de-test-demodata)
- [Prérequis](#-prérequis)
- [Installation & Utilisation](#-installation--utilisation)
- [Rapports générés (`report/`)](#-rapports-générés-report)

---

## 📖 Présentation

Ce projet implémente un pipeline complet de traitement et d'analyse de journaux de sécurité (logs) inspiré du fonctionnement d'un **SIEM** (*Security Information and Event Management*). 

Il permet d'ingérer de volumineux fichiers de journaux distribués (`auth.log`, `network.log`, `server.log`), d'en extraire les métadonnées et le payload JSON, de normaliser les données à l'aide du *pattern matching*, d'appliquer des règles de sécurité modulaires (détection d'attaques par force brute, comptage d'erreurs, suivi des protocoles) et de produire des rapports d'audit détaillés grâce aux mécanismes d'introspection de Python.

---

## ⚡ Fonctionnalités clés

1. **Ingestion en streaming / mémoire maîtrisée** : Utilisation de générateurs (`yield`, `yield from`) pour parcourir les journaux ligne par ligne sans saturer la mémoire vive.
2. **Parsing structuré** : Découpage des formats de logs hétérogènes et désérialisation sécurisée des payloads au format JSON.
3. **Filtrage et normalisation** :
   - Élimination des lignes invalides ou corrompues.
   - Normalisation typographique (majuscules, suppression des espaces superflus) via le pattern matching (`match ... case`).
4. **Moteur de règles de sécurité dynamique** : Application découplée et extensible de règles au moyen de `*args` et `**kwargs`.
5. **Détection d'attaques par force brute** : Détection automatique des adresses IP réalisant des tentatives de connexion répétées en échec (seuil paramétré à 5 échecs consécutifs).
6. **Analyse ensembliste & Corrélation avec Blacklist** : Comparaison des adresses IP actives avec une liste noire via la théorie des ensembles (union, intersection, différence, différence symétrique).
7. **Rapports d'audit par introspection** :
   - Introspection locale (`locals()`) pour tracer les anomalies au fil de l'eau.
   - Introspection globale (`globals()`) pour synthétiser les indicateurs de compromission (IoC) et les statistiques globales.

---

## 🏗️ Architecture & Modules

Le code source est organisé de manière modulaire au sein du dossier [`src/`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src) :

| Module | Fichier | Rôle principal |
|---|---|---|
| **Module 1 : Ingestion** | [`src/ingestion.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/ingestion.py) | - `lire_logs()` & `lire_all_logs()` : Lecture fainéante (lazy) par itérateurs.<br>- `parse_logs()` : Parsing textuel, extraction JSON et typage des métadonnées.<br>- `extract_blacklist_ips()` : Chargement des IP de liste noire sous forme de `frozenset` immuable. |
| **Module 2 : Transformation** | [`src/transfo.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/transfo.py) | - `filtrage_logs()` : Filtrage des enregistrements `None` ou vides via `filter()`.<br>- `normalize_logs()` : Nettoyage et standardisation des clés et valeurs via `match ... case`. |
| **Module 3 : Agrégation** | [`src/agregation.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/agregation.py) | - `brute_force_detector()` : Détecte les adresses IP ayant $\ge 5$ échecs consécutifs de connexion.<br>- `extract_unique_error_ips()` : Recense les adresses IP associées aux niveaux `ERROR`, `WARNING` et `CRITICAL`.<br>- `occurence()` : Dénombrement des niveaux de criticité et des utilisateurs impliqués.<br>- `occurence_ip_connexion()` : Agrégation des taux de succès/échec, protocoles réseau, ports et codes de statut. |
| **Module 4 : Moteur de règles** | [`src/rules_engine.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/rules_engine.py) | - `apply_security_rules()` : Exécute séquentiellement un ensemble variable de fonctions de règles passées en paramètres et capture l'état local d'exécution. |
| **Module 5 : Introspection** | [`src/introspection.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/introspection.py) | - `introspection_local()` : Extrait l'état à partir des variables locales pour consigner les événements suspects.<br>- `introspection_global()` : Récupère les structures globales, calcule les intersections avec la blacklist et génère les statistiques détaillées. |

Le fichier d'orchestration central est [`main.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/main.py).

---

## 📁 Arborescence du projet

```text
Projet_Python_Inge3_ECE/
├── demo_data/                # Jeux de données et logs fictifs
│   ├── README.txt            # Spécification des données et attaques simulées
│   ├── auth.log              # Logs d'authentification (~15 000 entrées)
│   ├── network.log           # Logs réseau (~12 000 entrées)
│   ├── server.log            # Logs serveur applicatif (~10 000 entrées)
│   └── blacklist.txt         # Adresses IP interdites / malveillantes
├── report/                   # Rapports de sécurité générés lors de l'exécution
│   ├── report_local.txt      # Alertes détaillées sur les anomalies au fil de l'eau
│   └── report_global.txt     # Synthèse statistique globale et analyse blacklist
├── src/                      # Modules Python
│   ├── ingestion.py          # Lecture flux & parsing JSON
│   ├── transfo.py            # Filtrage & normalisation (match/case)
│   ├── agregation.py         # Détection brute-force & métriques
│   ├── rules_engine.py       # Moteur d'application de règles
│   └── introspection.py      # Analyse par introspection & génération des rapports
├── .gitignore                # Règles d'exclusion Git (caches, venv, éditeurs)
├── main.py                   # Script principal (pipeline d'exécution)
└── README.md                 # Documentation du projet
```

---

## 📊 Données de test (`demo_data/`)

Les fichiers présents dans [`demo_data/`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/demo_data) simulent l'activité d'une infrastructure d'entreprise :
- Format type : `YYYY-MM-DDTHH:MM:SS level=<NIVEAU> ip=<IP> user=<UTILISATEUR> payload={...}`
- **Attaques simulées** :
  - Tentatives d'attaque par force brute (ex. 12 échecs consécutifs sur `192.168.1.50`, 10 échecs sur `10.0.0.99`).
  - Corrélation avec les IP blacklistées (`10.0.0.99` et `203.0.113.45`).

---

## 🔧 Prérequis

- **Python 3.10** ou version ultérieure (requis pour la syntaxe de pattern matching structural `match ... case`).
- **Aucune dépendance externe** : le projet repose exclusivement sur la bibliothèque standard Python (`json`, `collections`, `collections.abc`).

---

## 🚀 Installation & Utilisation

1. **Cloner le dépôt :**
   ```bash
   git clone https://github.com/Kingfor118/Projet_Python_Inge3_ECE.git
   cd Projet_Python_Inge3_ECE
   ```

2. **(Optionnel) Créer un environnement virtuel :**
   ```bash
   python -m venv venv
   # Sur Windows PowerShell :
   .\venv\Scripts\Activate.ps1
   # Sur Linux/macOS :
   source venv/bin/activate
   ```

3. **Lancer le pipeline d'analyse :**
   ```bash
   python main.py
   ```

---

## 📑 Rapports générés (`report/`)

À l'issue de l'exécution, deux fichiers de synthèse sont complétés dans le dossier `report/` :

- [`report/report_local.txt`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/report/report_local.txt) :  
  Consigne chaque événement à sévérité élevée (`WARNING`, `ERROR`, `CRITICAL`) ou lié à une adresse IP suspectée de force brute, avec le contexte local de l'exécution et les règles appliquées.
  
- [`report/report_global.txt`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/report/report_global.txt) :  
  Présente une vue d'ensemble macroscopique :
  - Liste des IP suspectes de force brute.
  - Répartition des erreurs par niveau et par utilisateur.
  - Statistiques de connexion (taux d'échec par IP, protocoles et ports les plus sollicités, codes statut).
  - Analyse d'ensemble vis-à-vis de la liste noire (IP actives blacklistées, IP suspectes non encore répertoriées).
