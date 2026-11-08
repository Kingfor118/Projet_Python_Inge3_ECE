# 📚 Documentation Technique Complète du Projet SIEM (Ingé 3 ECE)

Bienvenue dans la documentation technique exhaustive du projet **Pipeline d'Ingestion & Détection de Menaces sur Logs (SIEM)**.  
Ce dossier regroupe l'analyse détaillée de chaque module du projet, le protocole de tests, les guides d'exécution et de profiling, ainsi que le rapport interactif sous forme de Jupyter Notebook.

---

## 🗺️ Sommaire de la Documentation

### 🔬 Architecture & Modules Applicatifs
| Document | Fichier Cible | Description |
|---|---|---|
| [**01. Orchestration du Pipeline**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/01_PIPELINE_ORCHESTRATION_MAIN.md) | [`main.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/main.py) | Orchestration centrale, état partagé (`context`), flux de traitement par générateurs et déclenchement des audits. |
| [**02. Module Ingestion**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/02_MODULE_INGESTION.md) | [`src/ingestion.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/ingestion.py) | Ingestion streaming (évaluation paresseuse), découpage textuel, désérialisation JSON et chargement de la blacklist. |
| [**03. Module Transformation**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/03_MODULE_TRANSFORMATION.md) | [`src/transfo.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/transfo.py) | Filtrage paresseux des entrées corrompues et normalisation structurelle via *Pattern Matching* (`match...case`). |
| [**04. Module Agrégation**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/04_MODULE_AGREGATION.md) | [`src/agregation.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/agregation.py) | Règles de détection d'intrusions (Brute Force stateful), métriques de criticité, statistiques protocolaires et réseaux. |
| [**05. Module Moteur de Règles**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/05_MODULE_MOTEUR_DE_REGLES.md) | [`src/rules_engine.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/rules_engine.py) | Dispatcher dynamique découplé (`*args`, `**kwargs`) et capture de la portée locale (`locals()`). |
| [**06. Module Introspection**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/06_MODULE_INTROSPECTION.md) | [`src/introspection.py`](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/src/introspection.py) | Audit dynamique (`locals()`, `globals()`), algèbre ensembliste sur les IP (union, intersection, différence) et génération des rapports. |

### 🛠️ Ingénierie Logicielle, Qualité & Démonstration
| Document | Rôle & Contenu |
|---|---|
| [**07. Stratégie de Tests (`tests/`)**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/07_STRATEGIE_DE_TESTS.md) | Pyramide de tests, suites unitaires sous `pytest`, tests d'intégration bout-en-bout et pipeline CI/CD GitHub Actions. |
| [**08. Guide d'Exécution & Profiling**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/08_GUIDE_EXECUTION_ET_PROFILING.md) | Modes d'exécution, scripts de profiling mémoire (`tracemalloc`), CPU (`cProfile`) et résolution des incidents. |
| [**09. Spécification des Formats**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/09_SPECIFICATION_FORMATS_ET_DONNEES.md) | Grammaire formelle EBNF des logs, schéma JSON des payloads, taxonomie des sévérités et format des rapports. |
| [**10. Rapport Synthétique & Démo (`.ipynb`)**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/RAPPORT_SYNTHETIQUE_ET_DEMO.ipynb) | Notebook Jupyter interactif démontrant pas à pas chaque module avec graphiques des indicateurs de sécurité. |
| [**11. Checklist de Validation Projet**](file:///c:/Users/bapti/Code/GitHub/Projet_Python_Inge3_ECE/Documentation/checklist.md) | Matrice de conformité officielle du barème de notation (Ingé 3 ECE). |

---

## 🏗️ Architecture Globale et Flux de Données

```mermaid
flowchart TD
    A["Fichiers sources (auth.log, network.log, server.log)"] -->|Streaming (yield)| B["Module Ingestion: lire_all_logs()"]
    B -->|Tuples bruts (ligne, n°, fichier)| C["Module Ingestion: parse_logs()"]
    C -->|Dictionnaires ou None| D["Module Transformation: filtrage_logs()"]
    D -->|Logs valides uniquement| E["Module Transformation: normalize_logs()"]
    
    BL["Fichier blacklist.txt"] -->|frozenset| F["extract_blacklist_ips()"]
    
    E -->|Log normalisé unitaire| G["Boucle d'orchestration (main.py)"]
    G -->|log, context, règles| H["Module Rules Engine: apply_security_rules()"]
    
    subgraph "Moteur de Règles & Agrégation"
        H --> R1["brute_force_detector()"]
        H --> R2["occurence()"]
        H --> R3["extract_unique_error_ips()"]
        H --> R4["occurence_ip_connexion()"]
    end
    
    H -->|Capture portée locale via locals()| I["Module Introspection: introspection_local()"]
    I -->|Filtrage erreurs & alertes brute-force| J[("report/report_local.txt")]
    
    G -->|Fin du flux / globals()| K["Module Introspection: introspection_global()"]
    F -.->|Corrélation ensembliste| K
    K -->|Rapport d'audit global consolidé| L[("report/report_global.txt")]
```
