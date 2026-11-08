1. Environnement et architecture
6/8

[ ] Créer un environnement virtuel isolé (venv ou Conda).
[ ] Installer les dépendances nécessaires dans l'environnement.
[x] Générer un fichier requirements.txt avec pip freeze (ou environment.yml pour Conda).
[x] Vérifier que toutes les dépendances sont déclarées et réinstallables.
[x] Structurer le projet sous forme de package Python.
[x] Organiser le code en plusieurs modules .py indépendants.
[x] Créer un fichier main.py comme point d'entrée principal.
[x] Réserver les notebooks Jupyter (.ipynb) aux expérimentations et démonstrations graphiques.

2. Module 1 – Ingestion et générateurs mémoire
10/10

[x] Créer un générateur Python utilisant yield pour lire les logs ligne par ligne.
[x] Éviter de charger l'intégralité des fichiers en mémoire.
[x] Créer un sous-générateur utilisant yield from pour parcourir plusieurs fichiers successivement.
[x] Parser chaque ligne de log et la convertir en dictionnaire Python.
[x] Structurer les données avec un horodatage.
[x] Ajouter un niveau de sévérité (INFO, WARNING, ERROR, CRITICAL).
[x] Extraire l'adresse IP source.
[x] Extraire l'identifiant utilisateur.
[x] Prendre en charge un payload JSON ou une chaîne brute.
[ ] Utiliser des tuples pour représenter les métadonnées fixes (IP, Port, Protocole).

3. Module 2 – Pipeline et programmation fonctionnelle
11/11

[x] Utiliser filter() pour filtrer les entrées invalides.
[x] Utiliser des fonctions lambda dans les opérations de filtrage.
[x] Utiliser filter(None, ...) ou des prédicats personnalisés pour supprimer les entrées vides.
[x] Utiliser map() pour normaliser les enregistrements.
[x] Nettoyer les chaînes de caractères.
[x] Uniformiser la casse des données.
[x] Reformater les données avec des f-strings.
[x] Implémenter le Structural Pattern Matching (match-case).
[x] Détecter et router les chaînes brutes.
[x] Détecter et router les dictionnaires (ex. {'level': 'ERROR', 'code': code}).
[x] Détecter et router les tuples de connexion.

4. Module 3 – Agrégation et traitement avancé
10/15

[x] Identifier les adresses IP uniques ayant généré des erreurs avec set.
[x] Représenter les IP blacklistées avec un frozenset.
[x] Calculer l'union des IP blacklistées et des IP actives (|).
[x] Calculer l'intersection des deux ensembles (&).
[x] Calculer la différence entre les deux ensembles (-).
[x] Calculer la différence symétrique entre les deux ensembles (^).
[x] Utiliser defaultdict pour compter les occurrences par catégorie de log.
[x] Utiliser defaultdict pour compter les occurrences par utilisateur.
[x] Développer un algorithme de détection des attaques par force brute.
[x] Détecter X échecs de connexion consécutifs.
[ ] Combiner des boucles while et for dans l'algorithme.
[ ] Utiliser break dans les boucles.
[ ] Utiliser continue dans les boucles.
[ ] Utiliser obligatoirement else associé à une boucle.
[ ] Exploiter else pour valider la réussite complète d'un cycle de détection.

5. Module 4 – Moteur de règles et introspection
9/9

[x] Créer la fonction apply_security_rules(*args, **kwargs).
[x] Permettre de recevoir plusieurs fonctions de sécurité via *args.
[x] Permettre de recevoir des paramètres de configuration via **kwargs.
[x] Manipuler les fonctions comme des objets de première classe.
[x] Passer des fonctions en arguments à d'autres fonctions.
[x] Créer un module d'audit système.
[x] Utiliser globals() pour inspecter les variables globales.
[x] Utiliser locals() pour inspecter les variables locales.
[x] Exporter un rapport d'audit sur les variables présentes dans les portées inspectées.

6. Qualité, robustesse et sécurité
7/7

[x] Respecter les conventions PEP8.
[x] Ajouter des annotations de types (type hints).
[x] Gérer proprement les exceptions.
[x] Vérifier la robustesse face aux fichiers volumineux.
[x] Vérifier que le traitement ne provoque pas de surcharge mémoire.
[x] Vérifier le bon fonctionnement de chaque module indépendamment.
[x] Tester l'intégralité du pipeline.

7. Livrables finaux
8/9

[x] Créer un dépôt Git contenant le projet.
[x] Fournir une arborescence Python organisée en modules.
[x] Ajouter le fichier requirements.txt (ou environment.yml).
[x] Ajouter le fichier main.py exécutable.
[x] Fournir un jeu de données de test.
[x] Permettre à main.py de démontrer l'ensemble du pipeline.
[x] Créer un rapport synthétique au format Jupyter Notebook ou PDF.
[x] Illustrer le fonctionnement des différents modules dans le rapport.
[x] Vérifier que le dépôt permet de réinstaller et d'exécuter le projet sur un environnement vierge.
