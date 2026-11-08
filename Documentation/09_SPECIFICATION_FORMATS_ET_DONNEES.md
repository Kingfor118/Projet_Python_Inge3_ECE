# 📄 Documentation : Spécification des Formats et Modèle de Données

> **Rôle** : Ce document constitue la référence formelle des spécifications de données du projet SIEM. Il définit la grammaire syntaxique des logs entrants, le schéma JSON des payloads, la taxonomie des événements de sécurité, ainsi que la structure des rapports générés.

---

## 📋 Sommaire
1. [Grammaire EBNF des Fichiers de Logs Entrants](#-grammaire-ebnf-des-fichiers-de-logs-entrants)
2. [Spécification du Schéma JSON (`payload`)](#-spécification-du-schéma-json-payload)
3. [Taxonomie des Niveaux de Sévérité & Événements](#-taxonomie-des-niveaux-de-sévérité--événements)
4. [Format de la Liste Noire (`blacklist.txt`)](#-format-de-la-liste-noire-blacklisttxt)
5. [Spécification des Rapports de Sortie (`report/`)](#-spécification-des-rapports-de-sortie-report)
   - [5.1 Rapport d'Audit Local (`report_local.txt`)](#51-rapport-daudit-local-report_localtxt)
   - [5.2 Rapport de Synthèse Globale (`report_global.txt`)](#52-rapport-de-synthèse-globale-report_globaltxt)

---

## 📜 Grammaire EBNF des Fichiers de Logs Entrants

Les fichiers de logs traités (`auth.log`, `network.log`, `server.log`) respectent une grammaire régulière structurée combinant des paires clé-valeur et un objet JSON final :

```ebnf
LogLine        ::= Timestamp " " LevelField " " IpField " " UserField " " PayloadField
Timestamp      ::= Date "T" Time
Date           ::= Digit{4} "-" Digit{2} "-" Digit{2}
Time           ::= Digit{2} ":" Digit{2} ":" Digit{2}

LevelField     ::= "level=" ("DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL")
IpField        ::= "ip=" Ipv4Address
UserField      ::= "user=" UserName
PayloadField   ::= "payload=" JsonObject

Ipv4Address    ::= Octet "." Octet "." Octet "." Octet
Octet          ::= Digit{1,3}
UserName       ::= (Letter | Digit | "_" | "-"){1,64}
JsonObject     ::= "{" JsonMembers? "}"
```

### Exemple Conforme
```text
2026-03-11T14:32:01 level=ERROR ip=192.168.1.50 user=admin payload={"event":"LOGIN_FAILED","port":22,"protocol":"SSH"}
```

---

## 📦 Spécification du Schéma JSON (`payload`)

Le champ `payload` contient un objet JSON sérialisé.

| Champ | Type | Présence | Description | Exemples |
|---|---|---|---|---|
| `event` | `string` | **Obligatoire** | Identifiant de l'action de sécurité. La fonction `parse_logs` lève une exception s'il est manquant. | `"LOGIN_SUCCESS"`, `"LOGIN_FAILED"`, `"ACCESS_DENIED"` |
| `port` | `integer` | Optionnel | Numéro du port réseau de destination (1 à 65535). | `22`, `80`, `443`, `8080` |
| `protocol` | `string` | Optionnel | Protocole de couche transport ou application. | `"TCP"`, `"UDP"`, `"SSH"`, `"HTTP"`, `"HTTPS"` |
| `status` | `integer` \| `string` | Optionnel | Code de statut HTTP ou code d'erreur interne. | `200`, `401`, `403`, `500` |
| `method` | `string` | Optionnel | Verbe HTTP pour les requêtes web. | `"GET"`, `"POST"`, `"PUT"`, `"DELETE"` |

---

## 🏷️ Taxonomie des Niveaux de Sévérité & Événements

### 1. Niveaux de Sévérité (`LEVEL`)
- **`DEBUG`** : Diagnostic détaillé pour le développement (ignoré des alertes).
- **`INFO`** : Activité nominale du système (ex. ouverture de session autorisée).
- **`WARNING`** : Condition inhabituelle mais non critique (ex. tentative d'accès à une ressource restreinte). *Consigné dans le rapport local*.
- **`ERROR`** : Défaillance ou incident de sécurité (ex. échec d'authentification). *Consigné dans le rapport local*.
- **`CRITICAL`** : Anomalie grave (ex. déni de service, corruption ou brute-force avéré). *Consigné dans le rapport local*.

### 2. Événements Majeurs de Sécurité (`EVENT`)
- **`LOGIN_SUCCESS`** : Authentification réussie. Déclenche la réinitialisation du compteur de brute-force pour l'IP associée (`context['occurence_brute_force'][ip] = 0`).
- **`LOGIN_FAILED`** : Authentification infructueuse. Incrémente le compteur de brute-force de l'IP. Dès que le seuil de 5 est franchi, l'IP passe au statut suspect.
- **`PORT_SCAN` / `TRAFFIC`** : Événements réseau alimentant les compteurs de ports et protocoles.

---

## 🚫 Format de la Liste Noire (`blacklist.txt`)

Le fichier de référence `blacklist.txt` contient les adresses IPv4 réputées hostiles :
- **Règles de formatage** : Une seule adresse IPv4 valide par ligne.
- **Lignes blanches** : Les lignes vides ou composées d'espaces sont ignorées lors du chargement.
- **Stockage en mémoire** : `frozenset[str]` garantissant un accès en $\mathcal{O}(1)$ et l'immutabilité des références.

---

## 📄 Spécification des Rapports de Sortie (`report/`)

### 5.1 Rapport d'Audit Local (`report_local.txt`)
Chaque événement suspect ou anomalie donne lieu à l'insertion d'un bloc délimité :

```text
-----------------------------------------------------------------------
[LOG]
IP: 192.168.1.50
User: ROOT
Level: ERROR
Event: LOGIN_FAILED
Port: 22
Protocol: SSH

[MOTEUR DE REGLES]
nombre de regles appliquees: 4
regles appliquees: ['brute_force_detector', 'occurence', 'extract_unique_error_ips', 'occurence_ip_connexion']

[CONTEXTE]
Echecs de connexion pour cette IP : 5
IP suspecte de brute force : Oui
```

### 5.2 Rapport de Synthèse Globale (`report_global.txt`)
Généré en clôture du traitement, il récapitule l'ensemble des indicateurs de compromission :

```text
[VARIABLES GLOBALES]
nombre de fichier de log = 3

-----------------------------------------------------------------------
ip suspecte de brute force: 
- 10.0.0.99
- 192.168.1.50

l'occurence d'utilisateur: 
- ADMIN: 12
- ROOT: 45

l'occurence d'erreur: 
- CRITICAL: 15
- ERROR: 128
- WARNING: 34

nombre de ip unique: 
42
-----------------------------------------------------------------------

[COMPARAISON DES IP AVEC LA BLACKLIST]
Union des ip actives et blacklist: 
- 10.0.0.99
- 192.168.1.50
- 203.0.113.45

IP blacklistees actives : 
- 10.0.0.99

IP actives non blacklistees : 
- 192.168.1.50

Difference symetrique : 
- 192.168.1.50
- 203.0.113.45

[AUTRE]
IP suspecte qui n'est pas dans la blacklist 
- 192.168.1.50

portes d'ip:
- 22: 450
- 80: 1200
- 443: 8900

Protocoles d'ip:
- SSH: 450
- TCP: 10100

Codes de statut:
- 200: 9500
- 401: 58
- 404: 120

[STATISTIQUES DES IP]
192.168.1.50 (echecs: 12, succes: 0, pourcentage d'echec: 100.00%)
10.0.0.99 (echecs: 10, succes: 1, pourcentage d'echec: 90.91%)
-----------------------------------------------------------------------
[FIN DU RAPPORT]
```

