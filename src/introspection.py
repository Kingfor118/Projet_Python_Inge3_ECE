import os


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

def introspection_local(local_variables: dict, dossier_rapport: str):

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
        chemin_fichier = os.path.join(dossier_rapport, "report_local.txt")
        with open(chemin_fichier, "a", encoding="utf-8") as f:
            f.write(information)




def introspection_global(var_global: dict, dossier_rapport: str):
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
    formats = var_global.get('context').get('formats')


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
Formats des logs (routage match-case):
{formate_affichages(dict(formats))}
[STATISTIQUES DES IP]
{list_ip_string}
-----------------------------------------------------------------------
[FIN DU RAPPORT]

'''
    chemin_fichier = os.path.join(dossier_rapport, "report_global.txt")
    with open(chemin_fichier, "a", encoding="utf-8") as f:
        f.write(information)


# Fonction qui formate les affichages des dictionnaires et des ensembles pour le rapport global
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