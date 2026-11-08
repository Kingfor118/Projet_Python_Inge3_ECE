import os
import sys

from src.transfo import recuperer_payload


# resume d'un log pour le rapport, sans les valeurs vides
def list_info(log: dict) -> str:
    payload = recuperer_payload(log)

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


# rapport d'un log, a partir du locals() du moteur de regles
def introspection_local(local_variables: dict, dossier_rapport: str) -> None:
    kwargs = local_variables['kwargs']
    regles = local_variables['args']
    context = kwargs['context']
    log = kwargs['log']
    ip = log.get('IP')

    # on garde seulement les alertes et les ip suspectes
    alerte = log.get('LEVEL') in ('ERROR', 'WARNING', 'CRITICAL')
    if not alerte and ip not in context['ip_sus_brute_force']:
        return

    details = ""
    if recuperer_payload(log).get('EVENT') in ('LOGIN_SUCCESS', 'LOGIN_FAILED'):
        suspecte = 'Oui' if ip in context['ip_sus_brute_force'] else 'Non'
        details = f'''
[CONTEXTE]
Echecs de connexion pour cette IP : {context['occurence_brute_force'].get(ip, 0)}
IP suspecte de brute force : {suspecte}
'''

    information = f'''
-----------------------------------------------------------------------
[LOG]
{list_info(log)}
[MOTEUR DE REGLES]
nombre de regles appliquees: {len(regles)}
regles appliquees: {[regle.__name__ for regle in regles]}
{details}

'''
    chemin = os.path.join(dossier_rapport, "report_local.txt")
    with open(chemin, "a", encoding="utf-8") as f:
        f.write(information)


# pourcentage d'echec de login des ip avec des erreurs
def stats_ip(context: dict) -> str:
    texte = ""
    for ip in sorted(context['unique_ips']):
        echecs = context['echecs_par_ip'][ip]
        succes = context['success_par_ip'][ip]
        if echecs + succes > 0:
            pourcentage = echecs / (echecs + succes) * 100
            texte += (
                f"{ip} (echecs: {echecs}, succes: {succes}, "
                f"pourcentage d'echec: {pourcentage:.2f}%)\n"
            )
    return texte


# rapport final, a partir du globals() de main.py
def introspection_global(var_global: dict, dossier_rapport: str) -> None:
    context = var_global['context']
    blacklist = var_global['blacklist_ips']
    actives = context['ips_actives']
    suspectes = context['ip_sus_brute_force']

    information = f'''
[VARIABLES GLOBALES]
nombre de fichier de log = {len(var_global['logs'])}

-----------------------------------------------------------------------
ip suspecte de brute force:
{formate_affichages(suspectes)}
alertes par utilisateur:
{formate_affichages(dict(context['occurence_user']))}
alertes par niveau:
{formate_affichages(dict(context['occurence_error']))}
nombre d'ip actives:
{len(actives)}
nombre d'ip avec des erreurs:
{len(context['unique_ips'])}
-----------------------------------------------------------------------

[COMPARAISON DES IP AVEC LA BLACKLIST]
Union des ip actives et blacklist:
{formate_affichages(actives | blacklist)}
IP blacklistees actives :
{formate_affichages(actives & blacklist)}
IP actives non blacklistees :
{formate_affichages(actives - blacklist)}
Difference symetrique :
{formate_affichages(actives ^ blacklist)}

[AUTRE]
IP suspecte qui n'est pas dans la blacklist
{formate_affichages(suspectes - blacklist)}
Ports:
{formate_affichages(dict(context['ports']))}
Protocoles:
{formate_affichages(dict(context['protocols']))}
Codes de statut:
{formate_affichages(dict(context['status_codes']))}
Formats des logs (match-case):
{formate_affichages(dict(context['formats']))}
[STATISTIQUES DES IP]
{stats_ip(context)}

'''
    chemin = os.path.join(dossier_rapport, "report_global.txt")
    with open(chemin, "a", encoding="utf-8") as f:
        f.write(information)


# une ligne par element, triee
def formate_affichages(item: dict | set | frozenset) -> str:
    if isinstance(item, dict):
        # les nombres d'abord, puis les textes
        tri = sorted(item.items(), key=lambda paire: (isinstance(paire[0], str), paire[0]))
        lignes = [f"- {cle}: {valeur}" for cle, valeur in tri]
    else:
        lignes = [f"- {element}" for element in sorted(item)]

    if not lignes:
        return "- aucun\n"
    return "\n".join(lignes) + "\n"


# nom, type et taille de chaque variable
def audit_variable(variables: dict, titre: str) -> str:
    texte = f"[AUDIT {titre}]\n"

    for nom in sorted(variables):
        if nom.startswith("__"):
            continue
        valeur = variables[nom]
        texte += f"- {nom} : {type(valeur).__name__}, {sys.getsizeof(valeur)} octets\n"

    return texte


# ajoute l'audit de locals() et globals() au rapport final
def introspection_audit(
    locales_variables: dict, globales_variables: dict, dossier_rapport: str
) -> None:
    texte = audit_variable(locales_variables, "VARIABLES LOCALES (locals)")
    texte += "\n"
    texte += audit_variable(globales_variables, "VARIABLES GLOBALES (globals)")
    texte += "\n-----------------------------------------------------------------------\n"
    texte += "[FIN DU RAPPORT]\n"

    chemin = os.path.join(dossier_rapport, "report_global.txt")
    with open(chemin, "a", encoding="utf-8") as f:
        f.write(texte)
