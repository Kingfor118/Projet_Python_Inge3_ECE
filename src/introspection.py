def introspection_local(local_variables):
    function_kwargs = local_variables.get('kwargs')
    applied_rules = local_variables.get('args')
    context = function_kwargs['context']
    log = function_kwargs['log']

    ip_address = log.get('IP')
    username = log.get('USER')
    log_level = log.get('LEVEL')
    event = log.get('PAYLOAD', {}).get('event')


    information = f'''
    -----------------------------------------------------------------------
    [LOG]
    erreur: {log_level}
    ip: {ip_address}
    user: {username}
    event: {event}


    [MOTEUR DE REGLES]
    nombre de regles appliquees: {len(applied_rules)}
    regles appliquees: {[rule.__name__ for rule in applied_rules]}

    [CONTEXTE]

    Echecs de connexion pour cette IP : {len(context['occurence_brute_force'].get(ip_address, []))}
    IP suspecte de brute force : {'Oui' if ip_address in context['ip_sus_brute_force'] else 'Non'}
    IP enregistree dans unique_ips : {'Oui' if ip_address in context['unique_ips'] else 'Non'}

    '''
    if log_level == 'ERROR' or log_level == 'WARNING' or ip_address in context['ip_sus_brute_force']:
        with open("report/report.txt", "a") as f:
            f.write(information)



def introspection_global(var_global):
    ip_sus_brute_force = var_global.get('context').get('ip_sus_brute_force')
    occurence_user = var_global.get('context').get('occurence_user')
    occurence_error = var_global.get('context').get('occurence_error')
    unique_ips = var_global.get('context').get('unique_ips')

    information = f'''
    [VARIABLES GLOBALES]
    nombre de fichier de log = {len(var_global.get('logs', []))}

    ip suspecte de brute force: {ip_sus_brute_force} 
    l'occurence d'utilisateur: {dict(occurence_user)}
    l'occurence d'erreur: {dict(occurence_error)}
    nombre de ip unique: {len(unique_ips)}
    -----------------------------------------------------------------------
    [FIN DU RAPPORT]

    '''
    with open("report/report.txt", "a") as f:
        f.write(information)
    