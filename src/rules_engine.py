# fonction principale du moteur de regles
# *args = toutes les fonctions de regles qu'on lui donne (ca arrive sous forme de tuple)
# **kwargs = tous les parametres avec un nom (log=..., context=..., seuil_brute_force=...), ca arrive sous forme de dictionnaire
def apply_security_rules(*args, **kwargs) -> dict:
    # on appelle chaque regle une par une
    # rule(**kwargs) ca revient a faire rule(log=..., context=..., seuil_brute_force=...)
    for rule in args:
        rule(**kwargs)

    # locals() renvoie les variables locales de la fonction (args, kwargs, rule)
    # on les renvoie pour que introspection_local puisse faire le rapport
    return locals()
