# *args : les fonctions de regles
# **kwargs : les parametres (log, context, seuil...)
def apply_security_rules(*args, **kwargs) -> dict:
    for rule in args:
        rule(**kwargs)

    # locals() sert ensuite au rapport
    return locals()
