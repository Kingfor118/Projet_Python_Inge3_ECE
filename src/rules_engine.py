def apply_security_rules(*args, **kwargs):
    for rule in args:
        rule(**kwargs)
        
    return locals()