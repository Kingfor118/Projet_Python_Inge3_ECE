def apply_security_rules(*args, **kwargs) -> dict:
    for rule in args:
        rule(**kwargs)
        
    return locals()