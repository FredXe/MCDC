import sys

def mcdc():
    import mcdc

def dcbot():
    import dcbot


if len(sys.argv) == 2:
    arg = sys.argv[1]
    entry = getattr(sys.modules[__name__], arg, None)
    if entry is not None and entry and callable(entry):
        entry()
    else:
        print('Unknown argument {}'.format(arg))
