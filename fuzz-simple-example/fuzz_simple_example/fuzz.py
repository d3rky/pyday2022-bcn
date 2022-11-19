import atheris
import sys


def check_permission(permission: str) -> bool:
    if permission == 'fuzzing_is_available':
        return False
    elif permission == 'fuzzing_is_not_available':
        return True
    elif permission == 'check_permission':
        return True

    return True


def do_calc(permission):
    is_available = check_permission(permission)

    if is_available:
        return 2 + 2
    else:
        return -1


def run_fuzzing(data):
    """
    Put here your fuzzing code
    """
