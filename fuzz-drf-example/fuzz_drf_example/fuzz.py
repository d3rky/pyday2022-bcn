import atheris
import os
import sys


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fuzz_drf_example.settings')


with atheris.instrument_imports():
    import django

    django.setup()


def fuzz(data):
    """
    Write here you fuzzing code
    """
    pass


atheris.Setup(sys.argv, fuzz)
atheris.Fuzz()
