import atheris
import os
import sys


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fuzz_drf_example.settings')

# instrumentation of the imports, it will automatically instrument everything, including
# your account application
with atheris.instrument_imports():
    import django
    # since you are running fuzz.py out of Django, first you need to configure it
    django.setup()


def run_fuzzing(data):
    """
    Write here you fuzzing code
    """
    pass


# Setup and run Atheris fuzzing
atheris.Setup(sys.argv, run_fuzzing)
atheris.Fuzz()
