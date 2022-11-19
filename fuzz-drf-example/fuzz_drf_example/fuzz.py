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

    from rest_framework.test import APIClient
    from rest_framework.reverse import reverse


def run_fuzzing(data):
    client = APIClient()

    dp = atheris.FuzzedDataProvider(data)

    name_length_probability = dp.ConsumeBool()
    name_min_length, name_max_length = (1, 10) if name_length_probability else (12, 48)
    name_length = dp.ConsumeIntInRange(name_min_length, name_max_length)
    name = dp.ConsumeUnicodeNoSurrogates(name_length)
    name = name.replace('\x00', 'a')

    permissions_length = dp.ConsumeIntInRange(0, 5)
    permissions = []
    for _ in range(permissions_length):
        modify_permissions = dp.ConsumeBool()
        if modify_permissions:
            permission = dp.ConsumeUnicodeNoSurrogates(10)
            permission = permission.replace('\u0000', '.')
        else:
            key = dp.ConsumeUnicodeNoSurrogates(10)
            key = key.replace('\u0000', '.')
            value = dp.ConsumeUnicodeNoSurrogates(10)
            value = value.replace('\u0000', '.')
            permission = {
                'key': key,
                'value': value,
            }
        permissions.append(permission)

    account_data = {
        'name': name,
        'permissions': permissions,
    }

    response = client.post(reverse('account-list'), data=account_data, format='json')

    if response.status_code == 500:
        print(account_data)
        print(response.content)


# Setup and run Atheris fuzzing
atheris.Setup(sys.argv, run_fuzzing)
atheris.Fuzz()
