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
    name = dp.ConsumeUnicodeNoSurrogates(10)
    # replace nulls
    name = name.replace('\x00', 'a')

    permissions_length = dp.ConsumeIntInRange(0, 5)
    permissions = []
    for _ in range(permissions_length):
        # in 50% of cases let's replace the permission with the string
        modify_permission = dp.ConsumeBool()
        if modify_permission:
            permission = dp.ConsumeUnicodeNoSurrogates(10)
            # do not forget about the Postgres bug
            permission = permission.replace('\u0000', '.')
        else:
            # same code as before
            key = dp.ConsumeUnicodeNoSurrogates(10)
            value = dp.ConsumeUnicodeNoSurrogates(10)
            # w/a for postgres bug, it doesn't allow unicode dot in the JSONB fields
            key = key.replace('\u0000', '.')
            value = value.replace('\u0000', '.')
            permission = {
                'key': key,
                'value': value,
            }
        # add generated permissions
        permissions.add(permission)

    account_data = {
        'name': name,
        'permissions': permissions,
    }

    try:
        response = client.post(reverse('account-list'), data=account_data, format='json')
        if response.status_code == 500:
            print(f"500 returned for account_data {account_data} and answer is {response.content}")
    except Exception as e:
        print(f"Exception catched: {e}. With account_data {account_data}")


# Setup and run Atheris fuzzing
atheris.Setup(sys.argv, run_fuzzing)
atheris.Fuzz()
