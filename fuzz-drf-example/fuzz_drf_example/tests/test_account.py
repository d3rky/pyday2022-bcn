import pytest

import json

from rest_framework import status
from rest_framework.reverse import reverse

from account.models import Account


@pytest.mark.django_db
def test_create_account(client):
    account = {
        "name": "Pavel",
        "permissions": [{"key": "account", "value": True}]
    }

    response = client.post(reverse('account-list'), data=account, content_type='application/json')

    assert response.status_code == status.HTTP_201_CREATED, response.content


@pytest.mark.django_db
def test_create_account_miss_required_permissions(client):
    account = {
        "name": "Pavel",
        "permissions": [{"key": "account"}]
    }

    response = client.post(reverse('account-list'), data=account, content_type='application/json')

    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.content


@pytest.mark.django_db
def test_create_account_miss_additional_permission_fields(client):
    account = {
        "name": "Pavel",
        "permissions": [{"key": "account", "value": True, "test": "test"}]
    }

    response = client.post(reverse('account-list'), data=account, content_type='application/json')
    account_id = response.json()['id']
    account = Account.objects.get(pk=account_id)

    assert account.permissions == [{"key": "account", "value": True}]
