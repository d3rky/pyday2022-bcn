from django.db import models


def _default_permissions():
    return [{'key': 'account', 'value': True}]


class Account(models.Model):
    name = models.CharField('Name', max_length=10, null=True)
    permissions = models.JSONField('Permissions', default=_default_permissions)
