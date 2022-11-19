from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.viewsets import ModelViewSet

from account.models import Account


def _key_value_validator(value):
    for permission in value:
        if len({'key', 'value'} - permission.keys()):
            raise ValidationError("Permissions should contain 'key', 'value' fields")


class AccountSerializer(serializers.ModelSerializer):
    name = serializers.CharField(allow_blank=True)
    permissions = serializers.JSONField(validators=[_key_value_validator])

    class Meta:
        model = Account
        fields = ['id', 'name', 'permissions']

    def create(self, validated_data):
        validated_data['permissions'] = [
            {k: permission[k] for k in {'key', 'value'}} for permission in validated_data['permissions']
        ]

        return super().create(validated_data)


class AccountViewSet(ModelViewSet):
    serializer_class = AccountSerializer
    queryset = Account.objects.all()
