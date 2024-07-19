from django.core.management.base import BaseCommand as CreatesuperuserCommand
from uuid import uuid4
from django.core.exceptions import ValidationError
from user_auth.serializers import PermissionSerializer
from django.conf import settings
from user_auth.models import User
from django.db import transaction
import string,random

ADMIN_PERMISSIONS = [
                {
                    "module_id":1,
                    "edit":True,
                    "add":True,
                    "view":True,
                    "pname":""
                },
                {
                    "module_id":2,
                    "edit":True,
                    "add":True,
                    "view":True
                },
                {
                    "module_id":3,
                    "view":True,
                    "rpdf":True,
                    "rexcel":True
                }
            ]


def secret_key(size=16, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


class Command(CreatesuperuserCommand):
    def handle(self, *args, **options):
        super_user = {}
        super_user['username'] = settings.DJANGO_SUPERUSER_USERNAME
        super_user['name'] = settings.DJANGO_SUPERUSER_NAME
        super_user['password'] = settings.DJANGO_SUPERUSER_PASSWORD
        super_user['email_verified'] = settings.DJANGO_SUPERUSER_EMAIL_VERIFIED
        super_user['email'] = settings.DJANGO_SUPERUSER_EMAIL
        super_user['is_active'] = True
        super_user['is_staff'] = True
        super_user['secret_key'] = secret_key()
        super_user['role'] = settings.DJANGO_SUPERUSER_ROLE
        super_user['uu_id'] = str(uuid4()).replace('-','') # add uuid to the new user 

        # Custom email validation
        if "email" not in super_user:
            raise ValidationError('Email must be provided')
        if "password" not in super_user:
            raise ValidationError('Password must be provided')
        if "name" not in super_user:
            raise ValidationError('Email must be provided')
        with transaction.atomic():
            existing_user = User.objects.filter(username=super_user['username']).first()
            if existing_user:
                return "SuperAdmin already exists"
            user = User.objects.create_superuser(**super_user)
            for permission in ADMIN_PERMISSIONS:
                serializer = PermissionSerializer(data=permission)
                if serializer.is_valid():
                    serializer.save(user_ID=user)
        return "SuperAdmin created successfully"
