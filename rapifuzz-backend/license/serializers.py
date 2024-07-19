from rest_framework import serializers
from .models import *

"""
This files contails all the serializer for all the models.
"""
class LicenseDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = LicenseData
        fields = "__all__"

"""
This files contails all the serializer for all the models.
"""
class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = "__all__"