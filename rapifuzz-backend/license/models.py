from django.db import models

class LicenseData(models.Model):
    id = models.AutoField(primary_key=True)
    User_Id = models.IntegerField(null=False)
    license_key = models.CharField(max_length=256,null=False)
    email = models.CharField(max_length=255,null=False)
    Status = models.BooleanField(default=False)
    Created_At = models.DateTimeField(auto_now_add=True)
    Updated_At = models.DateTimeField(auto_now=True)
    expiry_time = models.DateTimeField(null=True)

    class Meta:
        unique_together = ('User_Id','license_key')

    def __str__(self):
        return self.expiry_time

class File(models.Model):
    User_Id = models.IntegerField(null=False)
    file = models.FileField(blank=False, null=False)
    def __str__(self):
        return self.file.name
