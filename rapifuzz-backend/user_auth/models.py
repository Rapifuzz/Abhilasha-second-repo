"""
Models related to User and User permissions.
"""

from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractUser


class UserManager(BaseUserManager):

    def _create_user(self, email,password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError("User must have an email")
        if not password:
            raise ValueError("User must have a password")
        if "name" not in extra_fields:
            raise ValueError("User must have a name")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    

    def create_user(self, email,password=None,**extra_fields):
        """
        Method for creating a new normal user with role=ROLE_USER
        """
        extra_fields['role'] = "ROLE_USER"
        extra_fields['is_staff'] = False
        extra_fields['is_superuser'] = False
        return self._create_user(email, password, **extra_fields)
        

    def create_superuser(self, email,password=None, **extra_fields):
        """
        Method for creating a Administrator with role=ROLE_ADMIN
        """
        extra_fields['role'] = "ROLE_ADMIN"
        extra_fields['is_superuser'] = True
        return self._create_user(email,password, **extra_fields)

class User(AbstractUser):

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ["name"]
    first_name = None
    last_name = None

    id = models.AutoField(primary_key=True,unique=True)
    username = models.CharField(max_length=200,null=True,blank=True)
    email = models.EmailField(('email address'), unique=True ,error_messages={
            'unique': ("A user with that username already exists."),
        }) # changes email to unique and blank to false
    name = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    role = models.CharField(max_length=20,null=True,blank=True)
    email_verified =models.BooleanField(default=False)
    uu_id = models.UUIDField(db_index = True,default = None,editable = False,unique=True,null=True,blank=True)
    secret_key = models.CharField(max_length=255,null=True,blank=True,default=None)
    is_confirmed_sk  = models.BooleanField(default=False,null=True,blank=True)
    is_smtp_enabled = models.BooleanField(default=False,null=True,blank=True)
    
    
    class Meta:
        db_table = "fuzzer_user" #giving custom name to the table

    objects = UserManager()
    def __str__(self):                                                       
        return self.email


class Permission(models.Model):
    """
    Permissions table regarding modules
    such as edit,view and reports.
    """
    user_ID = models.ForeignKey(User,on_delete=models.CASCADE, blank=True, null=True)
    module_id = models.IntegerField(null=True,blank=True)
    view = models.BooleanField(default=False,null=True,blank=True)
    add = models.BooleanField(default=False,null=True,blank=True)
    edit = models.BooleanField(default=False,null=True,blank=True)
    delete = models.BooleanField(default=False,null=True,blank=True)
    pname = models.TextField(null=True,blank=True)
    rexcel = models.BooleanField(default=False,null=True,blank=True)
    rpdf = models.BooleanField(default=False,null=True,blank=True)

    class Meta:
        db_table = "fuzzer_permission"

    def __str__(self):
        """Returns a string representation of permissions"""
        return "Permission"


class UserRawData(models.Model):
    """
    Table for the data saved without verification of otp given by user.
    """

    id = models.AutoField(primary_key=True,unique=True)
    expire_time = models.DateTimeField(auto_now_add=True,blank=True,null=True)
    otp = models.CharField(max_length=4,blank=True, null=False,default=None)
    pedit = models.BooleanField(default=False,null=True,blank=True)
    pname = models.CharField(max_length=255,blank=True, null=False,)
    rexcel = models.BooleanField(default=False,null=True,blank=True)
    rview = models.BooleanField(default=False,null=True,blank=True)
    rpdf = models.BooleanField(default=False,null=True,blank=True)
    sadd = models.BooleanField(default=False,null=True,blank=True)
    sedit = models.BooleanField(default=False,null=True,blank=True)
    sview = models.BooleanField(default=False,null=True,blank=True)
    user_email = models.EmailField(max_length=255,blank=True,null=True)
    user_is_active = models.BooleanField(default=False,null=True,blank=True)
    user_name = models.CharField(max_length=255)
    user_password = models.CharField(max_length=255)
    wrong_attempt = models.IntegerField(blank=True, null=True)