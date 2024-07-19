from .models import *
from rest_framework import serializers
from uuid import uuid4
from fuzzer.models import Project
from rest_framework import status
from django.db import transaction
from django.core.validators import RegexValidator
import logging
from django.contrib.auth.hashers import make_password,check_password
from fuzzer.base.base import check_valid_password


logger = logging.getLogger("api_fuzzer_server_logger")
logger.propagate = False

DEFAULT_PERMISSIONS = {
                "projects":{
                    "edit":False,
                    "pname":""
                },
                "scans":{
                    "edit":False,
                    "add":False,
                    "view":False
                },
                "reports":{
                    "view":False,
                    "rpdf":False,
                    "rexcel":False
                }
            }


def split_pids(string_value):
    """
    Splits the comma separated pids into a list
    """
    try:
        pids = string_value.split(',')
        if len(pids) == 1 and (pids[0] == '' or pids[0] == ""):
            return []
        return pids
    except ValueError as e:
        logger.info(f"Failed to split pids {e}")
        return []


def prepare_permission_data(data):
    """
    This method prepares the data needed to be saved in permission
    table .
    Permission Matrix.
    
    module_id  view  add  edit  delete  pname  rexcel  rpdf  user_id
    1          1     1    1     0              1       1     1
    2          1     1    1     0       None   1       1     1
    3          1     1    1     0       None   1       1     1

    """    
    permissions_list = []
    permissions_list.append(add_module_id(data['projects'],1))
    permissions_list.append(add_module_id(data['scans'],2))
    permissions_list.append(add_module_id(data['reports'],3))
    return permissions_list

def find_permissions_representation(data):
    """
    This method prepares the data needed to be send in the user permission 
    representation .
    Permission Matrix...
    """
    permissions = {}
    for permission in data:
        permission = dict(permission)
        if permission['module_id'] == 1:
            permission.pop('module_id', None)
            permission.pop('user_ID', None)
            permission.pop('id', None)
            permissions['projects'] = permission
        elif permission['module_id'] == 2:
            permission.pop('module_id', None)
            permission.pop('user_ID', None)
            permission.pop('id', None)
            permissions['scans'] = permission  
        elif permission['module_id'] == 3:
            permission.pop('module_id', None)
            permission.pop('user_ID', None)
            permission.pop('id', None)
            permissions['reports'] = permission      
    return permissions


def add_module_id(data,module_id):
    """
    This method adds the module_id to the permissions matrix 
    module_id  module
    1          Projects
    2          Scans
    3          Reports


    """    
    if module_id == 1:
        projects_list = split_pids(data['pname'])
        for i in projects_list:
            if Project.objects.filter(pid=i).count() == 0:
                logger.info(f"permissions matrix not added  as the given project id {i} does not exist")
                raise serializers.ValidationError("PID does not exists")
            else:
                data['view'] = 1
    data['module_id'] = module_id
    return data



class PermissionSerializer(serializers.ModelSerializer):
    """
    Permissions serializer
    """

    class Meta:
        model = Permission
        fields = "__all__"    


class UserSerializer(serializers.ModelSerializer):
    """
    User Serializer
    """
    name_regex = "^[a-zA-Z]([\\s](?![\\s])|[a-zA-Z]){1,32}[a-zA-Z]$"
    name_validator = RegexValidator(regex = name_regex, message = "The name should be having a minimum of 3 and maximum of 32 characters")

    PASSWORD_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*.()\\s])[A-Za-z\\d!@#$%^&*.()][A-Za-z\\d\\s!@#$%^&*.()]{6,48}[A-Za-z\\d!@#$%^&*.()]$" 
    password_validator = RegexValidator(regex = PASSWORD_REGEX, message = "The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
    password = serializers.JSONField(required=True, validators = [password_validator,])
    
    email = serializers.EmailField(required=True)
    name = serializers.CharField(required=True,
                                 max_length=32, 
                                 min_length=3,
                                 validators = [name_validator,]
                                #  error_messages = [serializers.ValidationError("Name is required"),
                                #                    serializers.ValidationError("Maximum allowed length is 30 characters"),
                                #                    serializers.ValidationError("User name must be of length greater than or equal to 3 characters")
                                #                    ]
                                )
    class Meta:
        model = User
        fields = ['name',"password",'last_login', 'email','uu_id','is_active']

    
    def get_permissions(self,data):
        return prepare_permission_data(data['permissions'])
    
    def validate_email(self,email):
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email already exists")
        return email
    
    def validate(self, data):

        # need to uncomment this line after creating smtp user api in backend.
        #  by passing the authentication
        # user = User.objects.get(email = self.context['request'].user)
        # if user.role != "ROLE_ADMIN":
        #     raise PermissionDenied("permission denied for user")
        data["uu_id"] = str(uuid4()).replace('-','') # add uuid to the new user 
        data['name'] = data['name'].lower() # user name is always in lowercase
        data['is_staff'] = True
        data['email_verified'] = True
        data['role'] = "ROLE_USER"
        # if not check_valid_password(data['password']): # For password validation
        #     raise serializers.ValidationError("The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
        return data
    
    
    def to_representation(self, instance):
        """
        In built serializer method which creates the representation of
        the queryset object.
        """
        representation = super().to_representation(instance)
        representation.pop('password', None)# Exclude the 'password' field from the serialized data
        return representation
    
    
    def create(self, validated_data):
        """
        Create or update the user details in the database.
        """
        # try:
        if "permissions" in self.context['request'].data:
            permissions = prepare_permission_data(self.context['request'].data['permissions'])
        else:
            permissions = prepare_permission_data(DEFAULT_PERMISSIONS)     
    
        with transaction.atomic():    
            if validated_data['role'] == "ROLE_ADMIN": # Condition for creating admin role
                user = User.objects.create_superuser(**validated_data)
                for permission in permissions:
                    Permission.objects.create(user_ID = user, **permission)
                return user

        with transaction.atomic():   
            user = User.objects.create_user(**validated_data)
            for permission in permissions:
                serializer = PermissionSerializer(data=permission)
                
                if serializer.is_valid():
                    serializer.save(user_ID=user)
                else:
                    logger.info(f"Permissions error {serializer.errors}")
                    raise serializers.ValidationError("Invalid permissions" , code = status.HTTP_400_BAD_REQUEST)    
            return user       


class EditUserSerializer(serializers.ModelSerializer):
    name_regex = "^[a-zA-Z]([\\s](?![\\s])|[a-zA-Z]){1,32}[a-zA-Z]$"
    name_validator = RegexValidator(regex = name_regex, message = "The name should be having a minimum of 3 and maximum of 32 characters")

    PASSWORD_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*.()\\s])[A-Za-z\\d!@#$%^&*.()][A-Za-z\\d\\s!@#$%^&*.()]{6,48}[A-Za-z\\d!@#$%^&*.()]$" 
    password_validator = RegexValidator(regex = PASSWORD_REGEX, message = "The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
    
    password = serializers.JSONField(required=False, validators = [password_validator,])
    
    email = serializers.EmailField(required=False)
    name = serializers.CharField(required=False,
                                 max_length=32, 
                                 min_length=3,
                                 validators = [name_validator,]
                                )
    class Meta:
        model = User
        fields = ['name', 'username', 'last_login', 'email','uu_id','is_active','password']


    def check_required_fields(self,data):
        """
        This method can initially get the data from frontend &
        we add a key into permission_data as name 'operation_'
        if during updation of data we can restrict email updation & 
        rest of details will be uudated except email .

        .. code-block:: python

            if 'permissions' not in data:
                return {"msg": "persmissions keyword is missing"}
            if 'password' not in data:
                return {"msg": "password keyword is missing"}
            if 'is_active' not in data:
                return {"msg": "is_active keyword is missing"}
            if 'name' not in data:
                return {"msg": "name keyword is missing"}
            return None

        .. note::This method is deprecated.    
        """
        if 'permissions' not in data:
            raise serializers.ValidationError({"msg": "persmissions keyword is missing"})
        if 'password' not in data:
            raise serializers.ValidationError({"msg": "password keyword is missing"})
        if 'is_active' not in data:
            raise serializers.ValidationError({"msg": "is_active keyword is missing"})
        if 'name' not in data:
            raise serializers.ValidationError({"msg": "name keyword is missing"})
        return None    
    
    def validate_email(self,email):
        pk = self.context.get('request').parser_context.get('kwargs').get('pk')
        if email.lower() != User.objects.filter(id=pk).values()[0]['email']:
            logger.info(f"Email can not be updated {email}")
            raise serializers.ValidationError("Email can not be updated")
        return email
    
    def validate_password(self, password):
        # if check_valid_password(password): # For password validation
        password = make_password(password)
        # else:
        #     raise serializers.ValidationError("The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
        return password
    
    # def validate_role(self,role):
    #     if role ==" ROLE_ADMIN":
    #         raise serializers.ValidationError("Admin can not be updated")
    #     return role
        

    def validate(self, data):

        pk = self.context.get('request').parser_context.get('kwargs').get('pk')
        # data['name'] = data['name'].lower() # user name is always in lowercase
        data['is_staff'] = True
        data['email_verified'] = True
        # Admin permissions can not be changed 
        if User.objects.get(id = pk).role == "ROLE_ADMIN":
            logger.info("Admin permissions can not be updated")
            raise serializers.ValidationError("Admin can not be updated")  
        return data

    
    def to_representation(self, instance):
        """
        In built serializer method which creates the representation of
        the queryset object.
        """
        representation = super().to_representation(instance)
        if instance.role == "ROLE_ADMIN":
            raise serializers.ValidationError("Admin details can't be accessed")
        permissions = Permission.objects.filter(user_ID = instance.id)
        permissions = PermissionSerializer(permissions,many=True).data
        permissions_representation = find_permissions_representation(permissions)
        representation.pop('password', None)# Exclude the 'password' field from the serialized data
        representation['permissions'] = permissions_representation
        return representation
     
        
    def update(self,instance,validated_data):
        """
        This method is to update the resource details in the database
        """ 
        if "permissions" in self.context['request'].data:
            permissions = prepare_permission_data(self.context['request'].data['permissions'])
        else:
            permissions = prepare_permission_data(DEFAULT_PERMISSIONS)    
        permission_ids = Permission.objects.filter(user_ID = instance.id)  
        user = User.objects.get(email = self.context['request'].user)
        if user.role == "ROLE_ADMIN":
            for permission,permission_id in zip(permissions, permission_ids):
                serializer = PermissionSerializer(permission_id,data = permission)
                if serializer.is_valid():
                    serializer.save()
                else:
                    raise serializers.ValidationError(serializer.errors)    
        return super().update(instance,validated_data)



class UserVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRawData
        fields = "__all__"

    def validate_email(self,email):
        if UserRawData.objects.filter(user_email=email).exists():
            raise serializers.ValidationError("Email already exists")
        return email


class VerifyUserSerializer(serializers.ModelSerializer):


    PASSWORD_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*.()\\s])[A-Za-z\\d!@#$%^&*.()][A-Za-z\\d\\s!@#$%^&*.()]{6,48}[A-Za-z\\d!@#$%^&*.()]$" 
    password_validator = RegexValidator(regex = PASSWORD_REGEX, message = "The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
    password = serializers.JSONField(required=False, validators = [password_validator,])
    class Meta:
        model = User
        fields = "__all__"

    def validate(self, data):
        """This serializer if verify the user details         """
        data["uu_id"] = str(uuid4()).replace('-','') # add uuid to the new user 
        data['name'] = data['name'].lower() # user name is always in lowercase
        data['is_staff'] = True
        data['email_verified'] = True
        data['role'] = "ROLE_USER"

        # if not check_valid_password(data['password']): # For password validation
            # raise serializers.ValidationError("The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
        return data


class ProfileUpdateSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(required=False)
    name_regex = "^[a-zA-Z]([\\s](?![\\s])|[a-zA-Z]){1,32}[a-zA-Z]$"
    name_validator = RegexValidator(regex = name_regex, message = "The name should be having a minimum of 3 and maximum of 32 characters")
    name = serializers.CharField(required=False,
                                 max_length=32, 
                                 min_length=3,
                                 validators = [name_validator,]
                                )
    
    PASSWORD_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*.()\\s])[A-Za-z\\d!@#$%^&*.()][A-Za-z\\d\\s!@#$%^&*.()]{6,48}[A-Za-z\\d!@#$%^&*.()]$" 
    password_validator = RegexValidator(regex = PASSWORD_REGEX, message = "The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")

    password = serializers.JSONField(required=False, validators = [password_validator,])
    class Meta:
        model = User
        fields = ['password', 'name', 'email', 'old_password']



    def validate_password(self,password): 
        # if check_valid_password(password):  # For password validation
        password = make_password(password)
        # else:
            # raise serializers.ValidationError("The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
        return password
    
    def validate(self, data):
        
        if 'password' in data and 'old_password' not in data:
            raise serializers.ValidationError("Old password is required")
        if 'old_password' in data and 'password' not in data :
            raise serializers.ValidationError("Password is required")
        return data

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            encoded_password = instance.password
            old_password = validated_data.get('old_password')
            if 'bcrypt_sha256' not in encoded_password:
                encoded_password = "%s$%s" % ('bcrypt_sha256', encoded_password)
            check = check_password(old_password, encoded_password)
            if not check:
                raise serializers.ValidationError("Old password is incorrect")
        return super().update(instance, validated_data)
