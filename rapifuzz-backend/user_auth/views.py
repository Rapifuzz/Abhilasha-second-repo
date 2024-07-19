"""
Views regarding user creation and updation.
"""
from rest_framework import status
from rest_framework.response import Response
from .models import User,UserRawData
from .serializers import UserSerializer,EditUserSerializer,PermissionSerializer,split_pids,UserVerificationSerializer,VerifyUserSerializer,ProfileUpdateSerializer
from rest_framework.permissions import IsAuthenticated
import logging,string,random
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView,UpdateAPIView,RetrieveUpdateAPIView,ListAPIView
from django.contrib.auth.hashers import make_password
import random,datetime,time
from rest_framework.decorators import api_view
from django.core.mail import EmailMessage
from django.core.mail.backends.smtp import EmailBackend
from django.http import HttpResponse
from fuzzer.components.customlog import AESCipher
from fuzzer.models import SMTP,BlacklistedDomains
from fuzzer.components.helper import base64_encode,base64
from uuid import uuid4




logger = logging.getLogger("api_fuzzer_server_logger")
logger.propagate = False

def secret_key(size=32, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


class CreateUser(CreateAPIView):
    """
    This class view is for creating a new user.

    For creating a new user you need to
    send the data in the json format just like

    .. code-block:: json

        {
            "email":"sam@mail.com",
            "name":"Sammy",
            "password":"sam123"
        }


    **Parameters**

    .. code-block:: json

        {
        "in": requestbody
        "name": email
        "type": str
        "required": true
        "description": user email.

        "name": name
        "type": str
        "required": true
        "description": user name.

        "in": requestbody
        "name": password
        "type": str
        "required": true
        "description": user password.
        }


    **Returns**

        status_code : 201 CREATED
        
        .. code-block:: json

            {
            "id": 6,
            "last_login": null,
            "is_superuser": false,
            "is_staff": true,
            "is_active": true,
            "date_joined": ,
            "username": null,
            "email": "raj.sandip2962@gmail.com",
            "name": "sandeep kr2",
            "password": "Bcrypt password",
            "role": null,
            "email_verified": true,
            "groups": [],
            "user_permissions": []
            }
    """
    # permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    

class UserRetrieveUpdateView(RetrieveUpdateAPIView):
    """
    For updating the user details.

    This class view updates the User details
    in the user table.
    """
    # permission_classes = [IsAuthenticated]
    lookup_field = 'pk'
    lookup_url_kwarg = 'pk'
    serializer_class = EditUserSerializer
    queryset = User.objects.all()
    


class ResetPassword(APIView):
    """
    This API View is reseting the user password
    in the user table.

    The password gets changed if the user wants to 
    change the old password.

    .. code-block:: python

        User.objects.filter(email=email).update(password=make_password(password))
    """

    def put(self, request):
        data = request.data
        email = data['email']
        password = data['password']
        User.objects.filter(email=email).update(password=make_password(password))
        return Response({"message":"Password updated"},status=status.HTTP_200_OK)

class UserListAPIView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    queryset = User.objects.filter(role="ROLE_USER")

class PermissionsView(CreateAPIView):
    serializer_class = PermissionSerializer


class UserVerificationView(APIView):
    """
    This API View is for User Verification, and sending the otp to mail and save the data to the raw table where otp saved. 
    """

    def post(self,request):
        """
        This method is for post the data required.
        """
        permission_data = request.data.get('permissions')
        otp = random.randint(1111,9999)
        try:
                
            data = {
                "user_name":request.data.get('user_name'),
                "user_password":request.data.get('user_password'),
                "user_email":request.data.get('user_email'),
                "user_is_active":request.data.get('user_is_active'),
                "pedit":permission_data['projects']['edit'],
                "pname":permission_data['projects']['pname'],
                "rexcel":permission_data['reports']['rexcel'],
                "rview":permission_data['reports']['view'],
                "sadd":permission_data['scans']['add'],
                "sedit":permission_data['scans']['edit'],
                "sview":permission_data['scans']['view'],
                "otp": otp,
                "expire_time":datetime.datetime.now(),
                "wrong_attempt": 0,
            }
            serializer = UserVerificationSerializer(data=data)
            if serializer.is_valid():
                serializer.validate_email(request.data.get('user_email'))
                serializer.save()
                self.send_otp(request.data)
                logger.info("Data save in Raw User Table sucessfully")
                return Response(request.data, status=status.HTTP_201_CREATED)
            logger.info("Email already exists")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(str(e))
            return HttpResponse(str(e), status=status.HTTP_400_BAD_REQUEST)


    def send_otp(self,smtp):
        """
        This method is for sending the otp to mail given by the user.
        """
        try:
            obj = AESCipher()
            to_email = smtp["user_email"]
            email = base64.b64encode(bytes(to_email,'utf-8'))
            encoded_email = email.decode('utf-8')           
            smtp_data = SMTP.objects.get(id=1)
            password = obj.decrypt(smtp_data.password).decode('utf8')
            backend = EmailBackend(host=smtp_data.host, port=smtp_data.port, username=smtp_data.username,password=password, fail_silently=False)
            subject = "EMAIL VERIFICATION"
            otp = UserRawData.objects.filter(user_email=smtp['user_email']).values()[0]['otp']
            domain = BlacklistedDomains.objects.filter(description="Dfront").values('host')[0]['host']
            # scheme = self.request.scheme
            # https is hardcoded and approved by vc
            msg = f"Hi {smtp['user_name']},\n"\
                "This email id sent for verification of you RAPIFUZZ account.\n"\
                f"Please go to this link and verify your account: https://{domain}/account/verification?email={encoded_email}\n"\
                f"Please find you OTP below: {otp}\n"\
                "Kindly note the OTP is valid for 15 minutes from the reception time of this email,\n"\
                "If it has expired kindly use the 'Refresh OTP' button in the verification page to generate new OTP which will be sent to your mail again.\n"\
                "Regards,\n"\
                "RAPIFUZZ Team"
            email = EmailMessage(subject=subject, body=msg, from_email= smtp_data.username, to = [to_email], connection=backend)
            email.send()
            logger.info("Email sent successfully to %s", to_email)
            return HttpResponse({"msg":"Email sent successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(str(e))
            return HttpResponse({"msg":"Otp send failed."}, status=status.HTTP_400_BAD_REQUEST)



class VerifyUserView(APIView): 
    """
    This View  is verify the details of a user and otp as well and then send the data to the user table succesfully.
    """

    def post(self,request):
        try:
            data = request.data
            email = data['user_email']
            otp = data['otp']
            decoded_email = base64.b64decode(email)
            email = decoded_email.decode('utf-8')
            saved_otp = UserRawData.objects.filter(user_email=email).values('otp')[0]['otp']
            user_data = UserRawData.objects.filter(user_email=email).values()[0]
            wrong_attempts = user_data['wrong_attempt']
            if int(saved_otp) == otp and  wrong_attempts < 3:
                user = {}
                user['is_active']: user_data['user_is_active']
                user['email_verified'] = True
                user['name'] = user_data['user_name']
                user['role'] = "ROLE_USER"
                user['password']= user_data['user_password']
                user['email'] = user_data['user_email']
                user['permissions'] = {"projects":{
                                                "edit":user_data['pedit'],
                                                "pname":user_data['pname']},
                                        "scans":{
                                                "edit":user_data['sedit'],
                                                "add":user_data['sadd'],
                                                "view":user_data['sview']},
                                        "reports":{
                                                "view":user_data['rview'],
                                                "rpdf":user_data['rpdf'],
                                                "rexcel":user_data['rexcel']}
                                        }
                serializer = VerifyUserSerializer(data=user)
                if serializer.is_valid():
                    serializer.save()
                    UserRawData.objects.filter(user_email=email).delete()
                else:
                    print(serializer.errors)             
            else:
                if wrong_attempts < 3:
                    wrong_attempts += 1
                    UserRawData.objects.filter(user_email = email).update(wrong_attempt=wrong_attempts)
                    logger.info(f"Invalid OTP. {3-wrong_attempts} attempts remaining.")
                    return HttpResponse(f"Invalid OTP. {3-wrong_attempts} attempts remaining.", status=status.HTTP_400_BAD_REQUEST)
                else:
                    logger.info("Maximum attempts reached. Access denied.Please send otp again.")
                    return HttpResponse({"msg":"Maximum attempts reached. Access denied.Please send otp again."}, status=status.HTTP_400_BAD_REQUEST)
                    
            logger.info("User created successfully.")
            return HttpResponse({"msg":"User created successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(str(e))
            return HttpResponse({"msg":"User creation Failed."}, status=status.HTTP_400_BAD_REQUEST)

class ResendOtp(APIView):
    """
    This view is used to resend otp to the user again through the mail.
    
    """ 

    def post(self,request):
        try:
            data = request.data
            email = data['user_email']
            decoded_email = base64.b64decode(email)
            email = decoded_email.decode('utf-8')
            otp = random.randint(1111,9999)
            time = datetime.datetime.now()
            saved_email = UserRawData.objects.filter(user_email=email).values('user_email')[0]['user_email']
            UserRawData.objects.filter(user_email=email).update(otp = otp,expire_time=time,wrong_attempt=0)
            self.resend_otp(otp,email)
            logger.info("Otp resend Successfully")
            return HttpResponse({"msg":"Otp resend successfully"}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception(str(e))
            return HttpResponse({"msg":"Falied to send otp."}, status=status.HTTP_400_BAD_REQUEST)


    def resend_otp(self,otp,encoded_email):
        """
        Thie method is for resend otp if the user attempts multiple time with wrong otp.

        Args:
            encoded_email (_type_): endoded email where otp will be resend

        Returns:
            A new otp issue to the email given by the user.
        """
        try:
            obj = AESCipher()
            # scheme = self.request.scheme
            email = base64.b64encode(bytes(encoded_email,'utf-8')).decode('utf-8')
            smtp_data = SMTP.objects.get(id=1)
            name = UserRawData.objects.filter(user_email = encoded_email).values()[0]['user_name']
            password = obj.decrypt(smtp_data.password).decode('utf8')
            backend = EmailBackend(host=smtp_data.host, port=smtp_data.port, username=smtp_data.username,password=password, fail_silently=False)
            subject = "EMAIL VERIFICATION"
            domain = BlacklistedDomains.objects.filter(description="Dfront").values('host')[0]['host']
            # https is hardcoded and approved by vc
            msg = f"Hi {name},\n"\
                "This email id sent for verification of you RAPIFUZZ account.\n"\
                f"Please go to this link and verify your account: https://{domain}/account/verification?email={email}\n"\
                f"Please find you OTP below: {otp}\n"\
                "Kindly note the OTP is valid for 15 minutes from the reception time of this email,\n"\
                "If it has expired kindly use the 'Refresh OTP' button in the verification page to generate new OTP which will be sent to your mail again.\n"\
                "Regards,\n"\
                "RAPIFUZZ Team"
            email = EmailMessage(subject=subject, body=msg, from_email= smtp_data.username, to = [encoded_email], connection=backend)
            email.send()
            logger.info("Email sent successfully to %s", encoded_email)
            return HttpResponse({"msg":"Email sent successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(str(e))
            return HttpResponse({"msg":"Falied to send Email."}, status=status.HTTP_400_BAD_REQUEST)


class ProfileUpdateView(APIView):
    """
    API for get and update the user profile
    """

    permission_classes = [IsAuthenticated]
    serializer_class = ProfileUpdateSerializer


    def get(self,request):
    
        user = User.objects.get(email=str(getattr(request, 'user', '')))
        user_id,name = user.id,user.name
        return Response({
            "name":name,
            "email":user.email
        })
 
    def patch(self,request):

        try:
            instance = User.objects.get(email=str(getattr(request, 'user', '')))
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = ProfileUpdateSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message":"Profile updated successfully"} ,status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

