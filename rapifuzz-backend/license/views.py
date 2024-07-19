from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated
from licensing.models import *
from licensing.methods import Key, Helpers
from .serializers import *
from .models import *
from rest_framework.parsers import FileUploadParser
import os
from rapifuzz.settings import *
from django.http import FileResponse
import json
from .custom_signature import *

# from incident.settings.base import *
import logging
logger = logging.getLogger("api_fuzzer_license_logger")
logger.propagate = False
logger.info("Failed to update the password for the user with email %s ","ujjwal")

def offline_license_verify():
    RSAPubKey = RSA_KEY
    license_key = None
    try:
        with open('licensefile.skm', 'r') as f:
            license_key = LicenseKey.load_from_string(RSAPubKey, f.read())
    except Exception as Argument:
        print("Exception = ", str(Argument))
    if license_key == None or not Helpers.IsOnRightMachine(license_key):
        return 0
    else:
        return 1


"""
activate the license using RSAPub Key and auth keys as public key.
The function takes license and product id as input and return, the status if the license is okay.
"""


def activate(license_key, product_id=PRODUCT_KEY):
    RSAPubKey = RSA_KEY
    auth = AUTH
    product_id = str(product_id)
    product_id = product_id.replace(" ", "")
    product_id = int(product_id)
    license_key = license_key.replace(" ", "")

    result = Key.activate(token=auth, \
                          rsa_pub_key=RSAPubKey, \
                          product_id=product_id, \
                          key=license_key, \
                          machine_code=Helpers.GetMachineCode())

    if result[0] == None or not Helpers.IsOnRightMachine(result[0],custom_machine_code=CustomSignature().get_custom_signature()):
    # if result[0] == None or not Helpers.IsOnRightMachine(result[0]):

        # an error occurred or the key is invalid or it cannot be activated
        # (eg. the limit of activated devices was achieved)
        print("The license does not work: {0}".format(result[1]))
        return 0, 0
    else:
        # everything went fine if we are here!
        print("The license is valid!")
        license_key = result[0]
        print("Feature 1: " + str(license_key.f1))
        print("License expires: " + str(license_key.expires))
        print("license data object - ", license_key.data_objects)
        # saving license file to disk
        # file_location =
        with open('licensefile.skm', 'w') as f:
            f.write(result[0].save_as_string())

        return 1, license_key.expires  # """Here we return status, if status is 1 as well as expiry date and time"""


# activate("IPYBT-WCEPC-ZRNAI-SXTUX")
"""
ActivateLicense class is responsible to receive post and get request.
Post request - receive license key and product id, further it will call activate function to activate license.
Get request - This will return the license details along with expiry date.
"""


class ActivateLicense(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):

        user_id = request.user.id
        print("org_id = ", user_id)
        print("org_id = ", request.user.id)
        data = request.data
        license_key = data['product_key']
        # product_id = data['product_id']
        temp_data = {}
        temp_data["license_key"] = license_key
        # temp_data["product_id"] = product_id
        temp_data["User_Id"] = user_id
        temp_data['email'] = data['email']

        queryset = LicenseData.objects.filter(license_key=license_key, Status=True)
        if len(queryset) > 0:
            serializer = LicenseDataSerializer(queryset, many=True)
            data = serializer.data[0]
            data['license_key'] = "*********" + data['license_key'][-5:]
            # data['product_id'] = "***"+data['product_id'][-2:]
            data.pop("id")
            data.pop("User_Id")
            print("data = ", data)
            return JsonResponse(data)
        queryset = LicenseData.objects.filter(license_key=license_key)
        if len(queryset) > 0:
            serializer = LicenseDataSerializer(queryset, many=True)
            data = serializer.data[0]
            data['license_key'] = "*********" + data['license_key'][-5:]
            # data['product_id'] = "***"+data['product_id'][-2:]
            data.pop("id")
            data.pop("User_Id")
            print("data = ", data)
            return JsonResponse(data)
        # status,expirydate = activate(license_key)
        status = 0
        """
        If the license is incorrect, in those case the system will return a message 
        stating the license key or product id is wrong.
        """
        # if not status:
        #     return JsonResponse({"message":"Something went wrong pls verify product key or product id"})

        temp_data['Status'] = status
        # temp_data['expiry_time'] = expirydate

        serializer = LicenseDataSerializer(data=temp_data)

        # return JsonResponse({"allready": True},status=status.HTTP_201_CREATED)
        if serializer.is_valid():
            details = serializer.save()
            serializer = LicenseDataSerializer(details)
            data = serializer.data
            data['license_key'] = "*********" + data['license_key'][-5:]
            # data['product_id'] = "***"+data['product_id'][-2:]
            data.pop("id")
            return JsonResponse(data)

        return JsonResponse(serializer.errors)

    def get(self, request):
        try:
            user_id = request.user.id
            queryset = LicenseData.objects.filter(User_Id=user_id, Status=True)
            serializer = LicenseDataSerializer(queryset, many=True)
            data = serializer.data[0]
            data['license_key'] = "*********" + data['license_key'][-5:]
            # data['product_id'] = "***"+data['product_id'][-2:]
            data.pop("id")
            # data.pop("product_id")
            data.pop("User_Id")
            print("check1211")
            return JsonResponse({"data": data}, status=None)
        except Exception as Argument:
            return JsonResponse(serializer.errors)


"""
The UploadActivationFile is used to upload activation file that the client can get from the internal team.
This class will get the file, then check whether it is valid license file or not and 
if the license file is valid it will stored it at specific location. 
Further update the license details to the LicenseData models
"""
from django.contrib.auth.models import User


class UploadActivationFile(APIView):
    """
    The below permission class is used to check authentication.
    """
    permission_classes = (IsAuthenticated,)
    parser_class = (FileUploadParser,)

    # background_view()
    def post(self, request, *args, **kwargs):
        print("check -1-1-1")
        user_id = request.user.id
        request.data['User_Id'] = user_id
        file_serializer = FileSerializer(data=request.data)
        print("check -1-1-2")
        if file_serializer.is_valid():
            print("check -1-1-3")
            details = file_serializer.save()
            # print("file_serializer - ",file_serializer.data['file'])
            filename = file_serializer.data['file']
            filename = filename[7:]
            print("check -1-1-4")
            file_location = os.path.join(MEDIA_ROOT, filename)
            """Move file to specific location"""
            print("check -1-1-5")
            RSAPubKey = RSA_KEY
            auth = AUTH
            # print("email  = ", User.objects.get(user_ID=1).email)
            with open(file_location, 'r') as f:
                license_key = LicenseKey.load_from_string(RSAPubKey, f.read())
                print("license key = ", license_key.key)
                if license_key == None or not Helpers.IsOnRightMachine(license_key,custom_machine_code=CustomSignature().get_custom_signature()):
                    print("NOTE: This license file does not belong to this machine.")
                    JsonResponse({"error": "This license file does not belong to this machine."})
                else:
                    with open(file_location, 'r') as file1:
                        with open("licensefile.skm", "w") as file2:
                            for line in file1:
                                file2.write(line)
                    # license_key = data['product_key']
                    # product_id = data['product_id']
                    print("-------", license_key.key, user_id)
                    query = LicenseData.objects.filter(license_key=license_key.key, User_Id=user_id)
                    if len(query) > 0:
                        print("chech111111111111111111--")
                        query.update(Status=True, expiry_time=license_key.expires)
                        serializer = LicenseDataSerializer(query, many=True)
                        data = serializer.data[0]
                        # print("updated !!!!!!! - ",data)
                        data['license_key'] = "*********" + data['license_key'][-5:]
                        data.pop('User_Id')
                        data.pop('email')
                        data.pop('Updated_At')
                        data.pop('id')

                        return JsonResponse(data)
                        # return JsonResponse({"message":"dd"})
                    else:
                        temp_data = {}
                        temp_data["license_key"] = license_key.key
                        # temp_data["product_id"] = product_id

                        temp_data["User_Id"] = user_id
                        temp_data['Status'] = 1
                        temp_data['expiry_time'] = license_key.expires
                        # print("licesse - = ",license_key.key)
                        serializer = LicenseDataSerializer(data=temp_data)

                        if serializer.is_valid():
                            details = serializer.save()
                            serializer = LicenseDataSerializer(details)
                            data = serializer.data
                            data['license_key'] = "*********" + data['license_key'][-5:]
                            # data['product_id'] = "***"+data['product_id'][-2:]
                            data.pop("id")
                            return JsonResponse(data)
                    try:
                        os.remove("licensefile.skm")
                    except Exception as e:
                        print("Exception - ",str(e))
                    return JsonResponse({"error":"Something went wrong."}, status=status.HTTP_403_FORBIDDEN)
        else:
            try:
                os.remove("licensefile.skm")
            except Exception as e:
                print("Exception - ",str(e))
            return JsonResponse({"error":"Invalid file."}, status=status.HTTP_400_BAD_REQUEST)


"""
GetMachineDetails is used whenever the client need to activate license offline, 
in that case the client require to submit machine id with the license provider(internal team)
Further the internal team use the machile id to generate license activation file from cryptolens
portal.
"""
from django.http import HttpResponse, HttpResponseNotFound


class GetMachineDetails(APIView):
    # print("check1")
    # permission_classes = (IsAuthenticated,)
    def get(self, request):
        # print("req = ",request)
        try:
            # It usage Helpers module from license package to fetch machine code
            print("fetching machine details")
            # machine_details = Helpers.GetMachineCode()
            machine_details = CustomSignature().get_custom_signature()
            print("check - 1 - ", machine_details)
            filename = 'license1-activation-file.lic'
            data = {"machine_id": machine_details, "Warning": "Please don't edit this file."}
            data_obj = json.dumps(data)
            with open(filename, 'w') as file:
                file.write(data_obj)
            # sending file to client
            print("check 2")
            response = HttpResponse(open(filename, mode='rb'), content_type='text/plain')
            response["Content-Disposition"] = 'attachment; filename="' + filename + '"'
            # removing this file from server
            # os.remove(filename)
            print("check 3")
            return response
        except Exception as Argument:
            print("exception : ", str(Argument))
            return JsonResponse({"error": str(Argument)}, status=status.HTTP_400_BAD_REQUEST)


"""
GetLicenseDetails, class is to view the expiry details of the license.
"""


class GetLicenseDetails(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        try:
            from rapifuzz.settings import LICENSE_KILLSWITCH
            if LICENSE_KILLSWITCH:
                print("license kill switch is on")
                data = {"Status":True,"Created_At":"23-March-2022 15:49:26 PM",
                        "expiry_time": ""}
                print("response from kill switch")
                data.update({"license_key":""})
                data.update({"email": ""})
                
                return JsonResponse({"data": data}, status=200)
        except Exception as e:
            print("exception as e = ", str(e))
            pass
        try:
            user_id = request.user.id
            print("check 22222222222222 - ", user_id)
            queryset = LicenseData.objects.filter(User_Id=user_id)
            serializer = LicenseDataSerializer(queryset, many=True)
            if len(serializer.data)==1:
                data = serializer.data[0]
            elif len(serializer.data)==0:
                return JsonResponse({"error": "no active license"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                query = LicenseData.objects.filter(User_Id=user_id,Status=True)
                serializer = LicenseDataSerializer(query, many=True)
                data = serializer.data[0]

            print("check 111111111111 - ")
            # print("check 22222222222222 - ",data['license_key'])
            data['license_key'] = "*********" + data['license_key'][-5:]
            print("check 191999999")
            # data['product_id'] = "***"+data['product_id'][-2:]
            data.pop("id")
            # data.pop("product_id")
            data.pop("User_Id")
            data.pop("Updated_At")
            print("check1211")
            return JsonResponse({"data": data}, status=None)
        except Exception as Argument:
            return JsonResponse({"error": "no active license"}, status=status.HTTP_400_BAD_REQUEST)

"""
GetLicenseDetailsAllUser class is used to provide the license details (expiry date time) for all user.
"""
class GetLicenseDetailsAllUser(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        RSAPubKey = RSA_KEY
        license_key = None
        try:
            from rapifuzz.settings import LICENSE_KILLSWITCH
            if LICENSE_KILLSWITCH:
                print("license kill switch is on")
                data = {"Status":True,"Created_At":"21-Feb-2022 15:49:26 PM",
                        "expiry_time": "14-Feb-2023 16:12:48 PM"}
                print("response from kill switch")
                return JsonResponse({"data": data}, status=200)
        except Exception as e:
            print("exception as e = ", str(e))
            pass

        try:
            with open('licensefile.skm', 'r') as f:
                license_key = LicenseKey.load_from_string(RSAPubKey, f.read())
            key = license_key.key
            try:
                queryset = LicenseData.objects.filter(license_key=key)
                serializer = LicenseDataSerializer(queryset, many=True)
                if len(serializer.data)==1:
                    data = serializer.data[0]
                elif len(serializer.data)==0:
                    return JsonResponse({"error": "no active license"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    query = LicenseData.objects.filter(license_key=key,Status=True)
                    serializer = LicenseDataSerializer(query, many=True)
                    data = serializer.data[0]
                print("check 111111111111 - ")
                # print("check 22222222222222 - ",data['license_key'])
                data['license_key'] = "*********" + data['license_key'][-5:]
                print("check 191999999")
                # data['product_id'] = "***"+data['product_id'][-2:]
                data.pop("id")
                # data.pop("product_id")
                data.pop("User_Id")
                data.pop("Updated_At")
                data.pop("email")
                data.pop("license_key")
                # data.pop("")
                return JsonResponse({"data": data}, status=None)
            except Exception as Argument:
                return JsonResponse({"error":"no active license"})
        except Exception as Argument:
            return JsonResponse({"error": "no active license"}, status=status.HTTP_400_BAD_REQUEST)



class DeleteAPI(APIView):
    # permission_classes = (IsAuthenticated,)
    # print("hebeh")
    def get(self, request):
        try:
            queryset = LicenseData.objects.all().delete()
        except Exception as Argument:
            pass
        try:
            os.remove("licensefile.skm")
            queryset = LicenseData.objects.all()
            message = "Active license : " + str(len(queryset))
            return JsonResponse({"message": message})
        except OSError as e:
            queryset = LicenseData.objects.all()
            message = "Active license : " + str(len(queryset))
            return JsonResponse({"message": message})
        except Exception as Argument:
            return JsonResponse({"error": "something went wrong!"}, status=status.HTTP_400_BAD_REQUEST)
