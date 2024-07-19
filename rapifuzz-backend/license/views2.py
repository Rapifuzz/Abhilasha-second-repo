from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from license.serializers import FileSerializer
from rest_framework.parsers import FileUploadParser
import os
from rapifuzz.settings import *
from license.sentinel_license import License
from django.http import HttpResponse
import logging


logger = logging.getLogger("api_fuzzer_license_logger")
logger.propagate = False


class UploadActivationFile(APIView):
    """
    This API is responsible to receive V2C file from user and activate the license.
    The UploadActivationFile is used to upload activation file that the client can get from the internal team.
    This class will get the file, then check whether it is valid license file or not and 
    if the license file is valid it will stored it at specific location. 
    Further update the license details to the LicenseData models
    """
    permission_classes = (IsAuthenticated,)
    parser_class = (FileUploadParser,)

    # background_view()
    def post(self, request, *args, **kwargs):
        try:
            user_id = request.user.id
            request.data['User_Id'] = user_id
            file_serializer = FileSerializer(data=request.data)
            logger.info("Updating license v2c file, request data : {}".format(request.data))
            if file_serializer.is_valid():
                details = file_serializer.save()
                filename = file_serializer.data['file']
                filename = filename[7:]
                file_location = os.path.join(MEDIA_ROOT, filename)
                license = License()
                if license.set_libs():
                    flag = license.activate_license(filename, file_location)
                    logger.info("license activated with status : {}".format(flag))
                    if flag:
                        return Response({
                            "message": "License Activated!",
                            "success": True}, status=status.HTTP_200_OK)
                    else:
                        return Response({
                            "message": "Unable to activate license!",
                            "success": False}, status=status.HTTP_403_FORBIDDEN)
                else:
                    logger.warning("unable to call license activate function : %s",license.set_libs())
                    raise ValueError("Unable to activate license!")
            else:
                logger.warning("Serilizer issue : %s", file_serializer.errors)
                raise ValueError("File is incorrect.")
        except ValueError as _error:
            return Response({
                "message": "Incorrect file",
                "success": False,
                "error": str(_error)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as _error:
            return Response({
                "message": "Something went wrong, please try after sometime.",
                "success": False,
                "error": str(_error)}, status=status.HTTP_400_BAD_REQUEST)


class GetMachineDetails(APIView):
    """
    It generates C2V file from sentinel runtime environment.
    GetMachineDetails is used whenever the client need to activate license offline, 
    in that case the client require to submit machine id with the license provider(internal team)
    Further the internal team use the machile id to generate license activation file from cryptolens
    portal.
    """
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        try:
            # It uses Helpers module from license package to fetch machine code
            license = License()
            if license.set_libs():
                file_path = license.get_updated_finger_print()
                if not file_path:
                    print("check 1 - updated fingerprint")
                    file_path = license.get_finger_print()
                if file_path:

                    response = HttpResponse(open(file_path, mode='rb'), content_type='text/plain')
                    response["Content-Disposition"] = 'attachment; filename="fingerprint.c2v"'
                    return response
                else:
                    raise ValueError("Something went wrong, please try after sometime.")
        except ValueError as _error:
            return Response({"error": str(_error)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as Argument:

            return Response({"error": str(Argument)}, status=status.HTTP_400_BAD_REQUEST)



class GetLicenseDetails(APIView):
    """
    GetLicenseDetails, class is to view the expiry details of the license.
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        try:
            from rapifuzz.settings import LICENSE_KILLSWITCH
            if LICENSE_KILLSWITCH:

                data = [ {
                        "info": "Test Feature",
                        "exp_date": "12/09/2022, 05:29:59"
                    }]
                return Response({
                    "success": True,
                    "data": data}, status=status.HTTP_200_OK)
        except Exception as e:
            pass
        try:
            license = License()
            data = {}
            if license.set_libs():
                data = license.get_license_details()
            else:
                raise ValueError("Unable to fetch license details.")
            return Response({
                "success": True,
                "data": data}, status=status.HTTP_200_OK)
        except ValueError as _error:
            logger.info(str(_error))
            Response({
                "success": False,
                "error": _error}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as _error:
            logger.info(str(_error))
            return Response({
                "success":False,
                "error":str(_error)
            }, status=status.HTTP_400_BAD_REQUEST)
