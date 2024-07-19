from django.urls import include, path
from license.views2 import *

urlpatterns = [

    path(r'get_details/',GetLicenseDetails.as_view()),

    path(r'upload-activation-file/',UploadActivationFile.as_view()),
    path(r'get-activation-file/',GetMachineDetails.as_view()),

    # path(r'get_details_allusers/',GetLicenseDetailsAllUser.as_view()),
]
