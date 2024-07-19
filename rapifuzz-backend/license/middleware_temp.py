"""
Licence Middleware
"""
import json
from licensing.models import *



def offline_license_verify():
    """
    offline license verification usages to verify license file. This takes licensefile as auto pick input
    and return whether license exits or not.
    """
    RSAPubKey = "<RSAKeyValue><Modulus>yJdndsoHiNEmQ+PUprbipZrOIHlHK1OVe3xCqgDYm744q4JKZ3S4Z3iauoyWDKjIAtpuwLyDSoxRoMTF6SFVf7byr4MIK2TiyEwKL1qSbFklCC0/y9IyUcushh3GKc2vgoZuh2Iw3OvqQP6x16ZuIM+nl/vet7B242HQ6BAQerGOab+03lVBIqgEADfGS2/uH/H6iBZ3E+plF5Oy2X+aC/MMIzXVIj80ZYnnNIJXWmPkoDoYbI0xTQ4gje2+bQ/6CNb9PthPJiyI7EKT99ubmW+1T3OyRH3yik6stnGDJTwDngVPgmEymBPAoQsCiusGWO6KA5y2hvX8qNkmmuPFCw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
    license_key = None
    try:
        with open('licensefile.skm', 'r') as f:
            license_key = LicenseKey.load_from_string(RSAPubKey, f.read())
    except Exception as Argument:
        print("Exception = ",str(Argument))
    if license_key == None or not Helpers.IsOnRightMachine(license_key):
        return 0
    else:
        return 1


class BaseMiddleware:
    """
    BaseMiddleware is the class which takes all request as 
    input and verify license and proceed the request
    to reach the respective views.
    """
    def __init__(self, get_response):
        self.get_response = get_response


    def __call__(self, request):
        response =  self.get_response(request)
        path = request.path_info
        if path=="/api/token":
            data = json.loads(response.content)
            status = offline_license_verify()
            data.update({"license_status":status})
            return Response(data)
        return response


    def process_view(self, request, view_func, view_args, view_kwargs):
        path = request.path_info
        """
        Check the path and if it is login then bypass it to get the token.
        Get the token and if that available check for org admin, whether the user is
        organization admin or general user.
        If the request come from general user and the license is okay the proceed else stop the request.
        If the request come from organization admin, then do the license check and even if that return invalid
        license, the application will return license page.
        """
        if path=="/api/token":
            return None
        return None
    
    def process_response(self, response):
        return None
