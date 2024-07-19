"""
Licence Middleware 
"""

import json
from licensing.models import *
from rapifuzz.settings import RSA_KEY
from rest_framework.renderers import JSONRenderer
from license.sentinel_license import License



def check_killswitch():
    """
    BaseMiddleware is the class which takes all request as input and verify license and proceed the request
    to reach the respective views.
    """
    try:
        from rapifuzz.settings import LICENSE_KILLSWITCH
        if LICENSE_KILLSWITCH:
            return True
    except Exception as e:
        pass

    return False

class BaseMiddleware:

    renederrer_class = JSONRenderer() # For rendering the json data .

    def __init__(self, get_response):
        self.get_response = get_response


    def __call__(self, request):

        path = request.path_info
        response =  self.get_response(request)
        if "/createproject" in path and not check_killswitch():
            license = License()
            if license.set_libs() and license.is_product_available():
                pass
            else:
                data = {
                    "message": "Further project cannot be created",
                    "success": False
                }
                response.content = self.renederrer_class.render(data)
            return response

        if path=="/api/token" or path=="/api/token/refresh":
            data = json.loads(response.content)
            license = License()
            if response.status_code in range(199,299): # For adding licence status in case of successful response only
                if license.set_libs():
                    status = license.verify_license()
                    data.update({"license_status":status})
                else:
                    data.update({"license_status": False})
            response.content  = self.renederrer_class.render(data)  
        return response
