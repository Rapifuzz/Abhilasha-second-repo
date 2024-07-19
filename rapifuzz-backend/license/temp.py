from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from rest_framework.permissions import IsAuthenticated
from licensing.models import *
from licensing.methods import Key, Helpers

RSAPubKey = "<RSAKeyValue><Modulus>yJdndsoHiNEmQ+PUprbipZrOIHlHK1OVe3xCqgDYm744q4JKZ3S4Z3iauoyWDKjIAtpuwLyDSoxRoMTF6SFVf7byr4MIK2TiyEwKL1qSbFklCC0/y9IyUcushh3GKc2vgoZuh2Iw3OvqQP6x16ZuIM+nl/vet7B242HQ6BAQerGOab+03lVBIqgEADfGS2/uH/H6iBZ3E+plF5Oy2X+aC/MMIzXVIj80ZYnnNIJXWmPkoDoYbI0xTQ4gje2+bQ/6CNb9PthPJiyI7EKT99ubmW+1T3OyRH3yik6stnGDJTwDngVPgmEymBPAoQsCiusGWO6KA5y2hvX8qNkmmuPFCw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"

auth = "WyIxMTQ1ODgzIiwiRjhaT3M2bUJyeUVIV1Zsa2F6STVucFppQTg5L0pCZFM5SW5NTmtlaCJd"

result = Key.activate(token=auth, \
                      rsa_pub_key=RSAPubKey, \
                      product_id=10760, \
                      key="EGDPV-CSWUJ-ENVEQ-HSQJX", \
                      machine_code=Helpers.GetMachineCode())

if result[0] == None or not Helpers.IsOnRightMachine(result[0]):
    # an error occurred or the key is invalid or it cannot be activated
    # (eg. the limit of activated devices was achieved)
    print("The license does not work: {0}".format(result[1]))
else:
    # everything went fine if we are here!
    license_key = result[0]

def activate(license_key,product_id):
    RSAPubKey = "<RSAKeyValue><Modulus>yJdndsoHiNEmQ+PUprbipZrOIHlHK1OVe3xCqgDYm744q4JKZ3S4Z3iauoyWDKjIAtpuwLyDSoxRoMTF6SFVf7byr4MIK2TiyEwKL1qSbFklCC0/y9IyUcushh3GKc2vgoZuh2Iw3OvqQP6x16ZuIM+nl/vet7B242HQ6BAQerGOab+03lVBIqgEADfGS2/uH/H6iBZ3E+plF5Oy2X+aC/MMIzXVIj80ZYnnNIJXWmPkoDoYbI0xTQ4gje2+bQ/6CNb9PthPJiyI7EKT99ubmW+1T3OyRH3yik6stnGDJTwDngVPgmEymBPAoQsCiusGWO6KA5y2hvX8qNkmmuPFCw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"

    auth = "WyIxMTQ1ODgzIiwiRjhaT3M2bUJyeUVIV1Zsa2F6STVucFppQTg5L0pCZFM5SW5NTmtlaCJd"
    product_id = str(product_id)
    product_id = product_id.replace(" ","")
    product_id = int(product_id)
    license_key = license_key.replace(" ","")

    result = Key.activate(token=auth, \
                          rsa_pub_key=RSAPubKey, \
                          product_id=product_id, \
                          key=license_key, \
                          machine_code=Helpers.GetMachineCode())

    if result[0] == None or not Helpers.IsOnRightMachine(result[0]):
        # an error occurred or the key is invalid or it cannot be activated
        # (eg. the limit of activated devices was achieved)
        print("The license does not work: {0}".format(result[1]))
    else:
        # everything went fine if we are here!
        license_key = result[0]


class ActivateLicense(APIView):
    # permission_classes = (IsAuthenticated,)
    # parser_classes = [JSONParser]

    def post(self,request):
        data = request.data
        license_key = data['product_key']
        product_id = data['product_id']
        activate(license_key,product_id)
        # if serializer.is_valid():
        #     details = serializer.save()
        #     return Response(PlaybooksSerializer(details).data, status=status.HTTP_201_CREATED)
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"data"}, status=status.HTTP_201_CREATED)
