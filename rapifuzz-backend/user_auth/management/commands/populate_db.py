from django.core.management.base import BaseCommand
from django.conf import settings
import pandas as pd
from fuzzer.models import TestcaseData,PayloadAndRegex,EPDTMap,ThirdPartyDomain,Ports,DefaultHTTPCodes
from fuzzer.components.portcheck import CHECKPORT


class UpdateStaticData():
    def __init__(self):
        self.aio_file = settings.STATIC_ROOT+"/testcasesheet/AIOx.xlsx"
    
    def _populate_testcase_data(self,data):
        if TestcaseData.objects.all().count() != 0:
            TestcaseData.objects.all().delete()
        for i in range(len(data)):
            obj = TestcaseData(category=str(data["category"][i]), is_active=True, exploitability=data["exploitability"][i], prevalence=data["prevalance"][i], detectability=data["detectability"][i], description=str(
                data["description"][i]), technical=data["technical"][i], prevention=str(data["prevention"][i]), cwe=str(data["cwe"][i]), name=str(data["name"][i]), custom_name=str(data["custom_name"][i]), tid=str(data["tid"][i]), mid=str(data["mid"][i]), api_2019=str(data["api_2019"][i]),api_2023=str(data["api_2023"][i]))
            obj.save()    

    def _populate_tpd_data(self,data):
        if ThirdPartyDomain.objects.all().count() != 0:
            ThirdPartyDomain.objects.all().delete()
        for i in range(len(data)):
            obj = ThirdPartyDomain(domain=str(data["domains"][i]))
            obj.save()    


    def _populate_epdt_data(self,data):
        if EPDTMap.objects.all().count() != 0:
            EPDTMap.objects.all().delete()
        for i in range(len(data)):
            obj = EPDTMap(epdt=str(data["epdt"][i]), string=str(
                data["string"][i]), value=data["value"][i])
            obj.save()    


    def _populate_ports_data(self,data):
        if Ports.objects.all().count() !=0:
            Ports.objects.all().delete()
        for i in range(len(data)):
            if CHECKPORT.check_port_status(data["portno"][i]):
                obj = Ports(pid=None, sid=None, portno=str(
                    data["portno"][i]), status=str(data["status"][i]))
                obj.save()

    def _populate_default_codes_data(self,data):
        if DefaultHTTPCodes.objects.all().count() != 0:
            DefaultHTTPCodes.objects.all().delete()
        for i in range(len(data)):
            obj = DefaultHTTPCodes(http_code = int(data["http_code"][i]),http_reason = str(data["http_reason"][i]),custom_mapping = str(data["custom_mapping"][i]),status_code_type = str(data["status_code_type"][i]).lower().capitalize(),)
            obj.save()

    def _populate_p_or_r_data(self,data):
        if PayloadAndRegex.objects.all().count() != 0:
            PayloadAndRegex.objects.all().delete()
        for i in range(len(data)):
            obj = PayloadAndRegex(mid=str(data["mid"][i]), payload_type=bool(data["payload_type"][i]), technique_type=str(
                data["technique_type"][i]), value=data["value"][i], p_or_r=str(data["p_or_r"][i]), db_type=str(data["db_type"][i]))
            obj.save()

    def _populate_data(self):

        testcase_data = pd.read_excel(self.aio_file, engine="openpyxl", sheet_name="testcase")
        testcase_data = pd.DataFrame(testcase_data)
        tpd_data = pd.read_excel(self.aio_file, engine="openpyxl", sheet_name="thirdpartydomains")
        tpd_data = pd.DataFrame(tpd_data)
        epdt_data = pd.read_excel(self.aio_file, engine="openpyxl", sheet_name="epdtmap")
        epdt_data = pd.DataFrame(epdt_data)
        payloadandregex_data = pd.read_excel(self.aio_file, engine="openpyxl", sheet_name="payloadandregex")
        payloadandregex_data = pd.DataFrame(payloadandregex_data)
        ports_data = pd.read_excel(self.aio_file, engine="openpyxl", sheet_name="proxyports")
        ports_data = pd.DataFrame(ports_data)
        http_codes_data = pd.read_excel(self.aio_file, engine="openpyxl",sheet_name="http_codes")
        http_codes_data = pd.DataFrame(http_codes_data)
        # Call all the methods here ......
        self._populate_testcase_data(testcase_data)
        self._populate_tpd_data(tpd_data)
        self._populate_epdt_data(epdt_data)
        self._populate_p_or_r_data(payloadandregex_data)
        self._populate_ports_data(ports_data) 
        self._populate_default_codes_data(http_codes_data) 
        return True

class Command(BaseCommand):
    def handle(self, *args, **options):
        try:
            static_data = UpdateStaticData()
            static_data._populate_data()
            return "Testcase data populated successfully................................................................"
        except Exception as e:
            raise Exception(f"Something went wrong while populating the testcase and other static data into database {e}")
