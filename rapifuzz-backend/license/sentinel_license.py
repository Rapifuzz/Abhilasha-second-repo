############################
# internal Python sample
############################

from ctypes import *
import sys
import platform
import xmltodict
import json
import os
import requests
from datetime import datetime
from fuzzer.components.licence import deactivate_projects
import logging
from rapifuzz.settings import FEATURE_ID as feature_id
from rapifuzz.settings import VENDOR_CODE as vendor_code
from rapifuzz.settings import LICENSE_HOST

feature_id = feature_id
vendor_code = c_char_p(vendor_code)

logger = logging.getLogger("api_fuzzer_license_logger")
logger.propagate = False




def check_killswitch():
    try:
        from rapifuzz.settings import LICENSE_KILLSWITCH
        if LICENSE_KILLSWITCH:
            return True
    except Exception as e:
        logger.warning("Check license kill switch error : {}".format(str(e)))
        pass

    return False


class License():
    """
    Lincese : It has functionality to get hasp_id, download c2v file, activate license and also verify license.
    """

    def __int__(self):
        self.vendor_code = c_char_p(vendor_code)
        self.feature_id = feature_id
        self.libc = None
        logger.info("License object created!")

    def is_execution(self) -> bool:
        try:
            """
            get_machine_details:    function is used to retrive information about license expiry details.
                                    Here we have set some pre-defined parameters such as scope, info format,
                                    which help in retriving the exact output from C-API.
            """
            result = []
            info_format = c_char_p(b'''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
            <haspformat root=\"hasp_info\">
                <hasp>
                    <attribute name=\"id\"/>
                    <attribute name=\"type\"/>
                    <feature>
                            <attribute name=\"id\"/>
                            <attribute name=\"name\"/>
                            <element name=\"license\"/>
                    </feature>
                </hasp>
            </haspformat>''')
            info = POINTER(c_char)()
            info_s = ""
            scope = c_char_p(b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><haspscope/>")
            status = self.libc.hasp_get_info(scope, info_format, vendor_code, byref(info))
            logger.info("License is_execution; status : {}".format(str(status)))
            if status == 0:
                i = 0
                while info[i] != b'\000':
                    info_s += info[i].decode('utf-8')
                    i = i + 1
                data_dict = xmltodict.parse(info_s)
                data_dict = json.dumps(data_dict)
                data_dict = json.loads(data_dict)
                feature = data_dict['hasp_info']['hasp']
                if type(feature) == list:
                    for iter in feature:
                        if iter['feature']:
                            feature = iter['feature']
                            break
                elif type(feature) == dict:
                    feature = feature['feature']

                for iter in feature:
                    if iter['license']['license_type'] == 'executions':
                        return True
            return False
        except Exception as e:
            logger.warning("License is_execution; exception : {}".format(str(e)))
            return False

    def decrement_execution(self):
        """Decrement the number of product allowed to test!!"""
        logger.info("License decreament execution count function call")  
        libc = self.set_libs()
        if check_killswitch():
            return True
        try:
            if self.is_execution() and self.libc:
                handle = c_int(0)
                from rapifuzz.settings import FEATURE_ID as feature_id
                feature_id = c_int(feature_id['project'])
                self.libc.hasp_login.argtypes = [c_int, c_void_p, c_void_p]
                self.libc.hasp_login.restype = c_int
                status = self.libc.hasp_login(feature_id, vendor_code, addressof(handle))
                logger.info("License decrement_execution; status : {}".format(str(status)))
                if status==0:
                    status = self.libc.hasp_logout(handle)
                    logger.info("License allocated to project successfully, status : {}".format(status))
                    return True
                logger.info("License decrement, status : {}".format(status))
            return False
        except Exception as _error:
            logger.warning("Exception from license decrement : {}".format(str(_error)))
            return False
    

    def decrement_APICount(self):
        """Decrement the individual API Count!!"""
        logger.info("License decreament API execution count function call")  
        libc = self.set_libs()
        if check_killswitch():
            return True
        try:
            if self.is_execution() and self.libc:
                handle = c_int(0)
                from rapifuzz.settings import FEATURE_ID as feature_id
                feature_id = c_int(feature_id.get('individual-api'))
                self.libc.hasp_login.argtypes = [c_int, c_void_p, c_void_p]
                self.libc.hasp_login.restype = c_int
                status = self.libc.hasp_login(feature_id, vendor_code, addressof(handle))
                logger.info("License decrement_APICount; status : {}".format(str(status)))
                if status==0:
                    status = self.libc.hasp_logout(handle)
                    logger.info("License allocated to individual API successfully, status : {}".format(status))
                    return True
                logger.info("License APICount decrement, status : {}".format(status))
            return False
        except Exception as _error:
            logger.warning("Exception from license APICount : {}".format(str(_error)))
            return False

    def verify_license(self, execution_feature_id = None):
        try:
            from rapifuzz.settings import LICENSE_KILLSWITCH
            if LICENSE_KILLSWITCH:
                return True
        except Exception as e:
            pass
        try:
            if self.libc:
                handle = c_int(0)
                if execution_feature_id:
                    feature_id = c_int(execution_feature_id)
                else:
                    from rapifuzz.settings import FEATURE_ID as feature_id
                    if "demo" in feature_id.keys():
                        feature_id = c_int(feature_id['demo'])
                    else:
                        feature_id = c_int(feature_id.get('enterprise'))
                self.libc.hasp_login.argtypes = [c_int, c_void_p, c_void_p]
                self.libc.hasp_login.restype = c_int
                status = self.libc.hasp_login(feature_id, vendor_code, addressof(handle))
                logger.info("License verify license; status : {}".format(str(status)))
                if status==0:
                    status = self.libc.hasp_logout(handle)
                    return True
                else:
                    pass        ###DEACTIVATE ALL PRODUCT
                    #####CHECK IF LICENSE HAS FESTURE ID OF EXECUTION OR ONLY DURATION
                    #####IF IT HAS EXECUTION FEATURE ID THEN DEACTIVATE ALL PRODUCT ELSE NO NEED TO DEACTIVATE
                    if self.is_execution():
                        status = deactivate_projects()
                        logger.info("All existing projects deactivated with status : {}".format(status))

            return False
        except Exception as _error:
            logger.warning("Exception from license verification : {}".format(str(_error)))
            return False

    def set_libs(self):
        try:
            OSplatform = sys.platform
            LibName = ""
            (bits, linkage) = platform.architecture()
            if OSplatform.startswith('win'):
                if bits == '64bit':
                    LibName = "hasp_windows_x64_demo"
                else:
                    LibName = "hasp_windows_demo"  # defaults to 32bit
            elif OSplatform.startswith('linux'):
                if bits == '64bit':
                    LibName = "libhasp_linux_x86_64_demo.so"
                else:
                    LibName = "libhasp_linux_demo.so"  # defaults to 32bit
            else:
                logger.warning("Unmanaged OS: {}".format(OSplatform))
                return False
            cwd = os.getcwd()
            file_path = os.path.join(cwd, "license/" + LibName)
            libc = cdll.LoadLibrary(file_path)
            self.libc = libc
            logger.info("License set_libc return : {}".format(str(True)))
            return True
        except Exception as _error:
            logger.warning("Exception from set_libc : {}".format(str(_error)))
            return False

    def get_updated_finger_print(self):
        """
        get_finger_print : This will generate a c2v file and save it locally.
        """
        try:
            # Variables configuration which are required to generate C2V
            handle = c_int(0)
            info_format = c_char_p(b'''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
            <haspformat root=\"hasp_info\">
                    <license_manager>
                                <element name=\"hostname\"/>
                                <element name=\"ip\"/>
                                <element name=\"osname\"/>
                </license_manager>
                <hasp>
                    <attribute name=\"id\"/>
                    <attribute name=\"type\"/>
                    <feature>
                            <attribute name=\"id\"/>
                            <attribute name=\"name\"/>
                            <element name=\"license\"/>
                    </feature>
                </hasp>
            </haspformat>''')
            info = POINTER(c_char)()
            info_s = ""
            # scope = c_char_p(b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><haspscope/>")
            scope = c_char_p(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             b"<haspscope><license_manager "
                             b"hostname=\"localhost\"/></haspscope>")
            format = c_char_p(b"<haspformat format=\"updateinfo\"/>")
            if self.libc:

                self.libc.hasp_login.argtypes = [c_int, c_void_p, c_void_p]
                self.libc.hasp_login.restype = c_int
                status = self.libc.hasp_get_info(scope, format, vendor_code, byref(info))
                logger.info("License get_updated_finger_print; status : {}".format(str(status)))
                if status == 0:
                    i = 0
                    while info[i] != b'\000':
                        info_s += info[i].decode('utf-8')
                        i = i + 1

                    cwd = os.getcwd()
                    file_path = os.path.join(cwd, "license/fingerprint.c2v")
                    with open(file_path, "w") as fp:
                        fp.write(info_s)
                    return file_path
                else:
                    return self.get_finger_print()
            return False
        except Exception as e:
            logger.warning("License get_updated_finger_print; exception : {}".format(str(e)))
            return False

    def get_finger_print(self):
        """
        get_finger_print : This will generate a c2v file and save it locally.
        """
        try:
            info = POINTER(c_char)()
            info_s = ""
            scope = c_char_p(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             b"<haspscope><license_manager "
                             b"hostname=\"localhost\"/></haspscope>")
            format = c_char_p(b"<haspformat format=\"host_fingerprint\"/>")
            if self.libc:

                self.libc.hasp_login.argtypes = [c_int, c_void_p, c_void_p]
                self.libc.hasp_login.restype = c_int
                status = self.libc.hasp_get_info(scope, format, vendor_code, byref(info))
                logger.info("License get_finger_print; status : {}".format(str(status)))
                if status == 0:
                    i = 0
                    while info[i] != b'\000':
                        info_s += info[i].decode('utf-8')
                        i = i + 1
                    cwd = os.getcwd()
                    file_path = os.path.join(cwd, "license/fingerprint.c2v")
                    with open(file_path, "w") as fp:
                        fp.write(info_s)
                    return file_path
        except Exception as e:
            logger.warning("License get_finger_print; exception : {}".format(str(e)))
        return False

    def activate_license(self, file_name, file_location):
        """
        activate_license:   It is uploading license to the sentinel runtime environment.
        """
        try:
            if self.libc:
                url = str(LICENSE_HOST)+"/_int_/checkin_file.html"
                # headers = {"Content-Type": "multipart/form-data","User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"}
                # cwd = os.getcwd()
                # file_path = os.path.join(cwd, file_name)

                payload = {"filename": (file_name, open(file_location, "rb"), "text/plain")}
                response = requests.request("POST", url, files = payload)
                logger.info("License activate; response code : {}, response text : {}".format(str(response.status_code), response.content))
                if response.status_code == 200:
                    status = deactivate_projects()
                    return True
        except Exception as e:
            logger.warning("License activate license; exception : {}".format(str(e)))
        return False

    def get_license_details(self):
        try:
            """
            get_machine_details:    function is used to retrive information about license expiry details.
                                    Here we have set some pre-defined parameters such as scope, info format,
                                    which help in retriving the exact output from C-API.
            """
            result = []
            info_format = c_char_p(b'''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
            <haspformat root=\"hasp_info\">
                <hasp>
                    <attribute name=\"id\"/>
                    <attribute name=\"type\"/>
                    <feature>
                            <attribute name=\"id\"/>
                            <attribute name=\"name\"/>
                            <element name=\"license\"/>
                    </feature>
                </hasp>
            </haspformat>''')
            info = POINTER(c_char)()
            info_s = ""
            scope = c_char_p(b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><haspscope/>")
            status = self.libc.hasp_get_info(scope, info_format, vendor_code, byref(info))
            logger.info("License details; status : {}".format(str(status)))
            if status == 0:
                i = 0
                while info[i] != b'\000':
                    info_s += info[i].decode('utf-8')
                    i = i + 1
                data_dict = xmltodict.parse(info_s)
                data_dict = json.dumps(data_dict)
                data_dict = json.loads(data_dict)
                feature = data_dict['hasp_info']['hasp']
                if type(feature) == list:
                    for iter in feature:
                        if iter['feature']:
                            feature = iter['feature']
                            break
                elif type(feature) == dict:
                    feature = feature['feature']

                for iter in feature:
                    if iter['@id'] == '2023' or iter['@id'] == '2024' or iter['@id'] == '1023' or iter['@id'] == '3024':
                        temp = {"info": iter['@name']}
                        if iter['license']['license_type'] == 'expiration':
                            temp.update({"exp_date": datetime.fromtimestamp(
                                (int(iter['license']['exp_date']))).strftime("%m/%d/%Y, %H:%M:%S")})
                        elif iter['license']['license_type'] == 'executions':
                            temp.update({"total": iter['license']['counter_fix']})
                            temp.update({"used": iter['license']['counter_var']})
                        result.append(temp)

            return result
        except Exception as e:
            logger.warning("License details; exception : {}".format(str(e)))

            return None


    def is_product_available(self):
        try:
            """
            get_machine_details:    function is used to retrive information about license expiry details.
                                    Here we have set some pre-defined parameters such as scope, info format,
                                    which help in retriving the exact output from C-API.
            """

            info_format = c_char_p(b'''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
            <haspformat root=\"hasp_info\">
                <hasp>
                    <attribute name=\"id\"/>
                    <attribute name=\"type\"/>
                    <feature>
                            <attribute name=\"id\"/>
                            <attribute name=\"name\"/>
                            <element name=\"license\"/>
                    </feature>
                </hasp>
            </haspformat>''')
            info = POINTER(c_char)()
            info_s = ""
            scope = c_char_p(b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><haspscope/>")
            status = self.libc.hasp_get_info(scope, info_format, vendor_code, byref(info))
            logger.info("License product availability; status : {}".format(str(status)))
            if status == 0:
                i = 0
                while info[i] != b'\000':
                    info_s += info[i].decode('utf-8')
                    i = i + 1

                data_dict = xmltodict.parse(info_s)
                data_dict = json.dumps(data_dict)
                data_dict = json.loads(data_dict)

                feature = data_dict['hasp_info']['hasp']
                if type(feature) == list:
                    for iter in feature:
                        if iter['feature']:
                            feature = iter['feature']
                            break
                elif type(feature) == dict:
                    feature = feature['feature']
                for iter in feature:
                    if iter['@id'] == '2024':
                        if iter['license']['license_type'] == 'executions':
                            fix = iter['license']['counter_fix']
                            var = iter['license']['counter_var']
                            if int(fix)>int(var):
                                return True
            return False
        except Exception as e:
            logger.warning("Product availablity check issue : {}".format(str(e)))

            return False
    


    def is_APICount_available(self):
        try:
            """
            get_machine_details:    function is used to retrive information about license expiry details.
                                    Here we have set some pre-defined parameters such as scope, info format,
                                    which help in retriving the exact output from C-API.
            """

            info_format = c_char_p(b'''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
            <haspformat root=\"hasp_info\">
                <hasp>
                    <attribute name=\"id\"/>
                    <attribute name=\"type\"/>
                    <feature>
                            <attribute name=\"id\"/>
                            <attribute name=\"name\"/>
                            <element name=\"license\"/>
                    </feature>
                </hasp>
            </haspformat>''')
            info = POINTER(c_char)()
            info_s = ""
            scope = c_char_p(b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><haspscope/>")
            status = self.libc.hasp_get_info(scope, info_format, vendor_code, byref(info))
            logger.info("License APICount availability; status : {}".format(str(status)))
            if status == 0:
                i = 0
                while info[i] != b'\000':
                    info_s += info[i].decode('utf-8')
                    i = i + 1

                data_dict = xmltodict.parse(info_s)
                data_dict = json.dumps(data_dict)
                data_dict = json.loads(data_dict)

                feature = data_dict['hasp_info']['hasp']
                if type(feature) == list:
                    for iter in feature:
                        if iter['feature']:
                            feature = iter['feature']
                            break
                elif type(feature) == dict:
                    feature = feature['feature']
                for iter in feature:
                    if iter['@id'] == '3024':
                        if iter['license']['license_type'] == 'executions':
                            fix = iter['license']['counter_fix']
                            var = iter['license']['counter_var']
                            if int(fix)>int(var):
                                return True
            return False
        except Exception as e:
            logger.warning("Product availablity check issue : {}".format(str(e)))

            return False

# Do not remove this code for sometime.
# l = License()
# print("Setting up variables - ",l.set_libs())
# print("License Status - ",l.verify_license())
# print("APICount Availability - ",l.is_APICount_available())
# print("Decrement APICount - ",l.decrement_APICount())
# print(l.get_finger_print())
# print(l.get_updated_finger_print())
# print(l.get_license_details())
# print(l.decrement_execution())
