import uuid
import hashlib
"""
CustomSignature is getting machine ID and encoding it with psycopg2 (SHA256).
"""
import os
import logging
logger = logging.getLogger("api_fuzzer_license_logger")
logger.propagate = False

class CustomSignature:

    def get_machine_id(self):
        uuid_obj = os.popen('sudo dmidecode | grep -w UUID | sed "s/^.UUID\: //g"')
        uuid = uuid_obj.read()
        uuid_str = uuid.strip()
        print("uuid : ",uuid_str)
        logger.info("Machine Id : %s ", uuid_str)
        return uuid_str

    def hash_machine_id(self,machine_id):
        machine_id = str(machine_id)
        result = hashlib.sha256(machine_id.encode())
        return result.hexdigest()

    def get_custom_signature(self):
        machine_id = str(self.get_machine_id())
        # machine_id = machine_id.split("-")
        # machine_id = machine_id[len(machine_id)-1]
        return self.hash_machine_id(machine_id)

    def validate_machine(self,hash):
        machine_id = str(self.get_machine_id())
        # ind = machine_id.index("-")
        # machine_id = machine_id[ind + 1:]
        return self.check_password_hash(hash,machine_id)

    def check_password_hash(self,hash,password):
        hash = str(hash)
        password = str(password)
        result = hashlib.sha256(password.encode())
        password = result.hexdigest()
        logger.info("Hash : {}, Password : {} ".format(hash, password))
        if hash==password:
            logger.info("Machine valid")
            return True
        logger.info("Machine Invalid")
        return False
