#!/usr/bin/env python
"""
    Linux disk drive information: model, serial, firmare version
"""

import sys, os, fcntl, struct, glob

def list_devices(pattern = 'sd*'):
    return [os.path.basename(d) for d in glob.glob('/sys/block/' + pattern)]

# https://stackoverflow.com/questions/4193514/get-hard-disk-serial-number-using-python-on-linux
def get_identity(dev):

    fields = ()
    try:
        with open('/dev/' + dev, "rb") as fd:

            hd_driveid_format_str = "@ 10H 20s 3H 8s 40s 2B H 2B H 4B 6H 2B I 36H I Q 152H"
            HDIO_GET_IDENTITY = 0x030d
            sizeof_hd_driveid = struct.calcsize(hd_driveid_format_str)
            assert sizeof_hd_driveid == 512

            buf = fcntl.ioctl(fd, HDIO_GET_IDENTITY, " " * sizeof_hd_driveid)
            fields = struct.unpack(hd_driveid_format_str, buf)
            return (dev, fields[15].strip(), fields[10].strip(), fields[14].strip())

    except IOError:
        pass

    return fields

def get_device(hdd_data):
    for i in range(0,len(hdd_data)):
        if hdd_data[i]['device']=="sda":
            return hdd_data[i]['hdd'].decode('utf-8')
            # a = hdd_data[i]['hdd'].decode('utf-8')
            # print("type - ",a)
            # data['Machine_Hdd']=sha_encoding(hdd_data[i]['hdd'].decode('utf-8'))
            break
        else:
            continue

def get_hdd_identity():
    if os.geteuid() >  0:
        print("ERROR: Must be run as root")
        sys.exit(1)

    devices = list_devices()
    if devices:
        fmt = "{0:<6}  {1:<40}  {2:<20}  {3:<8}"
        # print (fmt.format('Device', 'Model', 'Serial', 'Firmware'))
        # print ('-' * 80)
        li_devices = []
        for device in devices:
            identity = get_identity(device)
            if identity:
                data = {}
                # print (identity)
                # print (identity)
                data['device'] = identity[0]
                data['hdd'] = identity[2]
                li_devices.append(data)
                # print(li_devices)
                return get_device(li_devices)
            # print(identity[1])
    else:
        print ("No devices found.")
        return "No devices found."
