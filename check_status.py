import os
import re
import subprocess
from urllib.request import urlopen
import json

SERVER = 'http://192.168.1.27:8000'
UPDATE_URL = SERVER + '/update'


def main():
    status = {}
    try:
        get_ret('schtasks /query /tn "Shutdown"')
    except subprocess.CalledProcessError:
        status['shutdown'] = False
    else:
        status['shutdown'] = True

    status['apps'] = {}
    apps = get_ret_str('wmic product get /format:csv')
    status['apps']['office'] = 'office' in apps
    status['apps']['photoshop'] = 'photoshop' in apps
    status['apps']['indesign'] = 'indesign' in apps
    status['apps']['premiere'] = 'premiere' in apps
    status['apps']['illustrator'] = 'illustrator' in apps

    printers = get_ret_str('CScript C:/Windows/System32/Printing_Admin_Scripts/fr-FR/prnmngr.vbs -l')
    status['imprimante_ma'] = 'imprimante ma' in printers

    status['os'] = {}
    status['os']['ram'] = {}
    total_ram = get_ret_str('wmic computersystem get TotalPhysicalMemory')
    total_ram = re.search('\d+', total_ram).group(0)
    status['os']['ram']['total'] = int(int(total_ram) / 1024)

    available_ram = get_ret_str('wmic OS get FreePhysicalMemory')
    available_ram = re.search('\d+', available_ram).group(0)
    status['os']['ram']['available'] = int(available_ram)

    status['os']['disk'] = {}
    disk_space = get_ret_decode('fsutil volume diskfree c:')
    sizes = [int(s) for s in disk_space.split() if s.isdigit()]
    status['os']['disk']['total'] = sizes[1]
    status['os']['disk']['available'] = sizes[2]

    status['name'] = os.environ.get('COMPUTERNAME')

    urlopen(UPDATE_URL, data=json.dumps(status).encode())


def get_ret(cmd, *args, **kwargs):
    return subprocess.check_output(cmd, *args, **kwargs)


def get_ret_str(cmd, *args, **kwargs):
    return str(get_ret(cmd, *args, **kwargs)).lower()


def get_ret_decode(cmd, *args, **kwargs):
    return get_ret(cmd, *args, **kwargs).decode().lower()


if __name__ == '__main__':
    main()
