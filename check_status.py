import os
import re
import subprocess
from urllib.request import urlopen
import json
import requests

# To be modified variables
VERSION = 'v1.0.0'
ALLOWED_COMMITTERS = {'PhilippeGeek', 'Crocmagnon'}

# Referring server
SERVER = 'http://192.168.1.27:8000'
UPDATE_URL = SERVER + '/update'

# GitHub API settings
API_URL = 'https://api.github.com'
REPO_URL = API_URL + '/repos/bdeinsalyon/dashboard_client'
LATEST_RELEASE = '/releases/latest'
COMMIT_PATH = '/commits'
TAG_PATH = '/git/refs/tags/'
HEADERS = {'Accept': 'application/vnd.github.cryptographer-preview+json'}


def update():
    r = requests.get(API_URL + '/rate_limit')

    if False:
        # Get latest commit and check if OK
        r = requests.get(REPO_URL + COMMIT_PATH, headers=HEADERS)
        commit = r.json()[0]
        verified = commit.get('commit').get('verification').get('verified')
        author = commit.get('author').get('login')
        sha = commit.get('sha')

        download_needed = verified and author in ALLOWED_COMMITTERS
    else:
        download_needed = True

    if False and download_needed:
        r = requests.get(REPO_URL + COMMIT_PATH + '/' + sha, headers=HEADERS)
        files = r.json().get('files')
        for f in files:
            if f.get('filename') == sys.argv[0]:
                url = f.get('raw_url')

    url = 'https://github.com/BdEINSALyon/dashboard_client/raw/2abb28c6095ad79d5f992617078fc2adece91e63/check_status.py'
    print(download_needed)
    print(url)

    r = requests.get(url)

    with open('updated.py', 'w') as f:
        print(r.text, file=f)

def main():
    update()
    status = {}
    try:
        ret = get_ret_str('schtasks /query /tn "Shutdown"')
    except subprocess.CalledProcessError:
        status['shutdown'] = False
    else:
        status['shutdown'] = 'sactiv' not in ret

    # status['apps'] = {}
    # apps = get_ret_str('wmic product get /format:csv')
    # status['apps']['office'] = 'office' in apps
    # status['apps']['photoshop'] = 'photoshop' in apps
    # status['apps']['indesign'] = 'indesign' in apps
    # status['apps']['premiere'] = 'premiere' in apps
    # status['apps']['illustrator'] = 'illustrator' in apps

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

    print(status)
    # urlopen(UPDATE_URL, data=json.dumps(status).encode())


def get_ret(cmd, *args, **kwargs):
    return subprocess.check_output(cmd, *args, **kwargs)


def get_ret_str(cmd, *args, **kwargs):
    return str(get_ret(cmd, *args, **kwargs)).lower()


def get_ret_decode(cmd, *args, **kwargs):
    return get_ret(cmd, *args, **kwargs).decode().lower()


if __name__ == '__main__':
    main()
