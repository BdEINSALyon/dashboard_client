# coding: utf-8

import os
import sys
import re
import subprocess
from urllib.request import urlopen
import json
import requests
import hashlib

# To be modified variables
VERSION = 'v1.0.0'
ALLOWED_COMMITTERS = {'PhilippeGeek', 'Crocmagnon'}

# Referring server
SERVER = 'http://status.bde-insa-lyon.fr'
UPDATE_URL = SERVER + '/update'

# GitHub API settings
API_URL = 'https://api.github.com'
REPO_URL = API_URL + '/repos/bdeinsalyon/dashboard_client'
LATEST_RELEASE = '/releases/latest'
COMMIT_PATH = '/commits'
TAG_PATH = '/git/refs/tags/'
HEADERS = {'Accept': 'application/vnd.github.cryptographer-preview+json'}

SCRIPT_NAME = sys.argv[0]
UPDATE_FILE = 'updated.py'

def update():
    r = requests.get(API_URL + '/rate_limit')

    # Get latest commit and check if OK
    r = requests.get(REPO_URL + COMMIT_PATH, headers=HEADERS)
    commit = r.json()[0]
    verified = commit.get('commit').get('verification').get('verified')
    author = commit.get('author').get('login')
    sha = commit.get('sha')

    download_needed = verified and author in ALLOWED_COMMITTERS

    if not download_needed:
        return

    r = requests.get(REPO_URL + COMMIT_PATH + '/' + sha, headers=HEADERS)
    files = r.json().get('files')
    url = None
    for f in files:
        if f.get('filename') == SCRIPT_NAME:
            url = f.get('raw_url')

    if url is None:
        return

    r = requests.get(url)

    with open(UPDATE_FILE, 'w', encoding='utf-8') as f:
        print(r.text, file=f)

    with open(UPDATE_FILE, 'rb') as f1:
        with open(SCRIPT_NAME, 'rb') as f2:
            h1 = hashlib.sha256(f1.read()).hexdigest()
            h2 = hashlib.sha256(f2.read()).hexdigest()

    restart_needed = h1 != h2
    print('restart_needed', restart_needed)

    if restart_needed:
        # Prepare args for script restart
        args = sys.argv[:]
        args.insert(0, sys.executable)
        if sys.platform == 'win32':
            args = ['"%s"' % arg for arg in args]

        os.remove(SCRIPT_NAME)
        os.rename(UPDATE_FILE, SCRIPT_NAME)
        os.chdir(os.getcwd())
        os.execv(sys.executable, args)

    else:
        os.remove(UPDATE_FILE)


def main():
    update()
    status = {}
    try:
        ret = get_ret_str('schtasks /query /tn "Shutdown"')
    except subprocess.CalledProcessError:
        status['shutdown'] = False
    else:
        status['shutdown'] = 'sactiv' not in ret

    status['apps'] = {}

    office = is_installed('C:\Program Files (x86)\Microsoft Office\Office16\WINWORD.EXE') or is_installed('C:\Program Files\Microsoft Office\Office16\WINWORD.EXE')
    status['apps']['office'] = {
        'installed': office,
        'name': 'Microsoft Office',
        'mandatory': True
    }

    vlc = is_installed('c:\Program Files\VideoLAN')
    status['apps']['vlc'] = {
        'installed': vlc,
        'name': 'VLC',
        'mandatory': False
    }

    photoshop = is_installed('c:\Program Files\Adobe\Adobe Photoshop CC 2017')
    status['apps']['photoshop'] = {
        'installed': photoshop,
        'name': 'Adobe Photoshop',
        'mandatory': False
    }
    indesign = is_installed('c:\Program Files\Adobe\Adobe InDesign CC 2017')
    status['apps']['indesign'] = {
        'installed': indesign,
        'name': 'Adobe InDesign',
        'mandatory': False
    }
    premiere = is_installed('c:\Program Files\Adobe\Adobe Premiere Pro CC 2017')
    status['apps']['premiere'] = {
        'installed': premiere,
        'name': 'Adobe Premiere',
        'mandatory': False
    }
    illustrator = is_installed('c:\Program Files\Adobe\Adobe Illustrator CC 2017')
    status['apps']['illustrator'] = {
        'installed': illustrator,
        'name': 'Adobe Illustrator',
        'mandatory': False
    }

    videoproj = is_installed('c:\Program Files (x86)\EPSON Projector')
    status['apps']['videoproj'] = {
        'installed': videoproj,
        'name': 'Vidéoprojecteur Salle IF',
        'mandatory': False
    }

    antivirus = is_installed('C:\Program Files (x86)\Sophos\Sophos Anti-Virus')
    status['apps']['antivirus'] = {
        'installed': antivirus,
        'name': 'Sophos Antivirus',
        'mandatory': True
    }

    printers = get_ret_str('CScript C:/Windows/System32/Printing_Admin_Scripts/fr-FR/prnmngr.vbs -l')
    status['imprimante_ma'] = 'imprimante ma' in printers or 'imprimante accueil' in printers

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

    config = subprocess.check_output("net config server").decode('raw_unicode_escape').split('  ')
    comment = get_comment(config)

    comment = comment.strip()
    try:
        index = comment.index('\r')
        comment = comment[:index]
    except ValueError:
        comment = ''

    status['description'] = comment

    # print(status)
    urlopen(UPDATE_URL, data=json.dumps(status).encode())


def get_comment(s):
    met_name = False
    for i, val in enumerate(s):
        val = val.strip()
        if len(val) > 0 and i > 1:
            if not met_name:
                met_name = True
            else:
                return val

def is_installed(path):
    return 'ok' in get_ret_decode('if exist "{}" echo ok'.format(path), shell=True)

def get_ret(cmd, *args, **kwargs):
    return subprocess.check_output(cmd, *args, **kwargs)


def get_ret_str(cmd, *args, **kwargs):
    return get_ret(cmd, *args, **kwargs).decode('raw_unicode_escape').lower()


def get_ret_decode(cmd, *args, **kwargs):
    return get_ret(cmd, *args, **kwargs).decode().lower()


if __name__ == '__main__':
    main()
