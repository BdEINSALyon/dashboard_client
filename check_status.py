# coding: utf-8

import os
import sys
import re
import subprocess
from urllib.request import urlopen
import json
import requests
import hashlib
import pprint

# To be modified variables
VERSION = 'v1.0.0'
ALLOWED_COMMITTERS = {'PhilippeGeek', 'Crocmagnon'}

# Referring server
SERVER = 'https://status.bde-insa-lyon.fr'
UPDATE_URL = SERVER + '/update'
GRAPH_URL = SERVER + '/graphql'

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
    default_query = """{ allVerifs(type_Name:"{0}") { edges { node { displayName tag mandatory verifValues{ edges { node { value } } } } } }}"""

    # Fetch tasks
    tasks_query = default_query % ('Task')

    r = requests.get(GRAPH_URL + '?query=' + tasks_query)
    fetched_tasks = r.json()

    tasks = []

    for task in fetched_tasks['data']['allVerifs']['edges']:
        task = task['node']
        tasks.append({
            'tag': task['tag'],
            'display_name': task['displayName'],
            'mandatory': task['mandatory'],
            'names': [el['node']['value'] for el in task['verifValues']['edges']]
        })

    pprint.pprint(tasks)
    # Check tasks
    status['tasks'] = {}
    for task in tasks:
        try:
            ret = get_ret_str('schtasks /query /tn "{0}"'.format(task['name']))
            status['tasks'][task['tag']] = {
                'name': task['display_name'],
                'mandatory': task['mandatory'],
                'verification': {
                    'type': 'task',
                    'task_names': task['names']
                }
            }
        except subprocess.CalledProcessError:
            status['tasks'][task['tag']]['installed'] = False
        else:
            status['tasks'][task['tag']]['installed'] = 'désactivé' not in ret

    # Fetch apps
    apps_query = default_query % ('App')

    r = requests.get(GRAPH_URL + '?query=' + apps_query)
    fetched_apps = r.json()

    apps = []

    for app in fetched_apps['data']['allVerifs']['edges']:
        app = app['node']
        apps.append({
            'tag': app['tag'],
            'display_name': app['displayName'],
            'mandatory': app['mandatory'],
            'paths': [el['node']['value'] for el in app['verifValues']['edges']]
        })

    status['apps'] = {}
    # Check apps
    for app in apps:
        installed = False
        for path in app['paths']:
            installed = installed or is_installed(path)
        status['apps'][app['tag']] = {
            'name': app['display_name'],
            'mandatory': app['mandatory'],
            'installed': installed,
            'verification': {
                'type': 'path',
                'paths': app['paths']
            }
        }

    # MA Printer
    printers = get_ret_str('CScript C:/Windows/System32/Printing_Admin_Scripts/fr-FR/prnmngr.vbs -l')
    status['imprimante_ma'] = 'imprimante ma' in printers or 'imprimante accueil' in printers

    # RAM total and available
    status['os'] = {}
    status['os']['ram'] = {}
    total_ram = get_ret_str('wmic computersystem get TotalPhysicalMemory')
    total_ram = re.search('\d+', total_ram).group(0)
    status['os']['ram']['total'] = int(int(total_ram) / 1024)

    available_ram = get_ret_str('wmic OS get FreePhysicalMemory')
    available_ram = re.search('\d+', available_ram).group(0)
    status['os']['ram']['available'] = int(available_ram)

    # Disk total and available
    status['os']['disk'] = {}
    disk_space = get_ret_str('fsutil volume diskfree c:')
    sizes = [int(s) for s in disk_space.split() if s.isdigit()]
    status['os']['disk']['total'] = sizes[1]
    status['os']['disk']['available'] = sizes[2]

    # Locked sessions
    args = ['C:\\Windows\\sysnative\\query.exe', 'user']
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    output, err = process.communicate()
    usernames = [line[1:].split('  ')[0] for line in output.decode('cp850').split('\n')[1:] if 'Déco' in line]
    status['os']['locked'] = usernames

    # Computer name
    status['name'] = os.environ.get('COMPUTERNAME')

    # Computer description
    config = subprocess.check_output("net config server").decode('cp850').split('  ')
    comment = get_comment(config)

    comment = comment.strip()
    try:
        index = comment.index('\r')
        comment = comment[:index]
    except ValueError:
        comment = ''

    status['description'] = comment

    # Is windows active ?
    status['windows_activation'] = 'avec licence' in get_ret_str('cscript //nologo "%systemroot%\system32\slmgr.vbs" /dli', shell=True)

    print(status)
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
    return 'ok' in get_ret_str('if exist "{}" echo ok'.format(path), shell=True)

def get_ret(cmd, *args, **kwargs):
    return subprocess.check_output(cmd, *args, **kwargs)

def get_ret_str(cmd, *args, **kwargs):
    return get_ret(cmd, *args, **kwargs).decode('cp850').lower()

if __name__ == '__main__':
    main()
