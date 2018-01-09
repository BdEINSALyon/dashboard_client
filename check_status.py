# coding: utf-8
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import pprint

import pickle

import requests

# To be modified variables
UPDATE = True
VERSION = 'v1.0.0'
ALLOWED_COMMITTERS = {'philippegeek@gmail.com', 'gabriel@augendre.info'}

# Referring server
SERVER = 'https://status.bde-insa-lyon.fr'
UPDATE_URL = SERVER + '/update'
GRAPH_URL = SERVER + '/graphql'

# GitHub API settings
API_URL = 'https://git.bde-insa-lyon.fr/api/v4'
REPO_URL = API_URL + '/projects/BdEINSALyon%2Fstatus%2Fdashboard_client'
COMMIT_PATH = '/repository/commits'

WEB_COMMIT_URL = 'https://git.bde-insa-lyon.fr/BdEINSALyon/dashboard_client/commit/{}'

SCRIPT_NAME = os.path.basename(__file__)
UPDATE_FILE = 'updated.py'

NAME = ''

DATETIME_LOCATION = 'timestamp.txt'


def main():
    status = {
        'os': {}
    }

    if UPDATE:
        update(status)

    check_name(status)  # Needs to be first as other rely on it.
    check_category(status, 'App')
    check_category(status, 'Task')
    check_category(status, 'Registry')
    check_printer(status)
    check_os_version(status)
    check_ram_usage(status)
    check_disk_usage(status)
    check_sessions(status)
    check_description(status)
    check_windows_activation(status)
    check_network(status)
    check_temp_profiles(status)
    check_install_date(status)
    check_office_activation(status)  # Needs to be after check of apps.

    # pprint.pprint(status)
    headers = None
    token = os.getenv('DASHBOARD_TOKEN')
    if token:
        headers = {
            'Authorization': 'token {}'.format(token)
        }
    requests.post(UPDATE_URL, data=json.dumps(status).encode(), headers=headers)


def update(status):
    # Reduce update frequency
    data = {'last_run': None, 'version': None}
    if os.path.isfile(DATETIME_LOCATION):
        with open(DATETIME_LOCATION, 'rb') as f:
            data = pickle.load(f)
            status['version'] = data['version']

    if data['last_run'] is not None and data['last_run'] + datetime.timedelta(minutes=50) > datetime.datetime.now():
        return

    # Get latest commit and check if OK
    r = requests.get(REPO_URL + COMMIT_PATH)
    json = r.json()
    if 'message' in json:
        print(json)
        return
    commit = json[0]
    verified = True
    author = commit.get('author_email')
    sha = commit.get('id')

    data['last_run'] = datetime.datetime.now()
    data['version'] = {'sha': sha, 'url': WEB_COMMIT_URL.format(sha)}
    status['version'] = data['version']
    with open(DATETIME_LOCATION, 'wb') as f:
        pickle.dump(data, f)

    download_needed = verified and author in ALLOWED_COMMITTERS

    if not download_needed:
        return

    r = requests.get(REPO_URL + COMMIT_PATH + '/' + sha + '/diff')
    files = r.json()
    url = None
    for f in files:
        if f.get('new_path') == SCRIPT_NAME:
            url = 'https://git.bde-insa-lyon.fr/BdEINSALyon/status/dashboard_client/raw/' + sha + '/' + SCRIPT_NAME

    if url is None:
        return

    r = requests.get(url)

    # If we don't get a successful request, don't update with the returned content.
    if r.status_code not in [200, 301, 302]:
        return

    if r.text.startswith('<html><body><h1>503'):
        return

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


def check_category(status, category):
    fetched_checks = fetch_verifs(category)
    checks = []

    for check in fetched_checks['data']['allVerifs']['edges']:
        check = check['node']

        mandatory = check['mandatory']
        if check['exceptionRules'] and len(check['exceptionRules']['edges']) > 0:
            for exception in check['exceptionRules']['edges']:
                exception = exception['node']['value']
                if exception in NAME:
                    mandatory = not mandatory
                    break

        checks.append({
            'tag': check['tag'],
            'display_name': check['displayName'],
            'mandatory': mandatory,
            'icon': check['icon'],
            'icon_type': check['iconType'],
            'verifs': [el['node']['value'] for el in check['verifValues']['edges']]
        })

    if category == 'App':
        status_tag = 'apps'
    elif category == 'Task':
        status_tag = 'tasks'
    elif category == 'Registry':
        status_tag = 'registry'
    else:
        status_tag = 'none'

    status[status_tag] = {}

    # Check apps
    for check in checks:
        installed = False
        for verif in check['verifs']:
            installed = installed or is_installed(verif, category)

        if category == 'App':
            verif = {
                'type': 'path',
                'paths': check['verifs']
            }
        elif category == 'Task':
            verif = {
                'type': 'task',
                'task_names': check['verifs']
            }
        elif category == 'Registry':
            verif = {
                'type': 'registry',
                'keys': check['verifs']
            }
        else:
            verif = None

        status[status_tag][check['tag']] = {
            'name': check['display_name'],
            'mandatory': check['mandatory'],
            'icon': check['icon'],
            'icon_type': check['icon_type'],
            'installed': installed,
            'verification': verif
        }


def fetch_verifs(category):
    default_query = """
    {
        allVerifs(type_Name:"%s") {
            edges {
                node {
                    displayName
                    tag
                    icon
                    iconType
                    mandatory
                    verifValues { edges { node { value } } }
                    exceptionRules { edges { node { value } } }
                }
            }
        }
    }"""

    category_query = default_query % category

    r = requests.get(GRAPH_URL + '?query=' + category_query)
    return r.json()


def check_printer(status):
    printers = get_ret_str('CScript C:/Windows/System32/Printing_Admin_Scripts/fr-FR/prnmngr.vbs -l')
    status['imprimante_ma'] = 'imprimante ma' in printers or 'imprimante accueil' in printers


def check_os_version(status):
    version = sys.getwindowsversion()
    status['os']['version'] = {
        'major': version.major,
        'minor': version.minor,
        'build': version.build,
        'service_pack': version.service_pack
    }


def check_ram_usage(status):
    status['os']['ram'] = {}
    res = get_ret_str('powershell -command "Get-wmiobject -query \\"Select Capacity from CIM_PhysicalMemory\\"')
    total_ram = 0
    for line in res.split('\n'):
        if 'capacity' in line:
            total_ram += int(re.search('\d+', line).group(0))
    status['os']['ram']['total'] = int(total_ram / 1024)

    available_ram = get_ret_str('wmic OS get FreePhysicalMemory')
    available_ram = re.search('\d+', available_ram).group(0)
    status['os']['ram']['available'] = int(available_ram)


def check_disk_usage(status):
    """
    Retrieve the
    :param status:
    :return:
    """
    status['os']['disk'] = {}
    disk_space = get_ret_str('fsutil volume diskfree c:')
    sizes = [int(s) for s in disk_space.split() if s.isdigit()]
    status['os']['disk']['total'] = sizes[1]
    status['os']['disk']['available'] = sizes[2]


def check_sessions(status):
    """
    Get the locked sessions
    """

    args = ['C:\\Windows\\sysnative\\query.exe', 'user']

    # For some reason, subprocess.check_output doesn't work with query.exe
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    output, err = process.communicate()

    # Parse the output : for each line except the first, if "Déco" appears, get the username.
    sessions = output.decode('cp850').split('\r\n')
    usernames = [line[1:].split('  ')[0] for line in sessions[1:] if 'Déco' in line]
    status['os']['locked'] = usernames

    # Also check the total number of sessions : no header and line length not null
    status['os']['total_sessions'] = len([session for session in sessions[1:] if len(session) > 0])


def check_name(status):
    """
    Get computer name.
    """
    global NAME
    status['name'] = os.environ.get('COMPUTERNAME')
    NAME = status['name']


def check_description(status):
    """
    Get computer description.
    """
    config = subprocess.check_output("net config server").decode('cp850').split('\r\n')

    comment = ''
    for line in config:
        if 'commentaires' in line.lower():
            # The line will be like "Commentaires du serveur         Description de l'ordinateur".
            # The regex matches the last bits.
            # \S matches any non-whitespace character.
            re_desc = re.compile('^(?:\S+ )+(?: )+(\S+(?: \S+)*)$')
            match = re_desc.search(line)
            if match:
                comment = match.group(1)
            break

    status['description'] = comment


def check_windows_activation(status):
    """
    Check whether Windows is activated.
    """
    status['windows_activation'] = 'avec licence' in get_ret_str(
        'cscript //nologo "%systemroot%\system32\slmgr.vbs" /dli', shell=True)


def check_network(status):
    """
    Get network information : IP address and DHCP activation.
    """
    status['network'] = {}

    name = ""

    for tag in ['', ' 2', ' 3', ' 4']:
        prefix = "Connexion au réseau local"
        if sys.getwindowsversion().major == 10:
            prefix = "Ethernet"

        net_full = get_ret_str('netsh interface ip show config "{0}{1}"'.format(prefix, tag))
        if 'adresse ip' not in net_full:
            continue
        net = net_full.split('\r\n')
        re_ip = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        for info in net:
            if 'dhcp activé' in info:
                status['network']['dhcp'] = 'oui' in info
            elif 'adresse ip' in info:
                match = re_ip.search(info)
                status['network']['ip'] = match.group(1)

        if '134.214' in net_full:
            name = prefix + tag
            break

    macs = get_ret_str('getmac /v /fo csv /nh').replace('"', '').split('\r\n')
    for mac in macs:
        mac = mac.split(',')
        if len(mac) > 2 and name.lower() == mac[0]:
            status['network']['mac'] = mac[2].replace('-', ':')


def check_temp_profiles(status):
    """
    Count the number of temporary profiles opened.
    """
    home_drive = os.environ.get('HOMEDRIVE')
    if home_drive:
        query = 'dir {0}\\users'.format(home_drive)
    else:
        user_home = os.environ.get('USERPROFILE')
        username = os.environ.get('USERNAME')
        query = 'dir ' + re.sub(username + '$', '', user_home)

    users = get_ret_str(query, shell=True)
    status['os']['temp_profiles'] = users.count('.insa-lyon')


def check_install_date(status):
    """
    Get the system installation date.
    """
    info = get_ret_str('systeminfo').split('\r\n')
    install = ''

    for line in info:
        if 'installation' in line:
            install = line

    re_date = re.compile(r'(\d{1,2})/(\d{2})/(\d{4}), (\d{1,2}):(\d{1,2}):(\d{1,2})$')
    m = re_date.search(install)

    status['os']['install_date'] = {
        'day': int(m.group(1)),
        'month': int(m.group(2)),
        'year': int(m.group(3)),
        'hour': int(m.group(4)),
        'minute': int(m.group(5)),
        'second': int(m.group(6))
    }


def check_office_activation(status):
    """
    Check if office is activated. Doesn't check if office is not installed.
    """

    if not status.get('apps').get('office').get('installed'):
        status['office_activation'] = None
        return

    try:
        res = get_ret_str('cscript "C:/Program Files (x86)/Microsoft Office/Office16/OSPP.VBS" /dstatus').split('-' * 39)
    except subprocess.CalledProcessError:
        try:
            res = get_ret_str('cscript "C:/Program Files/Microsoft Office/Office16/OSPP.VBS" /dstatus').split('-' * 39)
        except subprocess.CalledProcessError:
            status['office_activation'] = None
            return

    for r in res:
        if 'office16proplus' in r or 'office16o365proplus' in r or 'office16standard' in r:
            status['office_activation'] = '---licensed---' in r
            return


def is_installed(name, category):
    """
    Determines whether an app or a scheduled task is installed.
    """
    if category == 'App':
        return 'ok' in get_ret_str('if exist "{}" echo ok'.format(name), shell=True)

    elif category == 'Task':
        try:
            ret = get_ret_str('schtasks /query /tn "{0}"'.format(name))
        except subprocess.CalledProcessError:
            return False
        else:
            return 'désactivé' not in ret

    elif category == 'Registry':
        name = name.split(' == ')
        key = name[0]
        expected_value = name[1]
        try:
            ret = get_ret_str('reg query {0}'.format(key)).replace('\r\n', '').split(' ')[-1]
        except subprocess.CalledProcessError:
            return False
        else:
            return ret == expected_value


def get_ret(cmd, *args, **kwargs):
    return subprocess.check_output(cmd, *args, **kwargs)


def get_ret_str(cmd, *args, **kwargs):
    return get_ret(cmd, *args, **kwargs).decode('cp850').lower()


if __name__ == '__main__':
    main()
