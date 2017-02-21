import requests
import pprint

SERVER = 'http://localhost:8000'
UPDATE_URL = SERVER + '/update'
GRAPH_URL = SERVER + '/graphql'

default_query = """{ allVerifs(type_Name:"%s") { edges { node { displayName tag mandatory verifValues{ edges { node { value } } } } } }}"""

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

pprint.pprint(apps)
