import requests

API_URL = 'https://api.github.com'
REPO_URL = API_URL + '/repos/bdeinsalyon/dashboard_client'
LATEST_RELEASE = '/releases/latest'
COMMIT_PATH = '/commits/'
TAG_PATH = '/git/refs/tags/'
HEADERS = {'Accept': 'application/vnd.github.cryptographer-preview+json'}
ALLOWED_COMMITTERS = {'PhilippeGeek', 'Crocmagnon'}

def update():
    r = requests.get(API_URL + '/rate_limit')
    print(r.json())
    # Get latest release from GitHub repo
    r = requests.get(REPO_URL + LATEST_RELEASE, headers=HEADERS)
    tag = r.json().get('tag_name')
    print(tag)

    if tag is None:
        return

    # Get commit SHA for latest release
    r = requests.get(REPO_URL + TAG_PATH + tag, headers=HEADERS)
    sha = r.json().get('object').get('sha')
    print(sha)

    # Get commit and check if OK
    r = requests.get(REPO_URL + COMMIT_PATH + sha, headers=HEADERS)
    commit = r.json()
    verified = commit.get('commit').get('verification').get('verified')
    if verified:
        print('VERIFIED')
    else:
        print('NOT OK')

    author = commit.get('author').get('login')

    if author in ALLOWED_COMMITTERS:
        print('AUTHOR OK')
    else:
        print('AUTHOR NOT OK')

if __name__ == '__main__':
    update()
